// exp2_mask_range empirically tests whether CF labeling with OPTIMIZED mask sizes
// (matched to the actual message range) can achieve correctness at tighter parameters
// than the current implementation and potentially outperform std.
//
// The current implementation uses masks in [0, √t ≈ 8184], but the benchmark values
// are in [1, 1000]. When mask_i > value_i, a_i = (value_i - mask_i + t) mod t ≈ t-1,
// causing large noise amplification (||a||_∞ ≈ t ≈ 67M) in the scalar multiplications
// a1×β2 and a2×β1 inside Mult.
//
// This experiment implements CF labeling with a CONTROLLABLE mask size and tests:
//   1. Current impl (mask ∈ [0, √t]): does a_i wrap to ≈ t-1?
//   2. Optimized impl (mask ∈ [0, value_max/2]): a_i stays small; noise ≈ 1.5×value_max×B_fresh
//
// Both correctness (5 reps) and the observed noise level are measured.
// This DOES NOT modify the main labeling code — it uses Lattigo directly.
//
// Run: go run ./experiments/exp2_mask_range/
package main

import (
	"fmt"
	"log"
	"math"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	nReps            = 5
	valueMax         = uint64(1000) // same as harness.GenerateDataset range
)

type maskMode struct {
	name    string
	maskBound uint64 // masks drawn uniformly from [0, maskBound)
}

type profile struct {
	name string
	logQ []int
	logP []int
}

var profiles = []profile{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
	{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
	{"min", []int{35, 35}, []int{35, 35}},
}

// encryptCF encrypts value using a mask drawn from [0, maskBound).
// Returns (a, β) where a = (value - mask) mod t and β = Enc(mask).
func encryptCF(params bgv.Parameters, pk *rlwe.PublicKey, value, maskBound uint64) ([]uint64, *rlwe.Ciphertext, error) {
	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, nil, err
	}
	slots := params.MaxSlots()
	t := params.PlaintextModulus()
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)

	masks := make([]uint64, slots)
	aVec := make([]uint64, slots)

	// Ensure maskBound is valid (must be a power of 2 for RandUniform).
	// Use nearest power of 2 ceiling.
	boundBits := bits.Len64(maskBound)
	if maskBound == 0 {
		boundBits = 1
	}
	roundedBound := uint64(1) << boundBits

	for i := range slots {
		// Use valueMax as the message for all slots (uniform test value).
		msg := uint64(i%int(valueMax) + 1)
		mask := ring.RandUniform(prng, maskBound, roundedBound-1) % maskBound
		masks[i] = mask
		aVec[i] = (msg - mask + t) % t
	}

	ptxt := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(masks, ptxt); err != nil {
		return nil, nil, fmt.Errorf("encode masks: %w", err)
	}
	ct, err := encryptor.EncryptNew(ptxt)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}
	return aVec, ct, nil
}

// multCF computes the CF multiplication of two labeled ciphertexts.
// Returns (a_out, β_out) where:
//
//	a_out = (a1*a2 - r) mod t
//	β_out = MulRelin(β1, β2) + a1×β2 + a2×β1 + Enc(r)
func multCF(params bgv.Parameters, pk *rlwe.PublicKey, evk *rlwe.MemEvaluationKeySet,
	a1 []uint64, beta1 *rlwe.Ciphertext,
	a2 []uint64, beta2 *rlwe.Ciphertext,
	betaLevel int,
) ([]uint64, *rlwe.Ciphertext, error) {
	t := params.PlaintextModulus()
	slots := params.MaxSlots()
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	eval := bgv.NewEvaluator(params, evk)

	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, nil, err
	}

	r := make([]uint64, slots)
	aOut := make([]uint64, slots)
	for i := range slots {
		ri := ring.RandUniform(prng, 1000, 1023) % 1000
		r[i] = ri
		aOut[i] = (a1[i]*a2[i] - ri + t) % t
	}

	betaOut := rlwe.NewCiphertext(params, params.MaxLevel(), betaLevel)

	// MulRelin(β1, β2).
	if err := eval.MulRelin(beta1, beta2, betaOut); err != nil {
		return nil, nil, fmt.Errorf("MulRelin: %w", err)
	}

	// a1 × β2.
	tmp := rlwe.NewCiphertext(params, params.MaxLevel(), betaLevel)
	if err := eval.Mul(beta2, a1, tmp); err != nil {
		return nil, nil, fmt.Errorf("Mul a1×β2: %w", err)
	}
	if err := eval.Add(betaOut, tmp, betaOut); err != nil {
		return nil, nil, fmt.Errorf("Add a1β2: %w", err)
	}

	// a2 × β1.
	if err := eval.Mul(beta1, a2, tmp); err != nil {
		return nil, nil, fmt.Errorf("Mul a2×β1: %w", err)
	}
	if err := eval.Add(betaOut, tmp, betaOut); err != nil {
		return nil, nil, fmt.Errorf("Add a2β1: %w", err)
	}

	// Enc(r).
	ptxtR := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(r, ptxtR); err != nil {
		return nil, nil, fmt.Errorf("encode r: %w", err)
	}
	ctR, err := encryptor.EncryptNew(ptxtR)
	if err != nil {
		return nil, nil, fmt.Errorf("Enc(r): %w", err)
	}
	if err := eval.Add(betaOut, ctR, betaOut); err != nil {
		return nil, nil, fmt.Errorf("Add Enc(r): %w", err)
	}

	return aOut, betaOut, nil
}

// decryptCF decrypts a labeled ciphertext (a, β) using the secret key.
func decryptCF(params bgv.Parameters, sk *rlwe.SecretKey, a []uint64, beta *rlwe.Ciphertext) ([]uint64, error) {
	t := params.PlaintextModulus()
	encoder := bgv.NewEncoder(params)
	dec := rlwe.NewDecryptor(params, sk)

	b := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(dec.DecryptNew(beta), b); err != nil {
		return nil, err
	}

	result := make([]uint64, params.MaxSlots())
	for i := range result {
		result[i] = (a[i] + b[i] + t) % t
	}
	return result, nil
}

func main() {
	fmt.Println("=== Exp-2: Mask Range Impact on CF Labeling Correctness ===")
	fmt.Printf("Message range: [1, %d]  (benchmark harness values)\n", valueMax)
	fmt.Printf("√t = %d  (current implementation mask range)\n\n", uint64(math.Sqrt(float64(plaintextModulus))))

	sqrtT := uint64(math.Sqrt(float64(plaintextModulus)))
	maskModes := []maskMode{
		{"current (mask=[0,√t])", sqrtT},
		{"optimized (mask=[0,500])", 500},
		{"minimal (mask=[0,10])", 10},
	}

	for _, prof := range profiles {
		bgvParams, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             logN,
			LogQ:             prof.logQ,
			LogP:             prof.logP,
			PlaintextModulus: plaintextModulus,
		})
		if err != nil {
			log.Printf("skip profile %s: %v", prof.name, err)
			continue
		}

		fmt.Printf("═══ Profile: %s (MaxLevel=%d) ═══\n", prof.name, bgvParams.MaxLevel())

		kgen := rlwe.NewKeyGenerator(bgvParams)
		sk, pk := kgen.GenKeyPairNew()
		rlk := kgen.GenRelinearizationKeyNew(sk)
		evk := rlwe.NewMemEvaluationKeySet(rlk)

		for _, mm := range maskModes {
			correctCount := 0
			maxAObserved := uint64(0)
			t := bgvParams.PlaintextModulus()

			for rep := 0; rep < nReps; rep++ {
				// Encrypt two vectors.
				a1, beta1, err := encryptCF(bgvParams, pk, 1, mm.maskBound)
				if err != nil {
					log.Printf("encryptCF: %v", err)
					continue
				}
				a2, beta2, err := encryptCF(bgvParams, pk, 1, mm.maskBound)
				if err != nil {
					log.Printf("encryptCF: %v", err)
					continue
				}

				// Track max |a| to verify the noise amplification.
				for _, ai := range a1 {
					// Centered representation: map [t/2, t) → negative side.
					centered := ai
					if ai > t/2 {
						centered = t - ai
					}
					if centered > maxAObserved {
						maxAObserved = centered
					}
				}

				// Multiply.
				aOut, betaOut, err := multCF(bgvParams, pk, evk, a1, beta1, a2, beta2, 1)
				if err != nil {
					log.Printf("multCF: %v", err)
					continue
				}

				// Decrypt.
				result, err := decryptCF(bgvParams, sk, aOut, betaOut)
				if err != nil {
					log.Printf("decryptCF: %v", err)
					continue
				}

				// Verify: expected product = (i%1000+1) * (i%1000+1) = (i%1000+1)^2.
				correct := true
				for i := 0; i < min(10, bgvParams.MaxSlots()); i++ {
					expected := uint64((i%int(valueMax)+1)) * uint64((i%int(valueMax)+1)) % t
					if result[i] != expected {
						correct = false
						break
					}
				}
				if correct {
					correctCount++
				}
			}

			fmt.Printf("  %-32s mask_bound=%-6d  max_|a|=%-8d  correct=%d/%d\n",
				mm.name, mm.maskBound, maxAObserved, correctCount, nReps)
		}

		// Std HMul (for comparison).
		correctStd := 0
		for rep := 0; rep < nReps; rep++ {
			encoder := bgv.NewEncoder(bgvParams)
			encryptor := rlwe.NewEncryptor(bgvParams, pk)
			eval := bgv.NewEvaluator(bgvParams, evk)
			dec := rlwe.NewDecryptor(bgvParams, sk)
			t := bgvParams.PlaintextModulus()

			msg := make([]uint64, bgvParams.MaxSlots())
			for i := range msg {
				msg[i] = uint64(i%int(valueMax) + 1)
			}
			ptxt := bgv.NewPlaintext(bgvParams, bgvParams.MaxLevel())
			if err := encoder.Encode(msg, ptxt); err != nil {
				continue
			}
			ct, err := encryptor.EncryptNew(ptxt)
			if err != nil {
				continue
			}
			ctSq, err := eval.MulRelinNew(ct, ct)
			if err != nil {
				continue
			}
			result := make([]uint64, bgvParams.MaxSlots())
			if err := encoder.Decode(dec.DecryptNew(ctSq), result); err != nil {
				continue
			}
			correct := true
			for i := 0; i < 10; i++ {
				expected := msg[i] * msg[i] % t
				if result[i] != expected {
					correct = false
					break
				}
			}
			if correct {
				correctStd++
			}
		}
		fmt.Printf("  %-32s              (no mask)           correct=%d/%d\n",
			"std HMul+Relin", correctStd, nReps)
		fmt.Println()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
