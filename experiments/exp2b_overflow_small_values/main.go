// exp2b_overflow_small_values tests the CF overflow path (UC4) with very small
// message values to verify whether the theoretical noise crossover holds empirically.
//
// The key theoretical finding from exp3 is:
//
//	CF overflow noise < std HMul noise  when  ||a||_∞ < B_fresh / 2 ≈ 205
//
// This means: for messages bounded by ~200, CF overflow SHOULD be less noisy than
// std HMul, potentially allowing CF to use tighter parameters.
//
// BUT: the current mask implementation uses [0, √t ≈ 8119], causing a_i = (v-b) mod t
// to wrap around to ≈ t-1 even for tiny v. This experiment tests both:
//   1. Current masks (wrap-around)
//   2. Optimized masks (matched to value range, no wrap-around)
//
// This is a standalone experiment using Lattigo directly (no labeling package modifications).
// Note: the overflow path avoids MulRelin entirely — only scalar-CT multiplications and
// Enc(a1*a2) for α.
//
// Run: go run ./experiments/exp2b_overflow_small_values/
package main

import (
	"fmt"
	"log"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	nReps            = 3
)

type testConfig struct {
	valueMax  uint64 // messages in [1, valueMax]
	maskBound uint64 // masks in [0, maskBound)
	desc      string
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

// encryptValue encrypts a single scalar message (broadcast to all slots) as a
// labeled ciphertext (a, β) where β = Enc(b) and a = (v - b) mod t.
func encryptValue(params bgv.Parameters, pk *rlwe.PublicKey, value, maskBound uint64) ([]uint64, *rlwe.Ciphertext, uint64) {
	prng, _ := sampling.NewPRNG()
	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	sqrtBound := uint64(1) << uint(math.Ceil(math.Log2(float64(maskBound)+1)))

	a := make([]uint64, slots)
	b := make([]uint64, slots)
	for i := range slots {
		mask := ring.RandUniform(prng, maskBound+1, sqrtBound-1) % (maskBound + 1)
		b[i] = mask
		a[i] = (value - mask + t) % t
	}

	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)

	ptxt := bgv.NewPlaintext(params, params.MaxLevel())
	_ = encoder.Encode(b, ptxt)
	beta, _ := encryptor.EncryptNew(ptxt)

	// Check centered norm of a.
	maxCentered := uint64(0)
	for _, ai := range a {
		centered := ai
		if ai > t/2 {
			centered = t - ai
		}
		if centered > maxCentered {
			maxCentered = centered
		}
	}

	return a, beta, maxCentered
}

// multOverflowDirect computes CF overflow multiplication (no relin) for a self-product.
// α = Enc(a*a) + 2*(a × β)  (no β×β, no MulRelin)
// Returns (α, max_|a|_centered).
func multOverflowDirect(params bgv.Parameters, pk *rlwe.PublicKey, a []uint64, beta *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	eval := bgv.NewEvaluator(params, nil)
	t := params.PlaintextModulus()

	// Enc(a*a).
	a2 := make([]uint64, len(a))
	for i, ai := range a {
		a2[i] = (ai * ai) % t
	}
	ptxtA2 := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(a2, ptxtA2); err != nil {
		return nil, err
	}
	alpha, err := encryptor.EncryptNew(ptxtA2)
	if err != nil {
		return nil, err
	}

	// 2 × (a × β): add a×β twice.
	for i := 0; i < 2; i++ {
		tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := eval.Mul(beta, a, tmp); err != nil {
			return nil, fmt.Errorf("Mul a×β: %w", err)
		}
		if err := eval.Add(alpha, tmp, alpha); err != nil {
			return nil, fmt.Errorf("Add α += a×β: %w", err)
		}
	}

	return alpha, nil
}

// multHMulRelin computes standard HMul + Relin of β × β (degree-2 → degree-1).
func multHMulRelin(params bgv.Parameters, evk *rlwe.MemEvaluationKeySet, beta *rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	eval := bgv.NewEvaluator(params, evk)
	return eval.MulRelinNew(beta, beta)
}

// decryptAndCheck decrypts α and checks if result slot 0 ≈ expected (in Z_t).
func decryptAndCheck(params bgv.Parameters, sk *rlwe.SecretKey, ct *rlwe.Ciphertext, expected uint64) bool {
	dec := rlwe.NewDecryptor(params, sk)
	encoder := bgv.NewEncoder(params)
	result := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(dec.DecryptNew(ct), result); err != nil {
		return false
	}
	return result[0] == expected
}

func main() {
	fmt.Println("=== Exp-2b: CF Overflow vs Std HMul for Small Message Values ===")
	fmt.Printf("Theoretical crossover: CF overflow < std HMul noise when ||a||_∞ < B_fresh/2 ≈ 205\n")
	fmt.Printf("(assuming NTT-domain noise amplification: noise_cf = ||a||_NTT × B_fresh vs noise_std = B_fresh²)\n\n")

	sqrtT := uint64(math.Sqrt(float64(plaintextModulus)))
	configs := []testConfig{
		{valueMax: 1000, maskBound: sqrtT, desc: "values[1,1000] mask=[0,√t] (wraps 88%)"},
		{valueMax: 1000, maskBound: 500, desc: "values[1,1000] mask=[0,500] (wraps 50%)"},
		{valueMax: 100, maskBound: 50, desc: "values[1,100]  mask=[0,50]  (wraps 50%)"},
		{valueMax: 10, maskBound: 5, desc: "values[1,10]   mask=[0,5]   (no wrap)"},
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

		t := bgvParams.PlaintextModulus()

		for _, cfg := range configs {
			correctOverflow := 0
			correctStd := 0
			maxAObserved := uint64(0)

			for rep := 0; rep < nReps; rep++ {
				value := cfg.valueMax/2 + 1 // mid-range value
				expected := (value * value) % t

				// CF Overflow path: labeled encrypt → multOverflowDirect → decrypt.
				a, beta, maxA := encryptValue(bgvParams, pk, value, cfg.maskBound)
				if maxA > maxAObserved {
					maxAObserved = maxA
				}

				alpha, err := multOverflowDirect(bgvParams, pk, a, beta)
				if err != nil {
					continue
				}
				// result = Dec(α) + Dec(β)²: Dec(α)=a²+2ab, Dec(β)=b → (a+b)²=m².
				dec := rlwe.NewDecryptor(bgvParams, sk)
				encoder := bgv.NewEncoder(bgvParams)

				alphaResult := make([]uint64, bgvParams.MaxSlots())
				if err := encoder.Decode(dec.DecryptNew(alpha), alphaResult); err != nil {
					continue
				}
				betaResult := make([]uint64, bgvParams.MaxSlots())
				if err := encoder.Decode(dec.DecryptNew(beta), betaResult); err != nil {
					continue
				}
				actual := (alphaResult[0] + (betaResult[0]*betaResult[0])%t + t) % t
				if actual == expected {
					correctOverflow++
				}

				// Std HMul path: directly encrypt value (not mask), MulRelin, decrypt.
				// This is the fair comparison: std computes value² without labeled structure.
				encryptor := rlwe.NewEncryptor(bgvParams, pk)
				vals := make([]uint64, bgvParams.MaxSlots())
				for i := range vals {
					vals[i] = value
				}
				ptxtV := bgv.NewPlaintext(bgvParams, bgvParams.MaxLevel())
				if err := encoder.Encode(vals, ptxtV); err != nil {
					continue
				}
				ctValue, err := encryptor.EncryptNew(ptxtV)
				if err != nil {
					continue
				}
				ctSq, err := multHMulRelin(bgvParams, evk, ctValue)
				if err != nil {
					continue
				}
				if decryptAndCheck(bgvParams, sk, ctSq, expected) {
					correctStd++
				}
			}

			fmt.Printf("  [%-48s] max_|a|=%-6d  CF_overflow=%d/%d  std_HMul=%d/%d\n",
				cfg.desc, maxAObserved, correctOverflow, nReps, correctStd, nReps)
		}
		fmt.Println()
	}

	fmt.Println("--- Noise analysis summary ---")
	bFresh := 3.2 * math.Sqrt(float64(1<<logN))
	fmt.Printf("B_fresh = σ × √N = %.0f\n", bFresh)
	fmt.Printf("Std HMul noise (NTT domain): B_fresh² = %.0f ≈ 2^%.1f\n", bFresh*bFresh, math.Log2(bFresh*bFresh))
	for _, cfg := range configs {
		aMax := cfg.maskBound + cfg.valueMax // worst-case centered norm
		overflowNoise := float64(aMax) * bFresh // ||a||_NTT × B_fresh (rough bound)
		label := "more noisy than std"
		if overflowNoise < bFresh*bFresh {
			label = "LESS noisy than std"
		}
		fmt.Printf("  CF overflow [%s]: ||a||≈%d, noise=%.0f ≈ 2^%.1f  [%s]\n",
			cfg.desc, aMax, overflowNoise, math.Log2(overflowNoise), label)
	}
}
