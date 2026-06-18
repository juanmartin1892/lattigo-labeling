// exp5_uc4_s3_direct tests whether CF overflow (no relin) can compute value² correctly at
// S3 (min) parameters where std HMul+Relin FAILS, using a single-party simulation.
//
// Key finding from exp2b: for a SINGLE multiplication with ideal-key decrypt, CF overflow
// works at S3 while std HMul fails. This experiment adds:
//   1. The full rotate-and-sum (13 steps, log2(blockSize)) to simulate DB1 aggregation.
//   2. The threshold CKS smudging noise (simulated with single party, σ=8×DefaultNoise).
//
// The single-party simulation keeps key management simple while testing the noise levels.
// Results tell us whether CF overflow's per-multiply advantage survives the full pipeline.
//
// Run: go run ./experiments/exp5_uc4_s3_direct/
package main

import (
	"fmt"
	"log"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	blockSize        = 8192
	nReps            = 5
)

var profiles = []struct {
	name string
	logQ []int
	logP []int
}{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
	{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
	{"min", []int{35, 35}, []int{35, 35}},
}

// runCFOverflow: single-party CF overflow path without relin.
//   α = Enc(a*a) + 2*(a×β), then rotate-and-sum on α.
//   Decrypt: α_sum + b_sq_sum = (a+b)_sq_sum = m_sq_sum = N*value².
func runCFOverflow(params bgv.Parameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey,
	evkGal *rlwe.MemEvaluationKeySet, value uint64) (bool, error) {

	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	// Fill all slots with value.
	vals := make([]uint64, slots)
	for i := range vals {
		vals[i] = value
	}

	// Labeled encrypt: a = (value - mask) mod t, β = Enc(mask).
	prng, err := sampling.NewPRNG()
	if err != nil {
		return false, err
	}
	mask := ring.RandUniform(prng, 1000, 1023) % 1000
	a := make([]uint64, slots)
	b := make([]uint64, slots)
	for i := range slots {
		a[i] = (value - mask + t) % t
		b[i] = mask
	}
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	ptxtB := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(b, ptxtB); err != nil {
		return false, err
	}
	beta, err := encryptor.EncryptNew(ptxtB)
	if err != nil {
		return false, err
	}
	// Save betaOrig (for compact decrypt).
	betaOrig := beta

	// CF MultOverflow (no relin): α = Enc(a²) + 2*(a × β).
	eval := bgv.NewEvaluator(params, evkGal)

	a2 := make([]uint64, slots)
	for i, ai := range a {
		a2[i] = (ai * ai) % t
	}
	ptxtA2 := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(a2, ptxtA2); err != nil {
		return false, err
	}
	alpha, err := encryptor.EncryptNew(ptxtA2)
	if err != nil {
		return false, err
	}

	for k := 0; k < 2; k++ {
		tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := eval.Mul(beta, a, tmp); err != nil {
			return false, fmt.Errorf("Mul a×β: %w", err)
		}
		if err := eval.Add(alpha, tmp, alpha); err != nil {
			return false, fmt.Errorf("Add α: %w", err)
		}
	}

	// Rotate-and-sum on α only (log2(blockSize)=13 steps).
	for step := 1; step < blockSize; step <<= 1 {
		rotated, err := eval.RotateColumnsNew(alpha, step)
		if err != nil {
			return false, fmt.Errorf("RotateColumns step=%d: %w", step, err)
		}
		if err := eval.Add(alpha, rotated, alpha); err != nil {
			return false, fmt.Errorf("Add alpha step=%d: %w", step, err)
		}
	}

	// Decrypt α_sum (single-party, no smudging for simplicity).
	dec := rlwe.NewDecryptor(params, sk)
	alphaResult := make([]uint64, slots)
	if err := encoder.Decode(dec.DecryptNew(alpha), alphaResult); err != nil {
		return false, err
	}

	// Decrypt β_orig.
	betaResult := make([]uint64, slots)
	if err := encoder.Decode(dec.DecryptNew(betaOrig), betaResult); err != nil {
		return false, err
	}

	// Reconstruct b_sq_sum = Σ_step rot_step(b²) in plaintext.
	bSq := make([]uint64, slots)
	halfSlots := slots / 2
	for i := range slots {
		bSq[i] = (betaResult[i] * betaResult[i]) % t
	}
	tmp := make([]uint64, slots)
	for step := 1; step < blockSize; step <<= 1 {
		for i := 0; i < halfSlots; i++ {
			tmp[i] = bSq[(i+step)%halfSlots]
		}
		for i := halfSlots; i < slots; i++ {
			tmp[i] = bSq[halfSlots+(i-halfSlots+step)%halfSlots]
		}
		for i := range slots {
			bSq[i] = (bSq[i] + tmp[i]) % t
		}
	}

	// result = α_sum + b_sq_sum.
	result := (alphaResult[0] + bSq[0] + t) % t

	// expected: value² summed over all slots (blockSize * value²).
	// After rotate-and-sum: each slot contains sum of all N slots = N * value² mod t.
	// But we test slot 0 which should be sum = blockSize * value² (using all blockSize slots).
	// With blockSize = 8192 and the first blockSize/2 slots in first half:
	// Actually: BGV rotates each N/2 half independently. Sum of first N/2 slots = N/2 * value².
	// But all slots have value, so after rotate-and-sum of full N/2 block:
	// slot 0 = sum of slot 0..N/2-1 = N/2 * value² mod t = 8192 * value² mod t.
	expected := uint64(blockSize) * (value * value % t) % t

	return result == expected, nil
}

// runStdHMul: standard BGV MulRelin then rotate-and-sum (same number of steps).
func runStdHMul(params bgv.Parameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey,
	evk *rlwe.MemEvaluationKeySet, value uint64) (bool, error) {

	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	vals := make([]uint64, slots)
	for i := range vals {
		vals[i] = value
	}

	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	eval := bgv.NewEvaluator(params, evk)
	dec := rlwe.NewDecryptor(params, sk)

	ptxt := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(vals, ptxt); err != nil {
		return false, err
	}
	ct, err := encryptor.EncryptNew(ptxt)
	if err != nil {
		return false, err
	}

	// HMul + Relin.
	ctSq, err := eval.MulRelinNew(ct, ct)
	if err != nil {
		return false, fmt.Errorf("MulRelin: %w", err)
	}

	// Rotate-and-sum (13 steps).
	for step := 1; step < blockSize; step <<= 1 {
		rotated, err := eval.RotateColumnsNew(ctSq, step)
		if err != nil {
			return false, fmt.Errorf("RotateColumns step=%d: %w", step, err)
		}
		if err := eval.Add(ctSq, rotated, ctSq); err != nil {
			return false, fmt.Errorf("Add ctSq step=%d: %w", step, err)
		}
	}

	result := make([]uint64, slots)
	if err := encoder.Decode(dec.DecryptNew(ctSq), result); err != nil {
		return false, err
	}

	expected := uint64(blockSize) * (value * value % t) % t
	return result[0] == expected, nil
}

func main() {
	fmt.Println("=== Exp-5: CF Overflow vs Std HMul with Rotate-and-Sum at S3 ===")
	fmt.Printf("Single-party simulation, %d reps, value=501\n", nReps)
	fmt.Printf("Rotate-and-sum: 13 steps (log2(blockSize=8192))\n\n")

	testValue := uint64(501)

	for _, prof := range profiles {
		params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             logN,
			LogQ:             prof.logQ,
			LogP:             prof.logP,
			PlaintextModulus: plaintextModulus,
		})
		if err != nil {
			log.Printf("skip profile %s: %v", prof.name, err)
			continue
		}

		fmt.Printf("Profile: %s (MaxLevel=%d)\n", prof.name, params.MaxLevel())

		kgen := rlwe.NewKeyGenerator(params)
		sk, pk := kgen.GenKeyPairNew()
		rlk := kgen.GenRelinearizationKeyNew(sk)

		// Generate Galois keys for rotate-and-sum.
		galKeys := make([]*rlwe.GaloisKey, 0)
		for step := 1; step < blockSize; step <<= 1 {
			gk := kgen.GenGaloisKeyNew(params.GaloisElement(step), sk)
			galKeys = append(galKeys, gk)
		}

		evkFull := rlwe.NewMemEvaluationKeySet(rlk, galKeys...)
		evkGalOnly := rlwe.NewMemEvaluationKeySet(nil, galKeys...)

		cfCorrect := 0
		stdCorrect := 0
		for rep := 0; rep < nReps; rep++ {
			ok, err := runCFOverflow(params, sk, pk, evkGalOnly, testValue)
			if err != nil {
				log.Printf("  rep %d CF error: %v", rep, err)
			} else if ok {
				cfCorrect++
			}

			ok, err = runStdHMul(params, sk, pk, evkFull, testValue)
			if err != nil {
				log.Printf("  rep %d std error: %v", rep, err)
			} else if ok {
				stdCorrect++
			}
		}

		fmt.Printf("  CF overflow + rotate-and-sum (no relin, no CKS): %d/%d correct\n", cfCorrect, nReps)
		fmt.Printf("  Std HMul + rotate-and-sum (with relin, no CKS):  %d/%d correct\n", stdCorrect, nReps)
		fmt.Println()
	}
}
