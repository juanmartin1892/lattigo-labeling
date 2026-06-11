//go:build ignore

// diag: single-block step-by-step verification of the CF heterogeneous formula.
// Run: go run ./experiments/exp7_heterogeneous/diag.go
package main

import (
	"fmt"
	"log"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	logN := 14
	t := uint64(0x3ee0001)
	blockSz := 8192

	profiles := []struct {
		name string
		logQ []int
		logP []int
	}{
		{"full", []int{56, 55, 55, 54}, []int{55, 55}},
		{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
		{"min", []int{35, 35}, []int{35, 35}},
	}

	// Heterogeneous values: v_i = 100 + i%501 (deterministic spread)
	vVec := make([]uint64, blockSz)
	for i := range blockSz {
		vVec[i] = 100 + uint64(i)%501
	}
	bj := uint64(50) // broadcast mask, < vMin=100

	// Expected: Σ v_i²
	expectedPlain := uint64(0)
	for _, v := range vVec {
		expectedPlain = (expectedPlain + v%t*v%t) % t
	}
	fmt.Printf("Expected Σ v_i² mod t: %d\n\n", expectedPlain)

	for _, prof := range profiles {
		params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             logN,
			LogQ:             prof.logQ,
			LogP:             prof.logP,
			PlaintextModulus: t,
		})
		if err != nil {
			log.Printf("skip %s: %v", prof.name, err)
			continue
		}
		fmt.Printf("=== Profile %s (MaxLevel=%d, budget≈2^%.1f) ===\n",
			prof.name, params.MaxLevel(), budgetBits(params))

		kgen := rlwe.NewKeyGenerator(params)
		sk, pk := kgen.GenKeyPairNew()
		galKeys := make([]*rlwe.GaloisKey, 0)
		for step := 1; step < blockSz; step <<= 1 {
			gk := kgen.GenGaloisKeyNew(params.GaloisElement(step), sk)
			galKeys = append(galKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galKeys...)

		encoder := bgv.NewEncoder(params)
		encryptor := rlwe.NewEncryptor(params, pk)
		dec := rlwe.NewDecryptor(params, sk)
		eval := bgv.NewEvaluator(params, evk)

		N := params.N()
		slots := params.MaxSlots()

		// Build aVec, a2Vec, bjVec.
		aVec := make([]uint64, slots)
		a2Vec := make([]uint64, slots)
		bjVec := make([]uint64, slots)
		for i := range blockSz {
			a := vVec[i] - bj
			aVec[i] = a
			a2Vec[i] = a * a % t
			bjVec[i] = bj
		}

		// Step 1: encrypt α = Enc([a_i²]).
		ptA2 := bgv.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(a2Vec, ptA2); err != nil {
			log.Fatalf("encode a2Vec: %v", err)
		}
		alpha, err := encryptor.EncryptNew(ptA2)
		if err != nil {
			log.Fatalf("enc a2Vec: %v", err)
		}

		// Decode immediately after encryption.
		step0 := make([]uint64, slots)
		if err := encoder.Decode(dec.DecryptNew(alpha), step0); err == nil {
			ok := true
			for i := range blockSz {
				if step0[i] != a2Vec[i] {
					ok = false
					break
				}
			}
			fmt.Printf("  Step 0: Enc(a²) decrypt correct: %v (slot0=%d, expected=%d)\n",
				ok, step0[0], a2Vec[0])
		}

		// Step 2: encrypt β = Enc([bj,...]).
		ptBj := bgv.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(bjVec, ptBj); err != nil {
			log.Fatalf("encode bjVec: %v", err)
		}
		beta, err := encryptor.EncryptNew(ptBj)
		if err != nil {
			log.Fatalf("enc bjVec: %v", err)
		}

		// Step 3: tmp = β × aVec (single multiplication).
		tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := eval.Mul(beta, aVec, tmp); err != nil {
			log.Fatalf("Mul β×a: %v", err)
		}

		// Decode tmp.
		step3 := make([]uint64, slots)
		if err := encoder.Decode(dec.DecryptNew(tmp), step3); err == nil {
			expectedSlot0 := bj * (vVec[0] - bj) % t
			fmt.Printf("  Step 3: β×a slot0=%d expected=%d correct=%v\n",
				step3[0], expectedSlot0, step3[0] == expectedSlot0)
		}

		// Step 4: α += 2×tmp.
		for range 2 {
			tmp2 := rlwe.NewCiphertext(params, 1, params.MaxLevel())
			if err := eval.Mul(beta, aVec, tmp2); err != nil {
				log.Fatalf("Mul β×a (loop): %v", err)
			}
			if err := eval.Add(alpha, tmp2, alpha); err != nil {
				log.Fatalf("Add: %v", err)
			}
		}

		// Decode after double add: should be [v_i² - bj²].
		step4 := make([]uint64, slots)
		if err := encoder.Decode(dec.DecryptNew(alpha), step4); err == nil {
			expectedSlot0 := (vVec[0]*vVec[0] - bj*bj + t) % t
			fmt.Printf("  Step 4: α[0]=v²-b² slot0=%d expected=%d correct=%v\n",
				step4[0], expectedSlot0, step4[0] == expectedSlot0)
		}

		// Step 5: rotate-and-sum — test per step to find where noise exceeds budget.
		correction := uint64(blockSz) * (bj * bj % t) % t
		stepNum := 0
		for step := 1; step < blockSz; step <<= 1 {
			rotated, err := eval.RotateColumnsNew(alpha, step)
			if err != nil {
				log.Fatalf("RotateColumns step=%d: %v", step, err)
			}
			if err := eval.Add(alpha, rotated, alpha); err != nil {
				log.Fatalf("Add rotated: %v", err)
			}
			stepNum++
			// Decode intermediate result to detect where error first appears.
			tmp := make([]uint64, slots)
			if err := encoder.Decode(dec.DecryptNew(alpha), tmp); err == nil {
				// After k steps, slot 0 = Σ_{i=0}^{2^k - 1} (v_i²-bj²).
				partialSum := uint64(0)
				for i := 0; i < (1 << stepNum); i++ {
					partialSum = (partialSum + (vVec[i]*vVec[i]%t + t - bj*bj%t)) % t
				}
				got := tmp[0]
				expected_here := partialSum
				pass := got == expected_here
				if !pass || stepNum >= 11 {
					fmt.Printf("  RotAS step%2d (rot=%4d): slot0=%d expected=%d PASS=%v\n",
						stepNum, step, got, expected_here, pass)
				}
			}
		}

		finalResult := make([]uint64, slots)
		if err := encoder.Decode(dec.DecryptNew(alpha), finalResult); err == nil {
			rawSlot0 := finalResult[0]
			result := (rawSlot0 + correction) % t
			fmt.Printf("  Step 5 final: slot0=%d correction=%d result=%d expected=%d PASS=%v\n",
				rawSlot0, correction, result, expectedPlain, result == expectedPlain)
		}

		// --- KS noise measurement ---
		// Encrypt a known ciphertext, apply ONE rotation (step=32, which causes failure),
		// decrypt and measure the deviation from expected to estimate B_ks.
		fmt.Printf("  [KS noise test: rotate a freshly encrypted constant by 32]\n")
		testVal := uint64(1000)
		testVec := make([]uint64, slots)
		for i := range blockSz {
			testVec[i] = testVal
		}
		ptTest := bgv.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(testVec, ptTest); err == nil {
			ctTest, _ := encryptor.EncryptNew(ptTest)
			// Rotate by 32.
			rotTest, err := eval.RotateColumnsNew(ctTest, 32)
			if err == nil {
				decTest := make([]uint64, slots)
				if err := encoder.Decode(dec.DecryptNew(rotTest), decTest); err == nil {
					// After rotation by 32: slot[0] should be old slot[32] = testVal.
					gotSlot0 := decTest[0]
					expSlot0 := testVal
					fmt.Printf("    After Rotate(ct_const, 32): slot0=%d expected=%d diff=%d PASS=%v\n",
						gotSlot0, expSlot0, absDiff(gotSlot0, expSlot0, t), gotSlot0 == expSlot0)
				}
			}
		}

		// --- Test with constant values in heterogeneous code path ---
		// If buildBlockAlphaHetero with all-same values behaves like exp6 (homogeneous),
		// it should also pass at S3/min.
		fmt.Printf("  [Homogeneous path through buildBlockAlphaHetero: v_i=%d for all i]\n", testVal)
		constVec := make([]uint64, blockSz)
		constB := uint64(250)
		for i := range blockSz {
			constVec[i] = testVal
		}
		expectedConst := (testVal * testVal % t * uint64(blockSz)) % t
		// rebuild alpha for constant data:
		constAVec := make([]uint64, slots)
		constA2Vec := make([]uint64, slots)
		constBVec := make([]uint64, slots)
		constA := testVal - constB
		for i := range slots {
			constBVec[i] = constB
		}
		for i := range blockSz {
			constAVec[i] = constA
			constA2Vec[i] = constA * constA % t
		}
		ptCA2 := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(constA2Vec, ptCA2)
		ctCA, _ := encryptor.EncryptNew(ptCA2)
		ptCB := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(constBVec, ptCB)
		ctCB, _ := encryptor.EncryptNew(ptCB)
		for range 2 {
			tmpC := rlwe.NewCiphertext(params, 1, params.MaxLevel())
			eval.Mul(ctCB, constAVec, tmpC)
			eval.Add(ctCA, tmpC, ctCA)
		}
		for step := 1; step < blockSz; step <<= 1 {
			rotated, _ := eval.RotateColumnsNew(ctCA, step)
			eval.Add(ctCA, rotated, ctCA)
		}
		constCorr := uint64(blockSz) * (constB * constB % t) % t
		decConst := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(ctCA), decConst)
		constResult := (decConst[0] + constCorr) % t
		fmt.Printf("    Result=%d expected=%d PASS=%v\n\n", constResult, expectedConst, constResult == expectedConst)

		// Noise model estimate for this profile.
		bFresh := 3.2 * math.Sqrt(float64(N))
		// NTT-domain analysis: max(NTT(PT_a)) = max(a_i) ≤ vMax ≈ 550
		maxA := float64(500) // vMax - bj
		bMul := maxA * bFresh
		bRotAS := float64(blockSz) * bMul
		budg := math.Pow(2, budgetBits(params))
		fmt.Printf("  Noise model: B_fresh=2^%.1f, max(a)=%.0f, B_mul=2^%.1f, B_RotAS=2^%.1f, budget=2^%.1f %s\n\n",
			math.Log2(bFresh), maxA, math.Log2(bMul), math.Log2(bRotAS), math.Log2(budg),
			func() string {
				if bRotAS < budg {
					return "✓"
				}
				return "✗"
			}())
	}
}

func absDiff(a, b, t uint64) uint64 {
	if a >= b {
		d := a - b
		if d > t/2 {
			return t - d
		}
		return d
	}
	d := b - a
	if d > t/2 {
		return t - d
	}
	return d
}

func budgetBits(params bgv.Parameters) float64 {
	logQ := 0.0
	for _, q := range params.Q() {
		logQ += math.Log2(float64(q))
	}
	return logQ - math.Log2(float64(params.PlaintextModulus())) - 1
}
