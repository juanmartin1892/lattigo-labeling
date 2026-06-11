//go:build ignore

// diag2: measures KS noise and confirms the N/2-fill vs N-fill issue.
// Key hypothesis: filling only first N/2 slots (second half = 0) creates a plaintext
// polynomial with large coefficients O(t), while filling ALL N slots with the same
// value creates a constant polynomial with coefficients bounded by the value.
// Run: go run ./experiments/exp7_heterogeneous/diag2.go
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
	N := 1 << logN
	blockSz := N / 2

	// S3/min only.
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             []int{35, 35},
		LogP:             []int{35, 35},
		PlaintextModulus: t,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("S3/min: MaxLevel=%d, budget≈2^%.1f\n\n", params.MaxLevel(), budgetBits(params))

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

	slots := params.MaxSlots()
	a := uint64(250)

	// Test 1: measure KS noise directly.
	// Encrypt zeros, rotate N/2-1 steps, see if it decodes correctly.
	fmt.Println("=== Test 1: KS noise accumulation (encrypt fresh, apply RotAS) ===")
	zeroVec := make([]uint64, slots)
	ptZero := bgv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(zeroVec, ptZero)
	ctFresh, _ := encryptor.EncryptNew(ptZero)
	// check: basic decrypt of zero ciphertext
	decZ := make([]uint64, slots)
	encoder.Decode(dec.DecryptNew(ctFresh), decZ)
	fmt.Printf("  Fresh Enc(0) slot0=%d PASS=%v\n", decZ[0], decZ[0] == 0)

	// Apply each rotation step and check.
	ctRotSum := rlwe.NewCiphertext(params, 1, params.MaxLevel())
	// start with all-a vector (n slots) to have a non-trivial result
	aVecFull := make([]uint64, slots)
	for i := range slots {
		aVecFull[i] = a
	}
	ptA := bgv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(aVecFull, ptA)
	ctRotSum, _ = encryptor.EncryptNew(ptA)

	expectedSum := a
	for step, k := 1, 1; step < blockSz; step, k = step<<1, k+1 {
		rotated, err := eval.RotateColumnsNew(ctRotSum, step)
		if err != nil {
			log.Fatalf("RotateColumns step=%d: %v", step, err)
		}
		if err := eval.Add(ctRotSum, rotated, ctRotSum); err != nil {
			log.Fatalf("Add: %v", err)
		}
		expectedSum = (expectedSum * 2) % t
		decS := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(ctRotSum), decS)
		pass := decS[0] == expectedSum
		if !pass || k >= 11 {
			fmt.Printf("  RotAS step%2d (rot=%4d): slot0=%d expected=%d PASS=%v\n", k, step, decS[0], expectedSum, pass)
		}
	}
	fmt.Println()

	// Test 2: N-fill vs N/2-fill for the same scalar a.
	fmt.Println("=== Test 2: N-fill (all slots) vs N/2-fill (first half only) ===")
	b := uint64(100)
	// a = value - b where value fills slots
	val := uint64(350) // value per slot
	aConst := val - b  // = 250

	// N-fill: both halves have aConst (same as exp6 approach)
	aVecNFull := make([]uint64, slots)
	for i := range slots {
		aVecNFull[i] = aConst
	}
	bVecFull := make([]uint64, slots)
	for i := range slots {
		bVecFull[i] = b
	}

	// N/2-fill: only first half has aConst, second half = 0.
	aVecHalf := make([]uint64, slots)
	for i := range blockSz {
		aVecHalf[i] = aConst
	}
	bVecHalf := make([]uint64, slots)
	for i := range blockSz {
		bVecHalf[i] = b
	}

	testConfig := []struct {
		name string
		aVec []uint64
		bVec []uint64
	}{
		{"N-fill (all slots)", aVecNFull, bVecFull},
		{"N/2-fill (half slots)", aVecHalf, bVecHalf},
	}

	for _, tc := range testConfig {
		// Build alpha: Enc(a²) + 2×(β × aVec)
		a2Vec := make([]uint64, slots)
		for i, av := range tc.aVec {
			a2Vec[i] = av * av % t
		}
		ptA2 := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(a2Vec, ptA2)
		ctAlpha, _ := encryptor.EncryptNew(ptA2)

		ptB := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(tc.bVec, ptB)
		ctBeta, _ := encryptor.EncryptNew(ptB)

		for range 2 {
			tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
			eval.Mul(ctBeta, tc.aVec, tmp)
			eval.Add(ctAlpha, tmp, ctAlpha)
		}

		// Decode BEFORE RotAS.
		preRAS := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(ctAlpha), preRAS)
		expSlot0BeforeRAS := (val*val%t + t - b*b%t) % t
		fmt.Printf("  [%s] Before RotAS: slot0=%d expected=%d PASS=%v\n",
			tc.name, preRAS[0], expSlot0BeforeRAS, preRAS[0] == expSlot0BeforeRAS)

		// RotAS.
		failStep := -1
		for step, k := 1, 1; step < blockSz; step, k = step<<1, k+1 {
			rotated, _ := eval.RotateColumnsNew(ctAlpha, step)
			eval.Add(ctAlpha, rotated, ctAlpha)
			tmp2 := make([]uint64, slots)
			encoder.Decode(dec.DecryptNew(ctAlpha), tmp2)
			// After k steps with constant data, slot0 = 2^k × (v²-b²).
			expK := uint64(1) << k
			expK = expK * expSlot0BeforeRAS % t
			pass := tmp2[0] == expK
			if !pass && failStep < 0 {
				failStep = k
				fmt.Printf("  [%s] RotAS FAILS at step %d (rot=%d): slot0=%d expected=%d\n",
					tc.name, k, step, tmp2[0], expK)
			}
		}
		if failStep < 0 {
			fmt.Printf("  [%s] RotAS ALL 13 steps PASS\n", tc.name)
		}
	}
	fmt.Println()

	// Test 3: measure effective noise introduced by CT×PT with N/2-fill.
	// Compute: (noise in aVec N/2-fill) vs (noise in aVec N-fill) by
	// running 1 iteration of Mul and checking the coefficient noise empirically.
	fmt.Println("=== Test 3: Noise after single Mul (N-fill vs N/2-fill aVec) ===")
	// Encrypt single fresh ciphertext and multiply.
	ptSmall := bgv.NewPlaintext(params, params.MaxLevel())
	smallVec := make([]uint64, slots)
	for i := range slots {
		smallVec[i] = 1 // encrypt 1 in all slots (fresh noise B_fresh)
	}
	encoder.Encode(smallVec, ptSmall)
	ctSmall, _ := encryptor.EncryptNew(ptSmall)

	for _, name := range []string{"N-fill", "N/2-fill"} {
		var aTest []uint64
		if name == "N-fill" {
			aTest = aVecNFull // [250, ..., 250] for all slots
		} else {
			aTest = aVecHalf // [250, ..., 250, 0, ..., 0]
		}

		tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := eval.Mul(ctSmall, aTest, tmp); err != nil {
			log.Fatalf("Mul: %v", err)
		}

		// Decode: should give aTest slot values. Any deviation = noise.
		decMul := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(tmp), decMul)

		// Expected: aTest[i] × 1 = aTest[i]
		maxErr := uint64(0)
		for i := range slots {
			want := aTest[i]
			got := decMul[i]
			err := absDiff(got, want, t)
			if err > maxErr {
				maxErr = err
			}
		}
		fmt.Printf("  [%s] After Mul: max noise ≈ %d (budget=2^%.1f, noise/budget=2^%.1f)\n",
			name, maxErr, budgetBits(params),
			math.Log2(float64(maxErr+1))-budgetBits(params))
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
