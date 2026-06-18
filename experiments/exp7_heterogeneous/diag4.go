//go:build ignore

// diag4: repeated trials to confirm the real threshold for a (CF compact RotAS at S3/min).
// The binary search in diag3 may have found a spurious threshold due to random noise.
// Run: go run ./experiments/exp7_heterogeneous/diag4.go
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

	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             []int{35, 35},
		LogP:             []int{35, 35},
		PlaintextModulus: t,
	})
	if err != nil {
		log.Fatal(err)
	}
	slots := params.MaxSlots() // N/2 = 8192
	blockSz := slots

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

	b := uint64(100)

	// Build constant vectors for b only once.
	bVec := make([]uint64, slots)
	for i := range slots {
		bVec[i] = b
	}
	ptB := bgv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(bVec, ptB)

	testA := func(a uint64) bool {
		aVec := make([]uint64, slots)
		a2Vec := make([]uint64, slots)
		for i := range blockSz {
			aVec[i] = a
			a2Vec[i] = a * a % t
		}
		ptA2 := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(a2Vec, ptA2)
		ctAlpha, _ := encryptor.EncryptNew(ptA2)
		ctBeta, _ := encryptor.EncryptNew(ptB)
		for range 2 {
			tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
			eval.Mul(ctBeta, aVec, tmp)
			eval.Add(ctAlpha, tmp, ctAlpha)
		}
		for step := 1; step < blockSz; step <<= 1 {
			rotated, _ := eval.RotateColumnsNew(ctAlpha, step)
			eval.Add(ctAlpha, rotated, ctAlpha)
		}
		correction := uint64(blockSz) * (b * b % t) % t
		decRes := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(ctAlpha), decRes)
		vSq := (a + b) * (a + b) % t
		expected := uint64(blockSz) * vSq % t
		result := (decRes[0] + correction) % t
		return result == expected
	}

	// Noise model: after 2×Mul(ctBeta, [a,...,a]) + RotAS over 12 steps
	// noise ≈ 2^12 × (1+2a) × B_fresh
	bFresh := 3.2 * math.Sqrt(float64(N))
	fmt.Printf("B_fresh = %.1f = 2^%.2f\n", bFresh, math.Log2(bFresh))
	fmt.Printf("Budget  = 2^%.1f\n\n", 43.0)

	trials := 5
	fmt.Printf("Testing a values with %d trials each:\n", trials)
	fmt.Printf("%-8s %-10s %-12s %-12s %s\n", "a", "noise2^", "budget2^", "margin2^", "results")
	fmt.Printf("%-8s %-10s %-12s %-12s %s\n", "---", "-------", "--------", "--------", "-------")

	for _, a := range []uint64{100, 200, 300, 312, 313, 400, 500, 600, 700, 800, 1000, 2000, 5000, 10000, 50000} {
		noise := float64(1<<12) * float64(1+2*a) * bFresh
		noiseLog2 := math.Log2(noise)
		margin := 43.0 - noiseLog2
		results := ""
		passes := 0
		for range trials {
			if testA(a) {
				results += "P"
				passes++
			} else {
				results += "F"
			}
		}
		fmt.Printf("a=%-6d noise=2^%-5.1f margin=%-5.1f  [%s] %d/%d\n",
			a, noiseLog2, margin, results, passes, trials)
	}

	// Also test the heterogeneous case: vMin=100, vMax=200, b=99, a_i = v_i - b
	// max(a_i) = vMax - b = 101
	fmt.Println()
	fmt.Println("=== Heterogeneous test: v_i random in [vMin, vMax], b = vMin-1 ===")
	testHetero := func(vMin, vMax uint64) (passes, total int) {
		bj := vMin - 1
		N2 := slots
		vVec := make([]uint64, N2)
		for i := range N2 {
			vVec[i] = vMin + uint64(i)%(vMax-vMin+1)
		}
		aVec := make([]uint64, slots)
		a2Vec := make([]uint64, slots)
		bjVec := make([]uint64, slots)
		for i := range N2 {
			aVec[i] = vVec[i] - bj
			a2Vec[i] = aVec[i] * aVec[i] % t
			bjVec[i] = bj
		}
		expectedSum := uint64(0)
		for _, v := range vVec {
			expectedSum = (expectedSum + v%t*v%t) % t
		}
		for range trials {
			ptA2 := bgv.NewPlaintext(params, params.MaxLevel())
			encoder.Encode(a2Vec, ptA2)
			ctAlpha, _ := encryptor.EncryptNew(ptA2)
			ptBj := bgv.NewPlaintext(params, params.MaxLevel())
			encoder.Encode(bjVec, ptBj)
			ctBeta, _ := encryptor.EncryptNew(ptBj)
			for range 2 {
				tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
				eval.Mul(ctBeta, aVec, tmp)
				eval.Add(ctAlpha, tmp, ctAlpha)
			}
			for step := 1; step < blockSz; step <<= 1 {
				rotated, _ := eval.RotateColumnsNew(ctAlpha, step)
				eval.Add(ctAlpha, rotated, ctAlpha)
			}
			correction := uint64(N2) * (bj * bj % t) % t
			decRes := make([]uint64, slots)
			encoder.Decode(dec.DecryptNew(ctAlpha), decRes)
			result := (decRes[0] + correction) % t
			total++
			if result == expectedSum {
				passes++
			}
		}
		return
	}

	for _, r := range []struct{ vMin, vMax uint64 }{
		{100, 200},   // max a = 101
		{100, 400},   // max a = 301
		{100, 500},   // max a = 401
		{100, 600},   // max a = 501
		{100, 800},   // max a = 701
		{100, 1000},  // max a = 901
		{100, 5000},  // max a = 4901
		{1000, 2000}, // max a = 1001
	} {
		maxA := r.vMax - (r.vMin - 1)
		noise := float64(1<<12) * float64(1+2*maxA) * bFresh
		passes, total := testHetero(r.vMin, r.vMax)
		fmt.Printf("  vMin=%5d vMax=%5d maxA=%5d noise=2^%-5.1f %d/%d\n",
			r.vMin, r.vMax, maxA, math.Log2(noise), passes, total)
	}
}
