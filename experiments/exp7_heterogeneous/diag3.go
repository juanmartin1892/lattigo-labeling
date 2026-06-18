//go:build ignore

// diag3: binary search for the max `a` that still works at S3/min,
// and directly measure KS noise per rotation.
// Run: go run ./experiments/exp7_heterogeneous/diag3.go
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

	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             []int{35, 35},
		LogP:             []int{35, 35},
		PlaintextModulus: t,
	})
	if err != nil {
		log.Fatal(err)
	}
	budget := budgetBits(params)
	fmt.Printf("S3/min: MaxLevel=%d budget=2^%.1f\n\n", params.MaxLevel(), budget)

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

	// --- Test 1: measure KS noise per rotation step ---
	// Strategy: Encrypt Enc([0,...,0]), apply RotAS step by step, measure max deviation.
	// Since the plaintext is 0, all decoded values should be 0. Any non-zero value = KS noise.
	fmt.Println("=== Test 1: KS noise per rotation (encrypting 0, apply each rotation) ===")
	zeroVec := make([]uint64, slots)
	ptZero := bgv.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(zeroVec, ptZero)

	maxKSNoiseSeen := uint64(0)
	for step := 1; step < blockSz; step <<= 1 {
		ct, _ := encryptor.EncryptNew(ptZero)
		rotated, _ := eval.RotateColumnsNew(ct, step)
		decoded := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(rotated), decoded)
		maxNoise := uint64(0)
		for _, v := range decoded {
			e := absDiff(v, 0, t)
			if e > maxNoise {
				maxNoise = e
			}
		}
		if maxNoise > maxKSNoiseSeen {
			maxKSNoiseSeen = maxNoise
		}
		if step <= 64 || step >= 2048 {
			fmt.Printf("  KS noise for rotate(%4d): max=%d (2^%.1f)\n", step, maxNoise, math.Log2(float64(maxNoise+1)))
		}
	}
	fmt.Printf("  Max KS noise across all rotations: 2^%.1f\n\n", math.Log2(float64(maxKSNoiseSeen+1)))

	// --- Test 2: binary search for max a ---
	// For the CF alpha build with aVec (N/2-fill) and given b, find max a that passes RotAS at S3/min.
	fmt.Println("=== Test 2: binary search for max a that passes S3/min RotAS ===")
	b := uint64(100)
	lo, hi := uint64(100), uint64(100000)

	testA := func(a uint64) bool {
		aVec := make([]uint64, slots)
		a2Vec := make([]uint64, slots)
		bVec := make([]uint64, slots)
		for i := range slots {
			bVec[i] = b
		}
		for i := range blockSz {
			aVec[i] = a
			a2Vec[i] = a * a % t
		}
		ptA2 := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(a2Vec, ptA2)
		ctAlpha, _ := encryptor.EncryptNew(ptA2)
		ptB := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(bVec, ptB)
		ctBeta, _ := encryptor.EncryptNew(ptB)
		for range 2 {
			tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
			eval.Mul(ctBeta, aVec, tmp)
			eval.Add(ctAlpha, tmp, ctAlpha)
		}
		// RotAS
		for step := 1; step < blockSz; step <<= 1 {
			rotated, _ := eval.RotateColumnsNew(ctAlpha, step)
			eval.Add(ctAlpha, rotated, ctAlpha)
		}
		correction := uint64(blockSz) * (b * b % t) % t
		decRes := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(ctAlpha), decRes)
		// Expected: blockSz × ((a+b)² % t)
		vSq := (a + b) * (a + b) % t
		expected := uint64(blockSz) * vSq % t
		result := (decRes[0] + correction) % t
		return result == expected
	}

	// Known bounds: a=250 passes, a=750 fails.
	// Binary search in [250, 750].
	lo, hi = 250, 750
	for lo < hi-1 {
		mid := (lo + hi) / 2
		if testA(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	fmt.Printf("  max a that passes: %d (fails at %d)\n", lo, hi)

	bFresh := 3.2 * math.Sqrt(float64(N))
	// The noise just before RotAS: ≈ (1+2a)×B_fresh
	noiseBeforeRAS := float64(1+2*lo) * bFresh
	noiseAfterRAS := float64(blockSz) * noiseBeforeRAS
	fmt.Printf("  B_fresh=2^%.1f, (1+2a)×B_fresh=2^%.1f, ×blockSz=2^%.1f, budget=2^%.1f\n",
		math.Log2(bFresh), math.Log2(noiseBeforeRAS), math.Log2(noiseAfterRAS), budget)
	fmt.Println()

	// --- Test 3: pure fresh ciphertext RotAS (no CT×PT) ---
	// Encrypt [v, ..., v, 0, ..., 0] fresh, apply RotAS, decode.
	// This isolates the KS noise growth without the CT×PT multiplication noise.
	fmt.Println("=== Test 3: fresh ciphertext RotAS at S3/min (no CT×PT) ===")
	for _, v := range []uint64{100, 250, 500, 750, 1000, 5000, 100000} {
		vVec := make([]uint64, slots)
		for i := range blockSz {
			vVec[i] = v
		}
		ptV := bgv.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(vVec, ptV)
		ctV, _ := encryptor.EncryptNew(ptV)
		for step := 1; step < blockSz; step <<= 1 {
			rotated, _ := eval.RotateColumnsNew(ctV, step)
			eval.Add(ctV, rotated, ctV)
		}
		decV := make([]uint64, slots)
		encoder.Decode(dec.DecryptNew(ctV), decV)
		expected := uint64(blockSz) * v % t
		pass := decV[0] == expected
		fmt.Printf("  v=%6d: RotAS slot0=%d expected=%d PASS=%v\n", v, decV[0], expected, pass)
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
