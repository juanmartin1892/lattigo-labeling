//go:build ignore

// multest: quickly verifies the BGV MulRelin behaviour with a concrete example.
// Encrypts [2,...,2], computes self-product, checks result with and without Rescale.
package main

import (
	"fmt"
	"log"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	t := uint64(0x3ee0001)

	// Use a larger profile to ensure correctness regardless of noise.
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{56, 55, 55, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: t,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("LogN=%d MaxLevel=%d DefaultScale=%v\n", params.LogN(), params.MaxLevel(), params.DefaultScale())

	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	rlk := kgen.GenRelinearizationKeyNew(sk)
	evk := rlwe.NewMemEvaluationKeySet(rlk)
	enc := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)
	ecd := bgv.NewEncoder(params)
	eval := bgv.NewEvaluator(params, evk)

	slots := params.MaxSlots()
	vals := make([]uint64, slots)
	for i := range slots {
		vals[i] = 2 // all slots = 2, expected product = 4
	}
	expected := uint64(4)

	pt := bgv.NewPlaintext(params, params.MaxLevel())
	ecd.Encode(vals, pt)
	ct, _ := enc.EncryptNew(pt)
	fmt.Printf("Fresh scale: %v, level: %d\n", ct.Scale, ct.Level())

	// 1. MulRelin without Rescale
	ctSq, _ := eval.MulRelinNew(ct, ct)
	fmt.Printf("After MulRelin: scale=%v level=%d\n", ctSq.Scale, ctSq.Level())
	decoded := make([]uint64, slots)
	ecd.Decode(dec.DecryptNew(ctSq), decoded)
	fmt.Printf("  Without Rescale: slot0=%d expected=%d PASS=%v\n", decoded[0], expected, decoded[0] == expected)

	// 2. MulRelin with Rescale
	ctSq2, _ := eval.MulRelinNew(ct, ct)
	if err := eval.Rescale(ctSq2, ctSq2); err != nil {
		fmt.Printf("  Rescale error: %v\n", err)
	} else {
		fmt.Printf("After Rescale: scale=%v level=%d\n", ctSq2.Scale, ctSq2.Level())
		decoded2 := make([]uint64, slots)
		ecd.Decode(dec.DecryptNew(ctSq2), decoded2)
		fmt.Printf("  With Rescale: slot0=%d expected=%d PASS=%v\n", decoded2[0], expected, decoded2[0] == expected)
	}

	// 3. MulRelin + RotAS (constant value) — full pipeline test
	fmt.Println()
	fmt.Println("=== Full pipeline: MulRelin + RotAS ===")
	v := uint64(100)
	vVec := make([]uint64, slots)
	for i := range slots {
		vVec[i] = v
	}
	ptV := bgv.NewPlaintext(params, params.MaxLevel())
	ecd.Encode(vVec, ptV)
	ctV, _ := enc.EncryptNew(ptV)

	// Galois keys for RotAS
	galKeys := make([]*rlwe.GaloisKey, 0)
	for step := 1; step < slots; step <<= 1 {
		galKeys = append(galKeys, kgen.GenGaloisKeyNew(params.GaloisElement(step), sk))
	}
	evkFull := rlwe.NewMemEvaluationKeySet(rlk, galKeys...)
	evalFull := bgv.NewEvaluator(params, evkFull)

	expectedSum := uint64(slots) * v % t * v % t
	expectedSum = (uint64(slots) * (v * v % t)) % t

	// Without Rescale
	ctVsq, _ := evalFull.MulRelinNew(ctV, ctV)
	for step := 1; step < slots; step <<= 1 {
		rotated, _ := evalFull.RotateColumnsNew(ctVsq, step)
		evalFull.Add(ctVsq, rotated, ctVsq)
	}
	decFull := make([]uint64, slots)
	ecd.Decode(dec.DecryptNew(ctVsq), decFull)
	fmt.Printf("  Without Rescale: slot0=%d expected=%d PASS=%v\n", decFull[0], expectedSum, decFull[0] == expectedSum)

	// With Rescale
	ctVsq2, _ := evalFull.MulRelinNew(ctV, ctV)
	if err := evalFull.Rescale(ctVsq2, ctVsq2); err != nil {
		fmt.Printf("  Rescale error: %v\n", err)
	} else {
		for step := 1; step < slots; step <<= 1 {
			rotated, _ := evalFull.RotateColumnsNew(ctVsq2, step)
			evalFull.Add(ctVsq2, rotated, ctVsq2)
		}
		decFull2 := make([]uint64, slots)
		ecd.Decode(dec.DecryptNew(ctVsq2), decFull2)
		fmt.Printf("  With Rescale:    slot0=%d expected=%d PASS=%v\n", decFull2[0], expectedSum, decFull2[0] == expectedSum)
	}

	// With heterogeneous values
	fmt.Println()
	fmt.Printf("=== Heterogeneous: slots=%d, v_i = 100 + i%%401, MulRelin + RotAS ===\n", slots)
	hetVec := make([]uint64, slots)
	for i := range slots {
		hetVec[i] = 100 + uint64(i)%401
	}
	expectedHet := uint64(0)
	for _, vv := range hetVec {
		expectedHet = (expectedHet + vv*vv%t) % t
	}
	ptHet := bgv.NewPlaintext(params, params.MaxLevel())
	ecd.Encode(hetVec, ptHet)
	ctHet, _ := enc.EncryptNew(ptHet)

	// Verify: decode ctHet and check a few slots match hetVec.
	decHetRaw := make([]uint64, slots)
	ecd.Decode(dec.DecryptNew(ctHet), decHetRaw)
	encodingOK := true
	for i := range 10 {
		if decHetRaw[i] != hetVec[i] {
			fmt.Printf("  ENCODING BUG at slot%d: got=%d want=%d\n", i, decHetRaw[i], hetVec[i])
			encodingOK = false
		}
	}
	if encodingOK {
		fmt.Println("  Encoding/decoding of hetVec: OK (first 10 slots match)")
	}

	ctHetSq, _ := evalFull.MulRelinNew(ctHet, ctHet)

	// Verify slot-by-slot after MulRelin (before RotAS).
	decHetSq := make([]uint64, slots)
	ecd.Decode(dec.DecryptNew(ctHetSq), decHetSq)
	mulrelinOK := true
	for i := range 10 {
		want := hetVec[i] * hetVec[i] % t
		if decHetSq[i] != want {
			fmt.Printf("  MULRELIN BUG at slot%d: got=%d want=%d (hetVec[i]=%d)\n", i, decHetSq[i], want, hetVec[i])
			mulrelinOK = false
		}
	}
	if mulrelinOK {
		fmt.Println("  MulRelin slot-by-slot (first 10): OK")
	}

	// Full RotAS.
	for step := 1; step < slots; step <<= 1 {
		rotated, _ := evalFull.RotateColumnsNew(ctHetSq, step)
		evalFull.Add(ctHetSq, rotated, ctHetSq)
	}
	decHet := make([]uint64, slots)
	ecd.Decode(dec.DecryptNew(ctHetSq), decHet)
	fmt.Printf("  After RotAS: slot0=%d expected=%d PASS=%v\n", decHet[0], expectedHet, decHet[0] == expectedHet)
	if decHet[0] != expectedHet {
		// Try to understand: is the expected wrong or is the circuit wrong?
		// Check if slot0 == 2*expectedHet or slot0 == expectedHet/2 etc.
		fmt.Printf("  Debug: 2*expected=%d  expected/2=%d\n",
			(2*expectedHet)%t, expectedHet/2)
	}
}
