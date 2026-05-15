// Copyright 2025 Juan Martín Pérez
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main demonstrates overflow homomorphic operations over labeled
// ciphertexts in a 2-party MHE setting, followed by threshold decryption
// of the resulting CiphertextLabeledciphertext — specs 002, 003, 004, 005
// and 006.
//
// Protocol phases:
//  1. Setup: N=2 parties generate secret key shares; MHEContext builds the
//     collective public key; GenCollectiveRelinKey produces the collective
//     relinearization key.
//  2. Encrypt: each party encrypts its own value with EncryptLabeled.
//  3. Overflow evaluate: the evaluator computes MultOverflowLabeled,
//     SumOverflowLabeled, and SumOverflowCiphertextLabeled, producing
//     CiphertextLabeledciphertext results whose α component is a ciphertext.
//  4. Threshold overflow decrypt: parties collaborate via
//     GenOverflowDecryptionShare + AggregateOverflowDecryptionShares +
//     DecryptThresholdOverflow to recover each result without assembling
//     the ideal secret key.
//
// Run with:
//
//	go run ./examples/mhe_threshold_overflow/
package main

import (
	"fmt"
	"log"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"

	"github.com/juanmartin1892/lattigo-labeling/labeling"
)

// BGV parameters for this example.
//
// LogN=14: 2^14 polynomial degree, 8192 slots.
// LogQ=[56,55,55,54,54,54]: 6-level modulus chain.
// LogP=[55,55]: auxiliary moduli for key-switching noise flooding.
// PlaintextModulus=0x3ee0001: consistent with single-party examples.
var (
	logN             = 14
	logQ             = []int{56, 55, 55, 54, 54, 54}
	logP             = []int{55, 55}
	plaintextModulus = uint64(0x3ee0001)
)

// fixedCRSSeed is shared by all parties for the collective public key.
var fixedCRSSeed = []byte("mhe-overflow-example-crs-seed-v1")

// fixedRLKSeed is shared by all parties for the collective relinearization key.
var fixedRLKSeed = []byte("mhe-overflow-example-rlk-seed-v1")

// fillSlots returns a []uint64 of length params.MaxSlots() with all elements set to v.
func fillSlots(params labeling.Parameters, v uint64) []uint64 {
	s := make([]uint64, params.MaxSlots())
	for i := range s {
		s[i] = v
	}
	return s
}

// thresholdDecryptOverflow runs the full N-party threshold decryption protocol for a
// CiphertextLabeledciphertext and returns the recovered plaintext slice.
func thresholdDecryptOverflow(ctx labeling.MHEContext, skShares []*rlwe.SecretKey, clct labeling.CiphertextLabeledciphertext) []uint64 {
	shares := make([]labeling.OverflowDecryptionShare, len(skShares))
	var err error
	for i, sk := range skShares {
		shares[i], err = labeling.GenOverflowDecryptionShare(ctx, sk, clct)
		if err != nil {
			log.Fatalf("GenOverflowDecryptionShare P%d: %v", i+1, err)
		}
	}
	combined, err := labeling.AggregateOverflowDecryptionShares(ctx, shares)
	if err != nil {
		log.Fatalf("AggregateOverflowDecryptionShares: %v", err)
	}
	result, err := labeling.DecryptThresholdOverflow(ctx, combined, clct)
	if err != nil {
		log.Fatalf("DecryptThresholdOverflow: %v", err)
	}
	return result
}

// checkSlots verifies that every element of result equals expected; calls log.Fatal if not.
func checkSlots(label string, result []uint64, expected uint64) {
	for i, v := range result {
		if v != expected {
			log.Fatalf("%s: slot %d: got %d, want %d", label, i, v, expected)
		}
	}
	fmt.Printf("  [OK] %s: all %d slots = %d\n", label, len(result), expected)
}

func main() {
	// -------------------------------------------------------------------------
	// Phase 1 — Parameter setup and collective context
	// -------------------------------------------------------------------------
	fmt.Println("=== Phase 1: Parameter setup ===")

	params, err := labeling.NewParametersFromLiteral(logN, logQ, logP, plaintextModulus)
	if err != nil {
		log.Fatalf("NewParametersFromLiteral: %v", err)
	}
	fmt.Printf("  LogN=%d  slots=%d  PlaintextModulus=0x%x\n",
		params.LogN(), params.MaxSlots(), params.PlaintextModulus())

	nParties := 2
	kgen := rlwe.NewKeyGenerator(params)
	skShares := make([]*rlwe.SecretKey, nParties)
	for i := range skShares {
		skShares[i] = kgen.GenSecretKeyNew()
		fmt.Printf("  P%d: secret key share generated\n", i+1)
	}

	crs, err := sampling.NewKeyedPRNG(fixedCRSSeed)
	if err != nil {
		log.Fatalf("NewKeyedPRNG (CKG): %v", err)
	}
	ctx, err := labeling.NewMHEContext(params, skShares, crs)
	if err != nil {
		log.Fatalf("NewMHEContext: %v", err)
	}
	fmt.Println("  Collective public key generated.")

	rlkCRS, err := sampling.NewKeyedPRNG(fixedRLKSeed)
	if err != nil {
		log.Fatalf("NewKeyedPRNG (RLK): %v", err)
	}
	rlk, err := labeling.GenCollectiveRelinKey(params, skShares, rlkCRS)
	if err != nil {
		log.Fatalf("GenCollectiveRelinKey: %v", err)
	}
	fmt.Println("  Collective relinearization key generated.")

	// -------------------------------------------------------------------------
	// Phase 2 — Labeled encryption (each party encrypts its own value)
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 2: Labeled encryption ===")

	// lct1=3, lct2=4, lct3=5, lct4=2 (used in SumOverflowCiphertext demo)
	const val1, val2, val3, val4 = uint64(3), uint64(4), uint64(5), uint64(2)

	lct1, err := labeling.EncryptLabeled(ctx, fillSlots(params, val1))
	if err != nil {
		log.Fatalf("EncryptLabeled val1: %v", err)
	}
	lct2, err := labeling.EncryptLabeled(ctx, fillSlots(params, val2))
	if err != nil {
		log.Fatalf("EncryptLabeled val2: %v", err)
	}
	lct3, err := labeling.EncryptLabeled(ctx, fillSlots(params, val3))
	if err != nil {
		log.Fatalf("EncryptLabeled val3: %v", err)
	}
	lct4, err := labeling.EncryptLabeled(ctx, fillSlots(params, val4))
	if err != nil {
		log.Fatalf("EncryptLabeled val4: %v", err)
	}
	fmt.Printf("  Encrypted: %d, %d, %d, %d\n", val1, val2, val3, val4)

	// -------------------------------------------------------------------------
	// Phase 3 — Overflow homomorphic evaluation
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 3: Overflow homomorphic evaluation ===")

	// MultOverflowLabeled(lct1, lct2) → CiphertextLabeledciphertext: α=Enc(3×4-r), β=[[...]]
	clctMult, err := labeling.MultOverflowLabeled(ctx, rlk, lct1, lct2)
	if err != nil {
		log.Fatalf("MultOverflowLabeled: %v", err)
	}
	fmt.Printf("  MultOverflowLabeled(Enc(%d), Enc(%d)) computed\n", val1, val2)

	// SumOverflowLabeled(clctMult, lct3) → extends the overflow result by adding lct3
	clctSum, err := labeling.SumOverflowLabeled(ctx, clctMult, lct3)
	if err != nil {
		log.Fatalf("SumOverflowLabeled: %v", err)
	}
	fmt.Printf("  SumOverflowLabeled(clct, Enc(%d)) computed\n", val3)

	// Second mult for SumOverflowCiphertextLabeled: MultOverflowLabeled(lct4, lct2) → Enc(2×5)... wait
	// We want: SumOverflowCiphertextLabeled(Mult(3,4), Mult(2,5)) → 12+10=22
	lct5, err := labeling.EncryptLabeled(ctx, fillSlots(params, val3)) // val3=5
	if err != nil {
		log.Fatalf("EncryptLabeled val5: %v", err)
	}
	clctMult2, err := labeling.MultOverflowLabeled(ctx, rlk, lct4, lct5)
	if err != nil {
		log.Fatalf("MultOverflowLabeled (2×5): %v", err)
	}
	fmt.Printf("  MultOverflowLabeled(Enc(%d), Enc(%d)) computed\n", val4, val3)

	clctSumOfMults, err := labeling.SumOverflowCiphertextLabeled(ctx, clctMult, clctMult2)
	if err != nil {
		log.Fatalf("SumOverflowCiphertextLabeled: %v", err)
	}
	fmt.Printf("  SumOverflowCiphertextLabeled(Mult(%d,%d), Mult(%d,%d)) computed\n", val1, val2, val4, val3)

	// -------------------------------------------------------------------------
	// Phase 4 — Threshold overflow decryption and verification
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 4: Threshold overflow decryption ===")

	// Decrypt MultOverflowLabeled(3, 4) → 12
	resultMult := thresholdDecryptOverflow(ctx, skShares, clctMult)
	checkSlots(fmt.Sprintf("MultOverflowLabeled(%d×%d)", val1, val2), resultMult, val1*val2)

	// Decrypt SumOverflowLabeled(Mult(3,4), 5) → 17
	resultSum := thresholdDecryptOverflow(ctx, skShares, clctSum)
	checkSlots(fmt.Sprintf("SumOverflowLabeled(Mult(%d,%d)+%d)", val1, val2, val3), resultSum, val1*val2+val3)

	// Decrypt SumOverflowCiphertextLabeled(Mult(3,4), Mult(2,5)) → 22
	resultSumOfMults := thresholdDecryptOverflow(ctx, skShares, clctSumOfMults)
	checkSlots(
		fmt.Sprintf("SumOverflowCiphertext(Mult(%d,%d)+Mult(%d,%d))", val1, val2, val4, val3),
		resultSumOfMults, val1*val2+val4*val3,
	)

	fmt.Println("\nMHE threshold overflow round-trip PASSED.")
}
