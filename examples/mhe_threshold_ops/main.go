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

// Package main demonstrates homomorphic operations over labeled ciphertexts
// in a 2-party MHE setting, using SumLabeled and MultLabeled followed by
// threshold decryption — specs 002, 003 and 004.
//
// Protocol phases:
//  1. Setup: N=2 parties generate secret key shares; MHEContext builds the
//     collective public key; GenCollectiveRelinKey produces the collective
//     relinearization key, without assembling the ideal secret key.
//  2. Encrypt: each party encrypts its own value with EncryptLabeled.
//  3. Evaluate: the evaluator (holding no secrets) computes SumLabeled and
//     MultLabeled over the labeled ciphertexts.
//  4. Threshold decrypt: parties collaborate via GenLabeledDecryptionShare +
//     AggregateLabeledDecryptionShares + DecryptThresholdLabeled to recover
//     each result.
//
// Run with:
//
//	go run ./examples/mhe_threshold_ops/
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
var fixedCRSSeed = []byte("mhe-ops-example-crs-seed-v1")

// fixedRLKSeed is shared by all parties for the collective relinearization key.
var fixedRLKSeed = []byte("mhe-ops-example-rlk-seed-v1")

// fillSlots returns a []uint64 of length params.MaxSlots() with all elements set to v.
func fillSlots(params labeling.Parameters, v uint64) []uint64 {
	s := make([]uint64, params.MaxSlots())
	for i := range s {
		s[i] = v
	}
	return s
}

// thresholdDecrypt runs the full N-party threshold decryption protocol on lct and returns
// the recovered plaintext slice.
func thresholdDecrypt(ctx labeling.MHEContext, skShares []*rlwe.SecretKey, lct labeling.PlaintextLabeledciphertext) []uint64 {
	shares := make([]labeling.LabeledDecryptionShare, len(skShares))
	var err error
	for i, sk := range skShares {
		shares[i], err = labeling.GenLabeledDecryptionShare(ctx, sk, lct)
		if err != nil {
			log.Fatalf("GenLabeledDecryptionShare P%d: %v", i+1, err)
		}
	}
	combined, err := labeling.AggregateLabeledDecryptionShares(ctx, shares)
	if err != nil {
		log.Fatalf("AggregateLabeledDecryptionShares: %v", err)
	}
	result, err := labeling.DecryptThresholdLabeled(ctx, combined, lct)
	if err != nil {
		log.Fatalf("DecryptThresholdLabeled: %v", err)
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

	const val1, val2 = uint64(3), uint64(4)

	lct1, err := labeling.EncryptLabeled(ctx, fillSlots(params, val1))
	if err != nil {
		log.Fatalf("EncryptLabeled P1: %v", err)
	}
	fmt.Printf("  P1 encrypted: %d\n", val1)

	lct2, err := labeling.EncryptLabeled(ctx, fillSlots(params, val2))
	if err != nil {
		log.Fatalf("EncryptLabeled P2: %v", err)
	}
	fmt.Printf("  P2 encrypted: %d\n", val2)

	// -------------------------------------------------------------------------
	// Phase 3 — Homomorphic evaluation (no secret key needed)
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 3: Homomorphic evaluation ===")

	lctSum, err := labeling.SumLabeled(ctx, lct1, lct2)
	if err != nil {
		log.Fatalf("SumLabeled: %v", err)
	}
	fmt.Printf("  SumLabeled(Enc(%d), Enc(%d)) computed\n", val1, val2)

	lctMult, err := labeling.MultLabeled(ctx, rlk, lct1, lct2)
	if err != nil {
		log.Fatalf("MultLabeled: %v", err)
	}
	fmt.Printf("  MultLabeled(Enc(%d), Enc(%d)) computed\n", val1, val2)

	// -------------------------------------------------------------------------
	// Phase 4 — Threshold decryption and verification
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 4: Threshold decryption ===")

	resultSum := thresholdDecrypt(ctx, skShares, lctSum)
	checkSlots(fmt.Sprintf("SumLabeled(%d+%d)", val1, val2), resultSum, val1+val2)

	resultMult := thresholdDecrypt(ctx, skShares, lctMult)
	checkSlots(fmt.Sprintf("MultLabeled(%d×%d)", val1, val2), resultMult, val1*val2)

	fmt.Println("\nMHE threshold ops round-trip PASSED.")
}
