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

// Package main demonstrates the minimal N-of-N MHE labeling round-trip using
// the labeling API from specs 002 and 003.
//
// Protocol phases:
//  1. Setup: N=2 parties generate secret key shares; MHEContext builds the
//     collective public key without assembling the ideal secret key.
//  2. Encrypt: evaluator encrypts a value under the collective public key
//     using EncryptLabeled.
//  3. Share: each party generates its decryption share with GenLabeledDecryptionShare.
//  4. Aggregate: AggregateLabeledDecryptionShares combines all shares.
//  5. Decrypt: DecryptThresholdLabeled recovers the plaintext — no party
//     ever holds the ideal secret key.
//
// Run with:
//
//	go run ./examples/mhe_threshold_basic/
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

// fixedCRSSeed is shared by all parties to derive the same Common Reference String.
var fixedCRSSeed = []byte("mhe-basic-example-crs-seed-v1")

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

	// Each party generates its secret key share. No party holds the ideal secret key.
	nParties := 2
	kgen := rlwe.NewKeyGenerator(params)
	skShares := make([]*rlwe.SecretKey, nParties)
	for i := range skShares {
		skShares[i] = kgen.GenSecretKeyNew()
		fmt.Printf("  P%d: secret key share generated\n", i+1)
	}

	// All parties derive the same Common Reference String (CRS) from the fixed seed.
	crs, err := sampling.NewKeyedPRNG(fixedCRSSeed)
	if err != nil {
		log.Fatalf("NewKeyedPRNG: %v", err)
	}

	// MHEContext derives the collective public key from the secret key shares and CRS.
	ctx, err := labeling.NewMHEContext(params, skShares, crs)
	if err != nil {
		log.Fatalf("NewMHEContext: %v", err)
	}
	fmt.Println("  Collective public key generated. No party holds the ideal secret key.")

	// -------------------------------------------------------------------------
	// Phase 2 — Labeled encryption
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 2: Labeled encryption ===")

	const value = uint64(7)
	plainValues := make([]uint64, params.MaxSlots())
	for i := range plainValues {
		plainValues[i] = value
	}

	lct, err := labeling.EncryptLabeled(ctx, plainValues)
	if err != nil {
		log.Fatalf("EncryptLabeled: %v", err)
	}
	fmt.Printf("  Evaluator encrypted: [%d, %d, …] (%d slots)\n", value, value, params.MaxSlots())

	// -------------------------------------------------------------------------
	// Phase 3 — Decryption share generation
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 3: Decryption share generation ===")

	decShares := make([]labeling.LabeledDecryptionShare, nParties)
	for i, sk := range skShares {
		decShares[i], err = labeling.GenLabeledDecryptionShare(ctx, sk, lct)
		if err != nil {
			log.Fatalf("P%d GenLabeledDecryptionShare: %v", i+1, err)
		}
		fmt.Printf("  P%d: decryption share generated\n", i+1)
	}

	// -------------------------------------------------------------------------
	// Phase 4 — Share aggregation
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 4: Share aggregation ===")

	combined, err := labeling.AggregateLabeledDecryptionShares(ctx, decShares)
	if err != nil {
		log.Fatalf("AggregateLabeledDecryptionShares: %v", err)
	}
	fmt.Println("  Combined decryption share ready.")

	// -------------------------------------------------------------------------
	// Phase 5 — Threshold decryption and verification
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 5: Threshold decryption ===")

	result, err := labeling.DecryptThresholdLabeled(ctx, combined, lct)
	if err != nil {
		log.Fatalf("DecryptThresholdLabeled: %v", err)
	}

	allCorrect := true
	for i, v := range result {
		if v != value {
			fmt.Printf("  ERROR slot %d: got %d, want %d\n", i, v, value)
			allCorrect = false
		}
	}
	if !allCorrect {
		log.Fatal("Round-trip FAILED.")
	}
	fmt.Printf("  All %d slots correct: DecryptThreshold(EncryptLabeled(%d)) = %d\n",
		params.MaxSlots(), value, value)

	fmt.Println("\nMHE threshold basic round-trip PASSED.")
}
