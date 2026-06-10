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

// Package main is a minimal demonstration of MultOverflowLabeledFree (depth-0 CF
// labeling without a relinearization key) followed by a rotate-and-sum tree.
//
// # Purpose
//
// UC2 and UC3 use MultLabeled (with collective RLK) + SumLabeled for accumulation.
// SumLabeled keeps β at size 1 throughout the tree. MultOverflowLabeledFree skips
// relinearization, leaving β = [β₁, β₂] after multiplication. Each subsequent
// SumOverflowCiphertextLabeled doubles the β array (β is concatenated, not merged).
// After L rotate-and-sum steps β has 2^(L+1) elements — the "β explosion".
//
// For blockSize=8192 (L=13 steps) the explosion reaches 2^14 = 16 384 ciphertexts
// per block, which is impractical. This demo uses blockSize=8 (L=3 steps, 16 β
// elements) to show that the mechanism is mathematically correct without exhausting
// memory. The fix for production use is the β compaction of UC4 (spec 011).
//
// # β count growth
//
//	After step 1: 2^2  =   4 β per block
//	After step 2: 2^3  =   8 β per block
//	After step 3: 2^4  =  16 β per block  ← this demo stops here
//	...
//	After step 13: 2^14 = 16384 β per block  ← blockSize=8192, OOM
//
// Run with:
//
//	go run ./benchmarks/overflow_demo/
package main

import (
	"fmt"
	"log"

	"github.com/juanmartin1892/lattigo-labeling/labeling"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	// blockSize=8 → L=3 rotation steps → 2^4=16 β elements at most.
	// With MaxLevel ciphertexts (~4 MB each) that is 64 MB per block — feasible.
	demoBlockSize = 8
	nParties      = 2
)

var crsSeed = []byte("overflow-demo-crs-seed-v1")

// logQ for a 4-prime "full" profile (same as UC2/UC3 S1).
var logQ = []int{56, 55, 55, 54}
var logP = []int{55, 55}

func main() {
	params, err := labeling.NewParametersFromLiteral(logN, logQ, logP, plaintextModulus)
	if err != nil {
		log.Fatalf("NewParametersFromLiteral: %v", err)
	}

	// ── Key generation ──────────────────────────────────────────────────────────
	bgvParams := params.Parameters
	kgen := rlwe.NewKeyGenerator(bgvParams)
	skShares := make([]*rlwe.SecretKey, nParties)
	for i := range skShares {
		skShares[i] = kgen.GenSecretKeyNew()
	}

	crs, err := sampling.NewKeyedPRNG(crsSeed)
	if err != nil {
		log.Fatalf("NewKeyedPRNG: %v", err)
	}

	ctx, err := labeling.NewMHEContext(params, skShares, crs)
	if err != nil {
		log.Fatalf("NewMHEContext: %v", err)
	}

	// No GenCollectiveRelinKey: MultOverflowLabeledFree does not need it.
	fmt.Println("setup: CKG done, no RKG needed (MultOverflowLabeledFree is rlk-free)")

	// Galois keys for the L=3 rotation steps: 4, 2, 1.
	var galEls []uint64
	for step := demoBlockSize / 2; step >= 1; step /= 2 {
		galEls = append(galEls, params.GaloisElementForColRotation(step))
	}
	proto := multiparty.NewGaloisKeyGenProtocol(bgvParams)
	galKeys := make([]*rlwe.GaloisKey, len(galEls))
	for j, galEl := range galEls {
		crp := proto.SampleCRP(crs)
		shares := make([]multiparty.GaloisKeyGenShare, nParties)
		for i, sk := range skShares {
			shares[i] = proto.AllocateShare()
			if err := proto.GenShare(sk, galEl, crp, &shares[i]); err != nil {
				log.Fatalf("GenShare galEl %d: %v", galEl, err)
			}
		}
		for i := 1; i < nParties; i++ {
			if err := proto.AggregateShares(shares[0], shares[i], &shares[0]); err != nil {
				log.Fatalf("AggregateShares galEl %d: %v", galEl, err)
			}
		}
		galKeys[j] = rlwe.NewGaloisKey(bgvParams)
		if err := proto.GenGaloisKey(shares[0], crp, galKeys[j]); err != nil {
			log.Fatalf("GenGaloisKey galEl %d: %v", galEl, err)
		}
	}
	evk := labeling.GenerateMemEvaluationKeySetWithGalois(nil, galKeys...)
	fmt.Printf("setup: %d Galois keys generated (steps: 4, 2, 1)\n", len(galEls))

	// ── Dataset: 8 values in [1, 10] ────────────────────────────────────────────
	// Party 1 holds v1, party 2 holds v2. Inner product = Σ v1[i]×v2[i].
	v1 := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	v2 := []uint64{8, 7, 6, 5, 4, 3, 2, 1}
	expectedDot := uint64(0)
	for i := range v1 {
		expectedDot = (expectedDot + v1[i]*v2[i]) % plaintextModulus
	}
	expectedSelfSq := uint64(0) // Σ v1[i]² (self-product demo)
	for _, x := range v1 {
		expectedSelfSq = (expectedSelfSq + x*x) % plaintextModulus
	}

	// Pad to maxSlots (BGV requires full-length input for encoding).
	maxSlots := params.MaxSlots()
	pad := func(v []uint64) []uint64 {
		buf := make([]uint64, maxSlots)
		copy(buf, v)
		return buf
	}

	// ── Encrypt ──────────────────────────────────────────────────────────────────
	lct1, err := labeling.EncryptLabeled(ctx, pad(v1))
	if err != nil {
		log.Fatalf("EncryptLabeled v1: %v", err)
	}
	lct2, err := labeling.EncryptLabeled(ctx, pad(v2))
	if err != nil {
		log.Fatalf("EncryptLabeled v2: %v", err)
	}
	fmt.Println("encrypt: done (PlaintextLabeledciphertext, β has 1 element each)")

	// ── Demo 1: cross-product dot (v1 · v2) ──────────────────────────────────────
	fmt.Println("\n── Demo 1: dot product v1·v2 via MultOverflowLabeledFree ──")
	clctDot, err := labeling.MultOverflowLabeledFree(ctx, lct1, lct2)
	if err != nil {
		log.Fatalf("MultOverflowLabeledFree: %v", err)
	}
	fmt.Printf("  after MultOverflow: β count = %d (was 1 each, now [β₁,β₂])\n", betaCount(clctDot))

	for step := demoBlockSize / 2; step >= 1; step /= 2 {
		clctRot, err := labeling.RotateColumnsOverflow(params, clctDot, step, evk)
		if err != nil {
			log.Fatalf("RotateColumnsOverflow step=%d: %v", step, err)
		}
		clctDot, err = labeling.SumOverflowCiphertextLabeled(ctx, clctDot, clctRot)
		if err != nil {
			log.Fatalf("SumOverflowCiphertextLabeled step=%d: %v", step, err)
		}
		fmt.Printf("  after step=%d: β count = %d\n", step, betaCount(clctDot))
	}

	dotResult := overflowDecrypt(ctx, skShares, clctDot)
	fmt.Printf("  result=%d  expected=%d  correct=%v\n", dotResult, expectedDot, dotResult == expectedDot)

	// ── Demo 2: self-product sum of squares (Σ v1[i]²) ──────────────────────────
	fmt.Println("\n── Demo 2: self-product Σv1[i]² via MultOverflowLabeledFree ──")
	clctSelfSq, err := labeling.MultOverflowLabeledFree(ctx, lct1, lct1)
	if err != nil {
		log.Fatalf("MultOverflowLabeledFree self: %v", err)
	}
	fmt.Printf("  after MultOverflow: β count = %d\n", betaCount(clctSelfSq))

	for step := demoBlockSize / 2; step >= 1; step /= 2 {
		clctRot, err := labeling.RotateColumnsOverflow(params, clctSelfSq, step, evk)
		if err != nil {
			log.Fatalf("RotateColumnsOverflow step=%d: %v", step, err)
		}
		clctSelfSq, err = labeling.SumOverflowCiphertextLabeled(ctx, clctSelfSq, clctRot)
		if err != nil {
			log.Fatalf("SumOverflowCiphertextLabeled step=%d: %v", step, err)
		}
		fmt.Printf("  after step=%d: β count = %d\n", step, betaCount(clctSelfSq))
	}

	selfSqResult := overflowDecrypt(ctx, skShares, clctSelfSq)
	fmt.Printf("  result=%d  expected=%d  correct=%v\n", selfSqResult, expectedSelfSq, selfSqResult == expectedSelfSq)

	// ── Summary ──────────────────────────────────────────────────────────────────
	fmt.Println("\n── Summary ──")
	fmt.Println("  MultOverflowLabeledFree: no rlk required, depth-0 BGV on α")
	fmt.Printf("  β after L=%d steps: 2^(L+1) = %d elements (manageable for blockSize=%d)\n",
		3, 1<<4, demoBlockSize)
	fmt.Printf("  β after L=%d steps: 2^(L+1) = %d elements (OOM for blockSize=8192)\n",
		13, 1<<14)
	fmt.Println("  → UC4 (spec 011) solves this with β compaction: decrypt β_orig once,")
	fmt.Println("    reconstruct sum-of-squares in plaintext (no β explosion).")
}

// betaCount delegates to the library method for observability.
func betaCount(clct labeling.CiphertextLabeledciphertext) int {
	return clct.BetaCount()
}

// overflowDecrypt performs a 2-party threshold decryption of clct and returns slot 0.
func overflowDecrypt(ctx labeling.MHEContext, skShares []*rlwe.SecretKey, clct labeling.CiphertextLabeledciphertext) uint64 {
	shares := make([]labeling.OverflowDecryptionShare, len(skShares))
	for i, sk := range skShares {
		var err error
		shares[i], err = labeling.GenOverflowDecryptionShare(ctx, sk, clct)
		if err != nil {
			log.Fatalf("GenOverflowDecryptionShare: %v", err)
		}
	}
	combined, err := labeling.AggregateOverflowDecryptionShares(ctx, shares)
	if err != nil {
		log.Fatalf("AggregateOverflowDecryptionShares: %v", err)
	}
	decoded, err := labeling.DecryptThresholdOverflow(ctx, combined, clct)
	if err != nil {
		log.Fatalf("DecryptThresholdOverflow: %v", err)
	}
	return decoded[0]
}
