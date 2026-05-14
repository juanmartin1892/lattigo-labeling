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

// Package main demonstrates the complete N-of-N MHE protocol using Lattigo v6.1.1's
// multiparty package with BGV parameters.
//
// Protocol phases:
//  1. Setup: each party generates its individual secret key.
//  2. Collective public key generation (PublicKeyGenProtocol).
//  3. Independent encryption: P1 encrypts 7, P2 encrypts 3.
//  4. Homomorphic evaluation: evaluator adds the two ciphertexts.
//  5. Collective key-switching to sk=0 (KeySwitchProtocol).
//  6. Local decryption and verification: result must equal 10.
//
// Run with:
//
//	go run ./examples/multiparty_basic/
package main

import (
	"fmt"
	"log"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// BGV parameters for this example.
//
// LogN=14: 2^14 polynomial degree, giving 8192 slots.
// LogQ=[56,55,55,54,54,54]: 6-level modulus chain, consistent with existing examples/.
// LogP=[55,55]: auxiliary moduli required for key-switching noise flooding.
// PlaintextModulus=0x101 (257): small prime chosen to keep values readable.
var paramsLiteral = bgv.ParametersLiteral{
	LogN:             14,
	LogQ:             []int{56, 55, 55, 54, 54, 54},
	LogP:             []int{55, 55},
	PlaintextModulus: 0x101, // 257
}

// fixedCRSSeed is shared by all parties to derive the same Common Reference String.
var fixedCRSSeed = []byte("multiparty-basic-example-crs-v1")

func main() {
	// -------------------------------------------------------------------------
	// Phase 1 — Parameter setup
	// -------------------------------------------------------------------------
	fmt.Println("=== Phase 1: Parameter setup ===")
	params, err := bgv.NewParametersFromLiteral(paramsLiteral)
	if err != nil {
		log.Fatalf("bgv.NewParametersFromLiteral: %v", err)
	}
	fmt.Printf("  LogN=%d  slots=%d  PlaintextModulus=%d\n", params.LogN(), params.MaxSlots(), params.PlaintextModulus())

	// -------------------------------------------------------------------------
	// Phase 2 — Collective public key generation
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 2: Collective key generation ===")

	nParties := 2
	kgen := rlwe.NewKeyGenerator(params)

	skShares := make([]*rlwe.SecretKey, nParties)
	skIdeal := rlwe.NewSecretKey(params)
	for i := range skShares {
		skShares[i] = kgen.GenSecretKeyNew()
		// ideal sk = sk1 + sk2 + … + skN (mod q)
		params.RingQP().Add(skIdeal.Value, skShares[i].Value, skIdeal.Value)
		fmt.Printf("  P%d: secret key share generated\n", i+1)
	}

	// All parties share a common CRS derived from the same seed.
	crs, err := sampling.NewKeyedPRNG(fixedCRSSeed)
	if err != nil {
		log.Fatalf("NewKeyedPRNG: %v", err)
	}

	// Run PublicKeyGenProtocol.
	ckgProtos := make([]multiparty.PublicKeyGenProtocol, nParties)
	ckgProtos[0] = multiparty.NewPublicKeyGenProtocol(params)
	for i := 1; i < nParties; i++ {
		ckgProtos[i] = ckgProtos[0].ShallowCopy()
	}
	crpPK := ckgProtos[0].SampleCRP(crs)

	pkShares := make([]multiparty.PublicKeyGenShare, nParties)
	for i := range pkShares {
		pkShares[i] = ckgProtos[i].AllocateShare()
		ckgProtos[i].GenShare(skShares[i], crpPK, &pkShares[i])
		fmt.Printf("  P%d: public key share generated\n", i+1)
	}
	for i := 1; i < nParties; i++ {
		ckgProtos[0].AggregateShares(pkShares[0], pkShares[i], &pkShares[0])
	}
	collectivePK := rlwe.NewPublicKey(params)
	ckgProtos[0].GenPublicKey(pkShares[0], crpPK, collectivePK)
	fmt.Println("  Collective public key generated.")

	// -------------------------------------------------------------------------
	// Phase 3 — Independent encryption
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 3: Encryption ===")

	encoder := bgv.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, collectivePK)

	val1, val2 := uint64(7), uint64(3)

	fillSlots := func(v uint64) []uint64 {
		s := make([]uint64, params.MaxSlots())
		for i := range s {
			s[i] = v
		}
		return s
	}

	pt1 := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(fillSlots(val1), pt1); err != nil {
		log.Fatalf("Encode P1: %v", err)
	}
	ct1, err := enc.EncryptNew(pt1)
	if err != nil {
		log.Fatalf("EncryptNew P1: %v", err)
	}
	fmt.Printf("  P1 encrypted: %d\n", val1)

	pt2 := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(fillSlots(val2), pt2); err != nil {
		log.Fatalf("Encode P2: %v", err)
	}
	ct2, err := enc.EncryptNew(pt2)
	if err != nil {
		log.Fatalf("EncryptNew P2: %v", err)
	}
	fmt.Printf("  P2 encrypted: %d\n", val2)

	// -------------------------------------------------------------------------
	// Phase 4 — Homomorphic evaluation (addition)
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 4: Homomorphic evaluation ===")

	eval := bgv.NewEvaluator(params, nil) // no eval keys needed for Add
	ctSum, err := eval.AddNew(ct1, ct2)
	if err != nil {
		log.Fatalf("AddNew: %v", err)
	}
	fmt.Printf("  Evaluator computed: Enc(%d) + Enc(%d) = Enc(?)\n", val1, val2)

	// -------------------------------------------------------------------------
	// Phase 5 — Collective key-switching to sk=0 (threshold decryption)
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 5: Collective key-switching (threshold decryption) ===")

	// Smudging noise masks individual sk*c1 contributions from other parties.
	sigmaSmudging := 8.0 * rlwe.DefaultNoise
	cksProto, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{
		Sigma: sigmaSmudging,
		Bound: 6 * sigmaSmudging,
	})
	if err != nil {
		log.Fatalf("NewKeySwitchProtocol: %v", err)
	}

	// zeroSK is the destination key (sk' = 0); decryption with it reads c0 directly.
	zeroSK := rlwe.NewSecretKey(params)
	cksShares := make([]multiparty.KeySwitchShare, nParties)
	for i := range cksShares {
		cksShares[i] = cksProto.AllocateShare(ctSum.Level())
		cksProto.GenShare(skShares[i], zeroSK, ctSum, &cksShares[i])
		fmt.Printf("  P%d: decryption share generated\n", i+1)
	}
	for i := 1; i < nParties; i++ {
		if err := cksProto.AggregateShares(cksShares[0], cksShares[i], &cksShares[0]); err != nil {
			log.Fatalf("AggregateShares: %v", err)
		}
	}
	ctSwitched := rlwe.NewCiphertext(params, ctSum.Degree(), ctSum.Level())
	cksProto.KeySwitch(ctSum, cksShares[0], ctSwitched)
	fmt.Println("  Combined decryption share applied.")

	// -------------------------------------------------------------------------
	// Phase 6 — Local decryption and verification
	// -------------------------------------------------------------------------
	fmt.Println("\n=== Phase 6: Decryption and verification ===")

	ptResult := rlwe.NewDecryptor(params, zeroSK).DecryptNew(ctSwitched)
	result := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(ptResult, result); err != nil {
		log.Fatalf("Decode: %v", err)
	}

	expected := (val1 + val2) % params.PlaintextModulus()
	fmt.Printf("  Decrypted result (slot 0): %d\n", result[0])
	fmt.Printf("  Expected:                  %d\n", expected)

	allCorrect := true
	for i, v := range result {
		if v != expected {
			fmt.Printf("  ERROR slot %d: got %d, want %d\n", i, v, expected)
			allCorrect = false
			break
		}
	}
	if allCorrect {
		fmt.Printf("\n  All %d slots correct: %d + %d = %d (mod %d)\n",
			params.MaxSlots(), val1, val2, expected, params.PlaintextModulus())
		fmt.Println("\nMHE round-trip PASSED.")
	} else {
		log.Fatal("MHE round-trip FAILED.")
	}
}
