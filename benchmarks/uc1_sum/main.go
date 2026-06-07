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

// Package main benchmarks UC1 (summation) comparing two variants:
//
//   - std:   MHE without labeling — standard BGV encryption + HAdd +
//     collective key-switch-to-zero decryption (Lattigo mhe primitives).
//   - label: MHE with labeling (CF construction) — EncryptLabeled + SumLabeled +
//     threshold decryption via DecryptThresholdLabeled.
//
// Protocol: each of the two parties computes its local sum in plaintext
// (s_j = Σ x_{ij}), encrypts the scalar, the evaluator adds the two ciphertexts,
// and the result is threshold-decrypted. Profundidad multiplicativa: 0.
//
// Results are written to a CSV file (default: results/uc1_sum.csv).
//
// Run with:
//
//	go run ./benchmarks/uc1_sum/ [-out path] [-reps n]
package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"

	"github.com/juanmartin1892/lattigo-labeling/benchmarks/internal/harness"
	"github.com/juanmartin1892/lattigo-labeling/labeling"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	nParties         = 2
	datasetSeed      = int64(42)
)

var (
	crsSeed = []byte("uc1-benchmark-crs-seed-v1")
	logQ    = []int{56, 55, 55, 54}
	logP    = []int{55, 55}
)

type dbConfig struct {
	label string
	n     int
}

var dbs = []dbConfig{
	{"DB1", 512},
	{"DB2", 100_000},
	{"DB3", 1_000_000},
}

func main() {
	out := flag.String("out", "results/uc1_sum.csv", "output CSV path")
	reps := flag.Int("reps", 10, "repetitions per variant per DB size")
	flag.Parse()

	params, err := labeling.NewParametersFromLiteral(logN, logQ, logP, plaintextModulus)
	if err != nil {
		log.Fatalf("NewParametersFromLiteral: %v", err)
	}

	var allRuns []harness.BenchmarkRun

	for _, db := range dbs {
		ds := harness.GenerateDataset(db.n, datasetSeed, plaintextModulus)
		fmt.Printf("=== %s (N=%d) ===\n", db.label, db.n)

		for rep := 1; rep <= *reps; rep++ {
			for _, variant := range []string{"std", "label"} {
				run := runVariant(variant, params, ds, db.label, rep)
				allRuns = append(allRuns, run)
				fmt.Printf("  variant=%-6s rep=%2d correct=%-5v total=%7.1fms\n",
					variant, rep, run.Correct, run.TotalMs())
			}
		}
	}

	if err := harness.AppendCSV(*out, allRuns); err != nil {
		log.Fatalf("AppendCSV: %v", err)
	}
	fmt.Printf("\nResults written to %s\n", filepath.Clean(*out))
}

func runVariant(
	variant string,
	params labeling.Parameters,
	ds harness.Dataset,
	dbLabel string,
	repID int,
) harness.BenchmarkRun {
	run := harness.BenchmarkRun{
		UseCase: "UC1",
		Variant: variant,
		DBLabel: dbLabel,
		N:       ds.N,
		RunID:   repID,
	}

	// precomp: each party computes its local sum in plaintext.
	// Party 0 takes ⌈N/2⌉ values, party 1 takes ⌊N/2⌋.
	var localSums [nParties]uint64
	run.Phases = append(run.Phases, harness.Run("precomp", func() {
		cut := ds.N/2 + ds.N%2
		for _, v := range ds.Values[:cut] {
			localSums[0] = (localSums[0] + v) % ds.PlaintextModulus
		}
		for _, v := range ds.Values[cut:] {
			localSums[1] = (localSums[1] + v) % ds.PlaintextModulus
		}
	}))

	var hePhases []harness.PhaseResult
	switch variant {
	case "std":
		hePhases, run.CommBytes, run.Rounds, run.Correct = runStd(params, localSums, ds.ExpectedSum)
	case "label":
		hePhases, run.CommBytes, run.Rounds, run.Correct = runLabel(params, localSums, ds.ExpectedSum)
	default:
		log.Fatalf("unknown variant %q", variant)
	}
	run.Phases = append(run.Phases, hePhases...)
	return run
}

// smudgingNoise returns the discrete Gaussian distribution used for CKS smudging,
// matching the parameters in the labeling package (σ = 8·DefaultNoise).
func smudgingNoise() ring.DiscreteGaussian {
	const sigma = 8 * rlwe.DefaultNoise
	return ring.DiscreteGaussian{Sigma: sigma, Bound: 6 * sigma}
}

// shareSize returns the theoretical serialized size in bytes of one KeySwitchShare
// at the given ciphertext level: two ring polynomials of N coefficients each, with
// (level+1) CRT limbs of 8 bytes each.
func shareSize(params labeling.Parameters, level int) int64 {
	return int64(2 * (1 << params.LogN()) * (level + 1) * 8)
}

// encodeScalar encodes a single uint64 value into slot 0 of a BGV plaintext
// (all other slots are zero).
func encodeScalar(encoder *bgv.Encoder, params labeling.Parameters, v uint64) *rlwe.Plaintext {
	slots := make([]uint64, params.MaxSlots())
	slots[0] = v
	pt := bgv.NewPlaintext(params.Parameters, params.MaxLevel())
	if err := encoder.Encode(slots, pt); err != nil {
		log.Fatalf("Encode: %v", err)
	}
	return pt
}

// runStd benchmarks the std variant: BGV encryption + HAdd + CKS-to-zero decryption.
func runStd(
	params labeling.Parameters,
	localSums [nParties]uint64,
	expected uint64,
) (phases []harness.PhaseResult, commBytes int64, rounds int, correct bool) {
	bgvParams := params.Parameters

	var skShares [nParties]*rlwe.SecretKey
	var pk *rlwe.PublicKey

	phases = append(phases, harness.Run("setup", func() {
		kgen := rlwe.NewKeyGenerator(bgvParams)
		for i := range skShares {
			skShares[i] = kgen.GenSecretKeyNew()
		}
		crs, err := sampling.NewKeyedPRNG(crsSeed)
		if err != nil {
			log.Fatalf("NewKeyedPRNG: %v", err)
		}
		// Use NewMHEContext to generate collective public key, consistent with label variant.
		ctx, err := labeling.NewMHEContext(params, skShares[:], crs)
		if err != nil {
			log.Fatalf("NewMHEContext: %v", err)
		}
		pk = ctx.CollectivePK
	}))

	var cts [nParties]*rlwe.Ciphertext
	phases = append(phases, harness.Run("encrypt", func() {
		encoder := bgv.NewEncoder(bgvParams)
		encryptor := rlwe.NewEncryptor(bgvParams, pk)
		for p := 0; p < nParties; p++ {
			pt := encodeScalar(encoder, params, localSums[p])
			ct, err := encryptor.EncryptNew(pt)
			if err != nil {
				log.Fatalf("EncryptNew party %d: %v", p, err)
			}
			cts[p] = ct
		}
	}))

	var ctSum *rlwe.Ciphertext
	phases = append(phases, harness.Run("eval", func() {
		eval := bgv.NewEvaluator(bgvParams, nil)
		var err error
		ctSum, err = eval.AddNew(cts[0], cts[1])
		if err != nil {
			log.Fatalf("AddNew: %v", err)
		}
	}))

	var result uint64
	phases = append(phases, harness.Run("decrypt", func() {
		sigmaSmudging := 8.0 * rlwe.DefaultNoise
		cksProto, err := multiparty.NewKeySwitchProtocol(bgvParams, ring.DiscreteGaussian{
			Sigma: sigmaSmudging,
			Bound: 6 * sigmaSmudging,
		})
		if err != nil {
			log.Fatalf("NewKeySwitchProtocol: %v", err)
		}
		zeroSK := rlwe.NewSecretKey(bgvParams)
		cksShares := make([]multiparty.KeySwitchShare, nParties)
		for i, sk := range skShares {
			cksShares[i] = cksProto.AllocateShare(ctSum.Level())
			cksProto.GenShare(sk, zeroSK, ctSum, &cksShares[i])
			commBytes += shareSize(params, ctSum.Level())
		}
		for i := 1; i < nParties; i++ {
			if err := cksProto.AggregateShares(cksShares[0], cksShares[i], &cksShares[0]); err != nil {
				log.Fatalf("AggregateShares: %v", err)
			}
		}
		ctSwitched := rlwe.NewCiphertext(bgvParams, ctSum.Degree(), ctSum.Level())
		cksProto.KeySwitch(ctSum, cksShares[0], ctSwitched)

		dec := rlwe.NewDecryptor(bgvParams, zeroSK)
		ptResult := dec.DecryptNew(ctSwitched)
		decoded := make([]uint64, bgvParams.MaxSlots())
		if err := bgv.NewEncoder(bgvParams).Decode(ptResult, decoded); err != nil {
			log.Fatalf("Decode: %v", err)
		}
		result = decoded[0]
	}))

	return phases, commBytes, 1, result == expected
}

// runLabel benchmarks the label variant: EncryptLabeled + SumLabeled + threshold decrypt.
func runLabel(
	params labeling.Parameters,
	localSums [nParties]uint64,
	expected uint64,
) (phases []harness.PhaseResult, commBytes int64, rounds int, correct bool) {
	var skShares [nParties]*rlwe.SecretKey
	var ctx labeling.MHEContext

	phases = append(phases, harness.Run("setup", func() {
		kgen := rlwe.NewKeyGenerator(params.Parameters)
		for i := range skShares {
			skShares[i] = kgen.GenSecretKeyNew()
		}
		crs, err := sampling.NewKeyedPRNG(crsSeed)
		if err != nil {
			log.Fatalf("NewKeyedPRNG: %v", err)
		}
		ctx, err = labeling.NewMHEContext(params, skShares[:], crs)
		if err != nil {
			log.Fatalf("NewMHEContext: %v", err)
		}
	}))

	var lcts [nParties]labeling.PlaintextLabeledciphertext
	phases = append(phases, harness.Run("encrypt", func() {
		for p := 0; p < nParties; p++ {
			values := make([]uint64, params.MaxSlots())
			values[0] = localSums[p]
			lct, err := labeling.EncryptLabeled(ctx, values)
			if err != nil {
				log.Fatalf("EncryptLabeled party %d: %v", p, err)
			}
			lcts[p] = lct
		}
	}))

	var lctSum labeling.PlaintextLabeledciphertext
	phases = append(phases, harness.Run("eval", func() {
		var err error
		lctSum, err = labeling.SumLabeled(ctx, lcts[0], lcts[1])
		if err != nil {
			log.Fatalf("SumLabeled: %v", err)
		}
	}))

	var result uint64
	phases = append(phases, harness.Run("decrypt", func() {
		decShares := make([]labeling.LabeledDecryptionShare, nParties)
		for i, sk := range skShares {
			var err error
			decShares[i], err = labeling.GenLabeledDecryptionShare(ctx, sk, lctSum)
			if err != nil {
				log.Fatalf("GenLabeledDecryptionShare party %d: %v", i, err)
			}
			commBytes += shareSize(params, decShares[i].Value.Level())
		}
		combined, err := labeling.AggregateLabeledDecryptionShares(ctx, decShares)
		if err != nil {
			log.Fatalf("AggregateLabeledDecryptionShares: %v", err)
		}
		decoded, err := labeling.DecryptThresholdLabeled(ctx, combined, lctSum)
		if err != nil {
			log.Fatalf("DecryptThresholdLabeled: %v", err)
		}
		result = decoded[0]
	}))

	return phases, commBytes, 1, result == expected
}
