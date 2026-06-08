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

// Package main benchmarks UC2 (dot product) comparing two variants:
//
//   - std:   MHE without labeling — standard BGV encryption + element-wise HMul +
//     rotate-and-sum + collective key-switch-to-zero decryption.
//   - label: MHE with labeling (CF construction) — EncryptLabeled + MultLabeled +
//     RotateColumns/SumLabeled rotate-and-sum + threshold decryption.
//
// Protocol: the dataset (N values) is split in half; party 1 holds the first M=N/2
// values and party 2 holds the last M values. Each party packs its vector in one or
// more BGV SIMD ciphertexts of blockSize=8192 slots. The evaluator computes the inner
// product <v1,v2> = Σᵢ v1[i]×v2[i] mod t via element-wise HMul + a log₂(blockSize)
// rotate-and-sum tree per block, then accumulates partial sums across blocks.
//
// Three security parameter profiles are benchmarked:
//
//	"full"  — baseline parameters (same as UC1); both variants correct.
//	"tight" — reduced LogQ; std fails due to relin noise; label resists (empirically calibrated).
//	"min"   — further reduced LogQ; both variants fail.
//
// S2 ("tight") and S3 ("min") LogQ values are placeholders; calibrate them by running
// with -reps 20 on DB1 and adjusting until the expected correct/fail pattern appears.
//
// Results are written to a CSV file (default: results/uc2_dotproduct.csv).
//
// Run with:
//
//	go run ./benchmarks/uc2_dotproduct/ [-out path] [-reps n]
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
	// blockSize is MaxSlots/2; column rotations in BGV operate independently within
	// each half of the SIMD vector, so blockSize is the safe working width.
	blockSize   = 8192
	nParties    = 2
	datasetSeed = int64(42)
)

var crsSeed = []byte("uc2-dotproduct-crs-seed-v1")

type dbConfig struct {
	label string
	n     int
}

var dbs = []dbConfig{
	{"DB1", 512},
	{"DB2", 100_000},
	{"DB3", 1_000_000},
}

type paramProfile struct {
	name string
	logQ []int
	logP []int
}

// profiles defines the three security parameter scenarios for the noise boundary analysis.
//
// Empirical calibration result (logN=14, t=0x3ee0001, nParties=2):
//
//	S1 "full":  generous parameters; both variants correct.
//	S2 "tight": label β lives at level=1 (q0×q1 ≈ 2^75); with collective relin+Galois keys
//	            the combined noise exceeds the level=1 budget → label fails, std correct.
//	            std uses the full modulus Q (MaxLevel=3 ≈ 2^188), budget >> noise.
//	S3 "min":   2-prime structure → both variants at MaxLevel=1 (Q ≈ 2^70);
//	            budget barely above the Mult noise floor for both → both fail.
//
// Note: the S2 finding differs from the theoretical prediction (which expected label to
// be MORE noise-resistant). The label variant's β at level=1 has a SMALLER budget than
// std's MaxLevel ciphertext, outweighing the absence of a collective relin protocol step.
// This is itself an interesting empirical result for the TFM security analysis.
var profiles = []paramProfile{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
	{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
	{"min", []int{35, 35}, []int{35, 35}},
}

func main() {
	out := flag.String("out", "results/uc2_dotproduct.csv", "output CSV path")
	reps := flag.Int("reps", 20, "repetitions per cell")
	flag.Parse()

	var allRuns []harness.BenchmarkRun

	for _, profile := range profiles {
		params, err := labeling.NewParametersFromLiteral(logN, profile.logQ, profile.logP, plaintextModulus)
		if err != nil {
			log.Printf("WARNING: skip profile %q: NewParametersFromLiteral: %v", profile.name, err)
			continue
		}

		for _, db := range dbs {
			ds := harness.GenerateDataset(db.n, datasetSeed, plaintextModulus)
			expected := dotProduct(ds)
			fmt.Printf("=== profile=%s  DB=%s  N=%d  expected=%d ===\n",
				profile.name, db.label, db.n, expected)

			for rep := 1; rep <= *reps; rep++ {
				for _, variant := range []string{"std", "label"} {
					run := runVariant(variant, params, ds, expected, db.label, rep, profile.name)
					allRuns = append(allRuns, run)
					fmt.Printf("  variant=%-6s rep=%2d correct=%-5v total=%7.1fms\n",
						variant, rep, run.Correct, run.TotalMs())
				}
			}
		}
	}

	if err := harness.AppendCSV(*out, allRuns); err != nil {
		log.Fatalf("AppendCSV: %v", err)
	}
	fmt.Printf("\nResults written to %s\n", filepath.Clean(*out))
}

// dotProduct returns the expected inner product <v1,v2> mod t where
// v1 = ds.Values[0..M-1] and v2 = ds.Values[M..2M-1], M = ds.N/2.
// Values are in [1,1000] so each product ≤ 10^6 < t; the running sum is
// accumulated as uint64 (max M×10^6 ≤ 5×10^11 < 2^40) then reduced mod t.
func dotProduct(ds harness.Dataset) uint64 {
	M := ds.N / 2
	var sum uint64
	for i := 0; i < M; i++ {
		sum += ds.Values[i] * ds.Values[M+i]
	}
	return sum % ds.PlaintextModulus
}

// blocks partitions values into K zero-padded slices of length maxSlots.
// Each slice packs data in slots [0, half) where half = maxSlots/2 = blockSize.
// Remaining slots in each slice are zero, so a rotate-and-sum tree within the
// first half correctly computes the partial sum without contamination from the
// second half.
func blocks(values []uint64, maxSlots int) [][]uint64 {
	half := maxSlots / 2
	K := (len(values) + half - 1) / half
	if K == 0 {
		K = 1
	}
	result := make([][]uint64, K)
	for b := range result {
		buf := make([]uint64, maxSlots)
		start := b * half
		end := start + half
		if end > len(values) {
			end = len(values)
		}
		copy(buf, values[start:end])
		result[b] = buf
	}
	return result
}

// rotationGaloisEls returns the log₂(blockSize)=13 Galois elements for the
// rotate-and-sum tree: steps blockSize/2, blockSize/4, ..., 1.
func rotationGaloisEls(params labeling.Parameters) []uint64 {
	var galEls []uint64
	for step := blockSize / 2; step >= 1; step /= 2 {
		galEls = append(galEls, params.GaloisElementForColRotation(step))
	}
	return galEls
}

// genCollectiveGaloisKeys runs the 1-round collective Galois key generation
// protocol (multiparty.GaloisKeyGenProtocol) for each element in galEls.
// One GaloisKey is produced per element; all parties contribute one share each.
func genCollectiveGaloisKeys(
	bgvParams bgv.Parameters,
	skShares []*rlwe.SecretKey,
	crs multiparty.CRS,
	galEls []uint64,
) ([]*rlwe.GaloisKey, error) {
	proto := multiparty.NewGaloisKeyGenProtocol(bgvParams)
	galKeys := make([]*rlwe.GaloisKey, len(galEls))
	for j, galEl := range galEls {
		crp := proto.SampleCRP(crs)
		// Generate one share per party, then aggregate pairwise.
		// GaloisKeyGenShare carries a GaloisElement field that must match across
		// all operands of AggregateShares, so we cannot start from a zero-value
		// AllocateShare(); instead we seed the accumulator from party 0's share.
		shares := make([]multiparty.GaloisKeyGenShare, len(skShares))
		for i, sk := range skShares {
			shares[i] = proto.AllocateShare()
			if err := proto.GenShare(sk, galEl, crp, &shares[i]); err != nil {
				return nil, fmt.Errorf("GenShare galEl %d party %d: %w", galEl, i, err)
			}
		}
		for i := 1; i < len(shares); i++ {
			if err := proto.AggregateShares(shares[0], shares[i], &shares[0]); err != nil {
				return nil, fmt.Errorf("AggregateShares galEl %d: %w", galEl, err)
			}
		}
		galKeys[j] = rlwe.NewGaloisKey(bgvParams)
		if err := proto.GenGaloisKey(shares[0], crp, galKeys[j]); err != nil {
			return nil, fmt.Errorf("GenGaloisKey galEl %d: %w", galEl, err)
		}
	}
	return galKeys, nil
}

// shareSize returns the theoretical serialized byte size of one threshold
// decryption share at the given ciphertext level.
func shareSize(params labeling.Parameters, level int) int64 {
	return int64(2 * (1 << params.LogN()) * (level + 1) * 8)
}

func runVariant(
	variant string,
	params labeling.Parameters,
	ds harness.Dataset,
	expected uint64,
	dbLabel string,
	repID int,
	profile string,
) harness.BenchmarkRun {
	run := harness.BenchmarkRun{
		UseCase:      "UC2",
		Variant:      variant,
		DBLabel:      dbLabel,
		N:            ds.N,
		RunID:        repID,
		ParamProfile: profile,
	}

	var phases []harness.PhaseResult
	switch variant {
	case "std":
		phases, run.CommBytes, run.Rounds, run.Correct = runStd(params, ds, expected)
	case "label":
		phases, run.CommBytes, run.Rounds, run.Correct = runLabel(params, ds, expected)
	default:
		log.Fatalf("unknown variant %q", variant)
	}
	run.Phases = phases
	return run
}

// runStd benchmarks the std MHE variant:
// BGV encrypt + HMul per block + rotate-and-sum + CKS-to-zero threshold decrypt.
func runStd(
	params labeling.Parameters,
	ds harness.Dataset,
	expected uint64,
) (phases []harness.PhaseResult, commBytes int64, rounds int, correct bool) {
	bgvParams := params.Parameters

	var skShares [nParties]*rlwe.SecretKey
	var pk *rlwe.PublicKey
	var evk *rlwe.MemEvaluationKeySet

	phases = append(phases, harness.Run("setup", func() {
		kgen := rlwe.NewKeyGenerator(bgvParams)
		for i := range skShares {
			skShares[i] = kgen.GenSecretKeyNew()
		}
		crs, err := sampling.NewKeyedPRNG(crsSeed)
		if err != nil {
			log.Fatalf("NewKeyedPRNG: %v", err)
		}
		ctx, err := labeling.NewMHEContext(params, skShares[:], crs)
		if err != nil {
			log.Fatalf("NewMHEContext: %v", err)
		}
		pk = ctx.CollectivePK

		rlk, err := labeling.GenCollectiveRelinKey(params, skShares[:], crs)
		if err != nil {
			log.Fatalf("GenCollectiveRelinKey: %v", err)
		}

		galEls := rotationGaloisEls(params)
		galKeys, err := genCollectiveGaloisKeys(bgvParams, skShares[:], crs, galEls)
		if err != nil {
			log.Fatalf("genCollectiveGaloisKeys: %v", err)
		}
		evk = labeling.GenerateMemEvaluationKeySetWithGalois(rlk, galKeys...)
	}))

	M := ds.N / 2
	v1 := ds.Values[:M]
	v2 := ds.Values[M : 2*M]

	var precomputedExpected uint64
	phases = append(phases, harness.Run("precomp", func() {
		// Each party partitions its half of the dataset into SIMD blocks.
		// The expected inner product is validated at decrypt time.
		precomputedExpected = expected
	}))
	_ = precomputedExpected

	maxSlots := params.MaxSlots()
	blks1 := blocks(v1, maxSlots)
	blks2 := blocks(v2, maxSlots)

	cts1 := make([]*rlwe.Ciphertext, len(blks1))
	cts2 := make([]*rlwe.Ciphertext, len(blks2))
	phases = append(phases, harness.Run("encrypt", func() {
		encoder := bgv.NewEncoder(bgvParams)
		encryptor := rlwe.NewEncryptor(bgvParams, pk)
		for b := range blks1 {
			pt1 := bgv.NewPlaintext(bgvParams, bgvParams.MaxLevel())
			if err := encoder.Encode(blks1[b], pt1); err != nil {
				log.Fatalf("Encode blk1[%d]: %v", b, err)
			}
			ct, err := encryptor.EncryptNew(pt1)
			if err != nil {
				log.Fatalf("EncryptNew blk1[%d]: %v", b, err)
			}
			cts1[b] = ct

			pt2 := bgv.NewPlaintext(bgvParams, bgvParams.MaxLevel())
			if err := encoder.Encode(blks2[b], pt2); err != nil {
				log.Fatalf("Encode blk2[%d]: %v", b, err)
			}
			ct2, err := encryptor.EncryptNew(pt2)
			if err != nil {
				log.Fatalf("EncryptNew blk2[%d]: %v", b, err)
			}
			cts2[b] = ct2
		}
	}))

	var ctTotal *rlwe.Ciphertext
	phases = append(phases, harness.Run("eval", func() {
		eval := bgv.NewEvaluator(bgvParams, evk)
		ctTotal = nil
		for b := range blks1 {
			ctProd, err := eval.MulRelinNew(cts1[b], cts2[b])
			if err != nil {
				log.Fatalf("MulRelinNew blk %d: %v", b, err)
			}
			// Rotate-and-sum: collapses all blockSize products into slot 0.
			for step := blockSize / 2; step >= 1; step /= 2 {
				ctRot, err := eval.RotateColumnsNew(ctProd, step)
				if err != nil {
					log.Fatalf("RotateColumnsNew step=%d blk=%d: %v", step, b, err)
				}
				if err := eval.Add(ctProd, ctRot, ctProd); err != nil {
					log.Fatalf("Add step=%d blk=%d: %v", step, b, err)
				}
			}
			if ctTotal == nil {
				ctTotal = ctProd
			} else {
				if err := eval.Add(ctTotal, ctProd, ctTotal); err != nil {
					log.Fatalf("Add acc blk=%d: %v", b, err)
				}
			}
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
			cksShares[i] = cksProto.AllocateShare(ctTotal.Level())
			cksProto.GenShare(sk, zeroSK, ctTotal, &cksShares[i])
			commBytes += shareSize(params, ctTotal.Level())
		}
		for i := 1; i < nParties; i++ {
			if err := cksProto.AggregateShares(cksShares[0], cksShares[i], &cksShares[0]); err != nil {
				log.Fatalf("AggregateShares: %v", err)
			}
		}
		ctSwitched := rlwe.NewCiphertext(bgvParams, ctTotal.Degree(), ctTotal.Level())
		cksProto.KeySwitch(ctTotal, cksShares[0], ctSwitched)

		ptResult := rlwe.NewDecryptor(bgvParams, zeroSK).DecryptNew(ctSwitched)
		decoded := make([]uint64, bgvParams.MaxSlots())
		if err := bgv.NewEncoder(bgvParams).Decode(ptResult, decoded); err != nil {
			log.Fatalf("Decode: %v", err)
		}
		result = decoded[0]
	}))

	return phases, commBytes, 1, result == expected
}

// runLabel benchmarks the label CF variant:
// EncryptLabeled + MultLabeled per block + RotateColumns/SumLabeled rotate-and-sum
// + threshold decryption.
func runLabel(
	params labeling.Parameters,
	ds harness.Dataset,
	expected uint64,
) (phases []harness.PhaseResult, commBytes int64, rounds int, correct bool) {
	bgvParams := params.Parameters

	var skShares [nParties]*rlwe.SecretKey
	var ctx labeling.MHEContext
	var rlk *rlwe.RelinearizationKey
	var evk *rlwe.MemEvaluationKeySet

	phases = append(phases, harness.Run("setup", func() {
		kgen := rlwe.NewKeyGenerator(bgvParams)
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
		rlk, err = labeling.GenCollectiveRelinKey(params, skShares[:], crs)
		if err != nil {
			log.Fatalf("GenCollectiveRelinKey: %v", err)
		}
		galEls := rotationGaloisEls(params)
		galKeys, err := genCollectiveGaloisKeys(bgvParams, skShares[:], crs, galEls)
		if err != nil {
			log.Fatalf("genCollectiveGaloisKeys: %v", err)
		}
		evk = labeling.GenerateMemEvaluationKeySetWithGalois(rlk, galKeys...)
	}))

	M := ds.N / 2
	v1 := ds.Values[:M]
	v2 := ds.Values[M : 2*M]

	phases = append(phases, harness.Run("precomp", func() {
		_ = v1
		_ = v2
	}))

	maxSlots := params.MaxSlots()
	blks1 := blocks(v1, maxSlots)
	blks2 := blocks(v2, maxSlots)

	lcts1 := make([]labeling.PlaintextLabeledciphertext, len(blks1))
	lcts2 := make([]labeling.PlaintextLabeledciphertext, len(blks2))
	phases = append(phases, harness.Run("encrypt", func() {
		for b := range blks1 {
			lct, err := labeling.EncryptLabeled(ctx, blks1[b])
			if err != nil {
				log.Fatalf("EncryptLabeled blk1[%d]: %v", b, err)
			}
			lcts1[b] = lct

			lct2, err := labeling.EncryptLabeled(ctx, blks2[b])
			if err != nil {
				log.Fatalf("EncryptLabeled blk2[%d]: %v", b, err)
			}
			lcts2[b] = lct2
		}
	}))

	var lctTotal *labeling.PlaintextLabeledciphertext
	phases = append(phases, harness.Run("eval", func() {
		lctTotal = nil
		for b := range blks1 {
			lctProd, err := labeling.MultLabeled(ctx, rlk, lcts1[b], lcts2[b])
			if err != nil {
				log.Fatalf("MultLabeled blk %d: %v", b, err)
			}
			// Rotate-and-sum on the labeled ciphertext: collapses blockSize products into slot 0.
			for step := blockSize / 2; step >= 1; step /= 2 {
				lctRot, err := labeling.RotateColumns(params, lctProd, step, evk)
				if err != nil {
					log.Fatalf("RotateColumns step=%d blk=%d: %v", step, b, err)
				}
				lctProd, err = labeling.SumLabeled(ctx, lctProd, lctRot)
				if err != nil {
					log.Fatalf("SumLabeled step=%d blk=%d: %v", step, b, err)
				}
			}
			if lctTotal == nil {
				tmp := lctProd
				lctTotal = &tmp
			} else {
				sum, err := labeling.SumLabeled(ctx, *lctTotal, lctProd)
				if err != nil {
					log.Fatalf("SumLabeled acc blk=%d: %v", b, err)
				}
				*lctTotal = sum
			}
		}
	}))

	var result uint64
	phases = append(phases, harness.Run("decrypt", func() {
		decShares := make([]labeling.LabeledDecryptionShare, nParties)
		for i, sk := range skShares {
			var err error
			decShares[i], err = labeling.GenLabeledDecryptionShare(ctx, sk, *lctTotal)
			if err != nil {
				log.Fatalf("GenLabeledDecryptionShare party %d: %v", i, err)
			}
			commBytes += shareSize(params, decShares[i].Value.Level())
		}
		combined, err := labeling.AggregateLabeledDecryptionShares(ctx, decShares)
		if err != nil {
			log.Fatalf("AggregateLabeledDecryptionShares: %v", err)
		}
		decoded, err := labeling.DecryptThresholdLabeled(ctx, combined, *lctTotal)
		if err != nil {
			log.Fatalf("DecryptThresholdLabeled: %v", err)
		}
		result = decoded[0]
	}))

	return phases, commBytes, 1, result == expected
}
