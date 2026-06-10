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

// Package main benchmarks UC4 (variance with β compaction) comparing two variants:
//
//   - std:           standard BGV MHE without labeling (same as UC3 std).
//   - label_compact: CF labeling with compact self-product decryption — eliminates
//     the collective rlk and avoids the β explosion by running the
//     rotate-and-sum tree only on α, then reconstructing the β²
//     contribution in plaintext.
//
// The compact protocol (spec 011):
//
//  1. Save β_orig = CopyBeta(lct) before multiplication.
//  2. clctSq = MultOverflowLabeledFree(lct, lct)  — no rlk, depth-0 inner BGV.
//  3. clctAlpha = CompactRotateAndSumAlpha(clctSq, rotOffsets, evk)
//     — accumulates α without growing β (no β explosion).
//  4. Decrypt sum_sq per block: GenCompactSelfProductShare + Aggregate +
//     DecryptThresholdCompact  — 2 CKS shares per block instead of 2^L.
//  5. Decrypt sum per block: standard SumLabeled + GenLabeledDecryptionShare.
//
// Three security parameter profiles are benchmarked (same as UC2/UC3):
//
//	"full"  — both variants correct.
//	"tight" — verify empirically if label_compact fails (β_orig at MaxLevel vs
//	          level=1 may change the noise threshold vs UC3).
//	"min"   — both variants expected to fail.
//
// Results are written to a CSV file (default: results/uc4_variance_compact.csv).
//
// Run with:
//
//	go run ./benchmarks/uc4_variance_compact/ [-out path] [-reps n]
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
	blockSize        = 8192
	nParties         = 2
	datasetSeed      = int64(42)
)

var crsSeed = []byte("uc4-variance-compact-crs-seed-v1")

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

var profiles = []paramProfile{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
	{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
	{"min", []int{35, 35}, []int{35, 35}},
}

func main() {
	out := flag.String("out", "results/uc4_variance_compact.csv", "output CSV path")
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
			expSum, expSumSq := expectedSumAndSumSq(ds)
			fmt.Printf("=== profile=%s  DB=%s  N=%d  sum=%d  sum_sq=%d ===\n",
				profile.name, db.label, db.n, expSum, expSumSq)

			for rep := 1; rep <= *reps; rep++ {
				for _, variant := range []string{"std", "label_compact", "label_compact_max", "label_compact_mb"} {
					run := runVariant(variant, params, ds, db.label, rep, profile.name)
					allRuns = append(allRuns, run)
					fmt.Printf("  variant=%-14s rep=%2d correct=%-5v total=%7.1fms\n",
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

func expectedSumAndSumSq(ds harness.Dataset) (sum, sumSq uint64) {
	t := ds.PlaintextModulus
	for _, v := range ds.Values {
		sum = (sum + v) % t
		sumSq = (sumSq + v*v%t) % t
	}
	return
}

// blocks partitions values into K zero-padded slices of length maxSlots.
// Data fills slots [0, half) where half = maxSlots/2 = blockSize.
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

// rotationOffsets returns the log₂(blockSize) rotation steps for the
// rotate-and-sum tree: blockSize/2, blockSize/4, ..., 1.
func rotationOffsets() []int {
	var offsets []int
	for step := blockSize / 2; step >= 1; step /= 2 {
		offsets = append(offsets, step)
	}
	return offsets
}

func rotationGaloisEls(params labeling.Parameters) []uint64 {
	var galEls []uint64
	for step := blockSize / 2; step >= 1; step /= 2 {
		galEls = append(galEls, params.GaloisElementForColRotation(step))
	}
	return galEls
}

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

func shareSize(params labeling.Parameters, level int) int64 {
	return int64(2 * (1 << params.LogN()) * (level + 1) * 8)
}

func runVariant(
	variant string,
	params labeling.Parameters,
	ds harness.Dataset,
	dbLabel string,
	repID int,
	profile string,
) harness.BenchmarkRun {
	run := harness.BenchmarkRun{
		UseCase:      "UC4",
		Variant:      variant,
		DBLabel:      dbLabel,
		N:            ds.N,
		RunID:        repID,
		ParamProfile: profile,
	}
	expSum, expSumSq := expectedSumAndSumSq(ds)

	var phases []harness.PhaseResult
	switch variant {
	case "std":
		phases, run.CommBytes, run.Rounds, run.Correct = runStd(params, ds, expSum, expSumSq)
	case "label_compact":
		phases, run.CommBytes, run.Rounds, run.Correct = runLabelCompact(params, ds, expSum, expSumSq, false, nil)
	case "label_compact_max":
		phases, run.CommBytes, run.Rounds, run.Correct = runLabelCompact(params, ds, expSum, expSumSq, true, nil)
	case "label_compact_mb":
		encFn := func(ctx labeling.MHEContext, blk []uint64) (labeling.PlaintextLabeledciphertext, error) {
			return labeling.EncryptLabeledWithMaskBound(ctx, blk, minValInBlock(blk))
		}
		phases, run.CommBytes, run.Rounds, run.Correct = runLabelCompact(params, ds, expSum, expSumSq, false, encFn)
	default:
		log.Fatalf("unknown variant %q", variant)
	}
	run.Phases = phases
	return run
}

// runStd is identical to UC3 runStd: BGV encrypt + auto-HMul rotate-and-sum (sum_sq)
// + HAdd rotate-and-sum (sum) + two CKS-to-zero threshold decrypts.
func runStd(
	params labeling.Parameters,
	ds harness.Dataset,
	expSum, expSumSq uint64,
) (phases []harness.PhaseResult, commBytes int64, rounds int, correct bool) {
	bgvParams := params.Parameters
	M := ds.N / 2
	v1 := ds.Values[:M]
	v2 := ds.Values[M : 2*M]

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

	maxSlots := params.MaxSlots()
	blks1 := blocks(v1, maxSlots)
	blks2 := blocks(v2, maxSlots)

	phases = append(phases, harness.Run("precomp", func() {
		_ = blks1
		_ = blks2
	}))

	cts1 := make([]*rlwe.Ciphertext, len(blks1))
	cts2 := make([]*rlwe.Ciphertext, len(blks2))
	phases = append(phases, harness.Run("encrypt", func() {
		encoder := bgv.NewEncoder(bgvParams)
		encryptor := rlwe.NewEncryptor(bgvParams, pk)
		for b := range blks1 {
			pt := bgv.NewPlaintext(bgvParams, bgvParams.MaxLevel())
			if err := encoder.Encode(blks1[b], pt); err != nil {
				log.Fatalf("Encode blk1[%d]: %v", b, err)
			}
			ct, err := encryptor.EncryptNew(pt)
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

	var ctSumSq, ctSum *rlwe.Ciphertext
	phases = append(phases, harness.Run("eval", func() {
		eval := bgv.NewEvaluator(bgvParams, evk)
		ctSumSq, ctSum = nil, nil

		for b := range blks1 {
			for _, ct := range []*rlwe.Ciphertext{cts1[b], cts2[b]} {
				ctSq, err := eval.MulRelinNew(ct, ct)
				if err != nil {
					log.Fatalf("MulRelinNew blk %d: %v", b, err)
				}
				for step := blockSize / 2; step >= 1; step /= 2 {
					ctRot, err := eval.RotateColumnsNew(ctSq, step)
					if err != nil {
						log.Fatalf("RotateColumnsNew sq step=%d: %v", step, err)
					}
					if err := eval.Add(ctSq, ctRot, ctSq); err != nil {
						log.Fatalf("Add sq step=%d: %v", step, err)
					}
				}
				if ctSumSq == nil {
					ctSumSq = ctSq
				} else {
					if err := eval.Add(ctSumSq, ctSq, ctSumSq); err != nil {
						log.Fatalf("Add sq acc: %v", err)
					}
				}
			}
		}

		for b := range blks1 {
			for _, ct := range []*rlwe.Ciphertext{cts1[b], cts2[b]} {
				ctS := ct
				for step := blockSize / 2; step >= 1; step /= 2 {
					ctRot, err := eval.RotateColumnsNew(ctS, step)
					if err != nil {
						log.Fatalf("RotateColumnsNew sum step=%d: %v", step, err)
					}
					if err := eval.Add(ctS, ctRot, ctS); err != nil {
						log.Fatalf("Add sum step=%d: %v", step, err)
					}
				}
				if ctSum == nil {
					ctSum = ctS
				} else {
					if err := eval.Add(ctSum, ctS, ctSum); err != nil {
						log.Fatalf("Add sum acc: %v", err)
					}
				}
			}
		}
	}))

	var decSumSq, decSum uint64
	phases = append(phases, harness.Run("decrypt", func() {
		decSumSq = stdCKSDecrypt(bgvParams, skShares[:], ctSumSq, params, &commBytes)
		decSum = stdCKSDecrypt(bgvParams, skShares[:], ctSum, params, &commBytes)
	}))
	return phases, commBytes, 1, decSumSq == expSumSq && decSum == expSum
}

func stdCKSDecrypt(
	bgvParams bgv.Parameters,
	skShares []*rlwe.SecretKey,
	ct *rlwe.Ciphertext,
	params labeling.Parameters,
	commBytes *int64,
) uint64 {
	sigmaSmudging := 8.0 * rlwe.DefaultNoise
	cksProto, err := multiparty.NewKeySwitchProtocol(bgvParams, ring.DiscreteGaussian{
		Sigma: sigmaSmudging,
		Bound: 6 * sigmaSmudging,
	})
	if err != nil {
		log.Fatalf("NewKeySwitchProtocol: %v", err)
	}
	zeroSK := rlwe.NewSecretKey(bgvParams)
	cksShares := make([]multiparty.KeySwitchShare, len(skShares))
	for i, sk := range skShares {
		cksShares[i] = cksProto.AllocateShare(ct.Level())
		cksProto.GenShare(sk, zeroSK, ct, &cksShares[i])
		*commBytes += shareSize(params, ct.Level())
	}
	for i := 1; i < len(skShares); i++ {
		if err := cksProto.AggregateShares(cksShares[0], cksShares[i], &cksShares[0]); err != nil {
			log.Fatalf("AggregateShares: %v", err)
		}
	}
	ctSwitched := rlwe.NewCiphertext(bgvParams, ct.Degree(), ct.Level())
	cksProto.KeySwitch(ct, cksShares[0], ctSwitched)

	ptResult := rlwe.NewDecryptor(bgvParams, zeroSK).DecryptNew(ctSwitched)
	decoded := make([]uint64, bgvParams.MaxSlots())
	if err := bgv.NewEncoder(bgvParams).Decode(ptResult, decoded); err != nil {
		log.Fatalf("Decode: %v", err)
	}
	return decoded[0]
}

// runLabelCompact benchmarks the UC4 label_compact variant:
//   - No GenCollectiveRelinKey in setup (rlk-free).
//   - sum_sq: MultOverflowLabeledFree + CompactRotateAndSumAlpha per block (no β explosion),
//     then DecryptThresholdCompact per block (2 CKS shares: α_final + β_orig).
//   - sum: SumLabeled rotate-and-sum + GenLabeledDecryptionShare (same as UC3).
//
// When keepLevel is true (the label_compact_max variant), the overflow multiply and the
// sum rotate-and-sum keep α/β at MaxLevel via the KeepLevel ops, so the compact threshold
// decrypt runs at the same level as the std baseline — the fixed-level honest comparison
// of spec 013. CompactRotateAndSumAlpha already preserves the α level.
// runLabelCompact runs the label_compact (or label_compact_max / label_compact_mb) variant.
// encryptFn overrides EncryptLabeled when non-nil (used by label_compact_mb to inject a
// custom mask bound). When nil, EncryptLabeled is used unchanged.
func runLabelCompact(
	params labeling.Parameters,
	ds harness.Dataset,
	expSum, expSumSq uint64,
	keepLevel bool,
	encryptFn func(labeling.MHEContext, []uint64) (labeling.PlaintextLabeledciphertext, error),
) (phases []harness.PhaseResult, commBytes int64, rounds int, correct bool) {
	if encryptFn == nil {
		encryptFn = func(ctx labeling.MHEContext, blk []uint64) (labeling.PlaintextLabeledciphertext, error) {
			return labeling.EncryptLabeled(ctx, blk)
		}
	}
	bgvParams := params.Parameters

	// Select the level-preserving ops for label_compact_max; both share the std signatures.
	multFn := labeling.MultOverflowLabeledFree
	sumFn := labeling.SumLabeled
	if keepLevel {
		multFn = labeling.MultOverflowLabeledFreeKeepLevel
		sumFn = labeling.SumLabeledKeepLevel
	}
	M := ds.N / 2
	v1 := ds.Values[:M]
	v2 := ds.Values[M : 2*M]

	var skShares [nParties]*rlwe.SecretKey
	var ctx labeling.MHEContext
	// No rlk: label_compact uses MultOverflowLabeledFree which needs no relinearization key.
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
		// No GenCollectiveRelinKey — MultOverflowLabeledFree is rlk-free.
		galEls := rotationGaloisEls(params)
		galKeys, err := genCollectiveGaloisKeys(bgvParams, skShares[:], crs, galEls)
		if err != nil {
			log.Fatalf("genCollectiveGaloisKeys: %v", err)
		}
		evk = labeling.GenerateMemEvaluationKeySetWithGalois(nil, galKeys...)
	}))

	maxSlots := params.MaxSlots()
	blks1 := blocks(v1, maxSlots)
	blks2 := blocks(v2, maxSlots)

	phases = append(phases, harness.Run("precomp", func() {
		_ = blks1
		_ = blks2
	}))

	lcts1 := make([]labeling.PlaintextLabeledciphertext, len(blks1))
	lcts2 := make([]labeling.PlaintextLabeledciphertext, len(blks2))
	phases = append(phases, harness.Run("encrypt", func() {
		for b := range blks1 {
			lct, err := encryptFn(ctx, blks1[b])
			if err != nil {
				log.Fatalf("encrypt blk1[%d]: %v", b, err)
			}
			lcts1[b] = lct

			lct2, err := encryptFn(ctx, blks2[b])
			if err != nil {
				log.Fatalf("encrypt blk2[%d]: %v", b, err)
			}
			lcts2[b] = lct2
		}
	}))

	rotOffsets := rotationOffsets()

	// Per-block results of CompactRotateAndSumAlpha and CopyBeta, held between
	// eval and decrypt phases. For DB3 this is ~124 blocks × 2 parties × 2 cts
	// at MaxLevel ≈ 1GB — feasible, avoids streaming decrypt into eval.
	type blockData struct {
		clctAlpha labeling.CiphertextLabeledciphertext
		betaOrig  *rlwe.Ciphertext
	}
	var allBlocks []blockData
	var lctSum *labeling.PlaintextLabeledciphertext

	phases = append(phases, harness.Run("eval", func() {
		allBlocks = allBlocks[:0]
		lctSum = nil

		for _, lcts := range [][]labeling.PlaintextLabeledciphertext{lcts1, lcts2} {
			for b := range lcts {
				lct := lcts[b]

				// sum_sq: save β_orig, run rlk-free multiply, compact α-only tree.
				// CompactRotateAndSumAlpha avoids the 2^L β explosion for blockSize=8192.
				betaOrig, err := labeling.CopyBeta(ctx, lct)
				if err != nil {
					log.Fatalf("CopyBeta blk %d: %v", b, err)
				}
				clctSq, err := multFn(ctx, lct, lct)
				if err != nil {
					log.Fatalf("MultOverflowLabeledFree blk %d: %v", b, err)
				}
				clctAlpha, err := labeling.CompactRotateAndSumAlpha(ctx, clctSq, rotOffsets, evk)
				if err != nil {
					log.Fatalf("CompactRotateAndSumAlpha blk %d: %v", b, err)
				}
				allBlocks = append(allBlocks, blockData{clctAlpha: clctAlpha, betaOrig: betaOrig})

				// sum: SumLabeled rotate-and-sum (no multiplication needed).
				lctS := lct
				for _, step := range rotOffsets {
					lctRot, err := labeling.RotateColumns(params, lctS, step, evk)
					if err != nil {
						log.Fatalf("RotateColumns sum step=%d blk %d: %v", step, b, err)
					}
					lctS, err = sumFn(ctx, lctS, lctRot)
					if err != nil {
						log.Fatalf("SumLabeled sum step=%d blk %d: %v", step, b, err)
					}
				}
				if lctSum == nil {
					tmp := lctS
					lctSum = &tmp
				} else {
					s, err := sumFn(ctx, *lctSum, lctS)
					if err != nil {
						log.Fatalf("SumLabeled acc blk %d: %v", b, err)
					}
					*lctSum = s
				}
			}
		}
	}))

	var sumSqResult uint64
	var decSum uint64
	phases = append(phases, harness.Run("decrypt", func() {
		sumSqResult = 0

		// Compact threshold decrypt per block: 2 CKS shares (α_final + β_orig).
		for _, bd := range allBlocks {
			decShares := make([]labeling.CompactSelfProductShare, nParties)
			for i, sk := range skShares {
				var err error
				decShares[i], err = labeling.GenCompactSelfProductShare(ctx, sk, bd.clctAlpha, bd.betaOrig)
				if err != nil {
					log.Fatalf("GenCompactSelfProductShare: %v", err)
				}
				commBytes += shareSize(params, labeling.AlphaLevel(bd.clctAlpha))
				commBytes += shareSize(params, bd.betaOrig.Level())
			}
			combined, err := labeling.AggregateCompactSelfProductShares(ctx, decShares)
			if err != nil {
				log.Fatalf("AggregateCompactSelfProductShares: %v", err)
			}
			result, err := labeling.DecryptThresholdCompact(ctx, combined, bd.clctAlpha, bd.betaOrig, rotOffsets)
			if err != nil {
				log.Fatalf("DecryptThresholdCompact: %v", err)
			}
			sumSqResult = (sumSqResult + result[0]) % plaintextModulus
		}

		// Threshold decrypt sum (standard labeled CKS).
		decSum = labelThresholdDecrypt(ctx, skShares[:], *lctSum, params, &commBytes)
	}))

	return phases, commBytes, 1, sumSqResult == expSumSq && decSum == expSum
}

// labelThresholdDecrypt performs GenLabeledDecryptionShare + Aggregate + Decrypt.
func labelThresholdDecrypt(
	ctx labeling.MHEContext,
	skShares []*rlwe.SecretKey,
	lct labeling.PlaintextLabeledciphertext,
	params labeling.Parameters,
	commBytes *int64,
) uint64 {
	decShares := make([]labeling.LabeledDecryptionShare, len(skShares))
	for i, sk := range skShares {
		var err error
		decShares[i], err = labeling.GenLabeledDecryptionShare(ctx, sk, lct)
		if err != nil {
			log.Fatalf("GenLabeledDecryptionShare: %v", err)
		}
		*commBytes += shareSize(params, decShares[i].Value.Level())
	}
	combined, err := labeling.AggregateLabeledDecryptionShares(ctx, decShares)
	if err != nil {
		log.Fatalf("AggregateLabeledDecryptionShares: %v", err)
	}
	decoded, err := labeling.DecryptThresholdLabeled(ctx, combined, lct)
	if err != nil {
		log.Fatalf("DecryptThresholdLabeled: %v", err)
	}
	return decoded[0]
}

// minValInBlock returns the smallest non-zero element in blk, ignoring padding zeros.
// Used to derive a safe maskBound for label_compact_mb (spec 014).
func minValInBlock(blk []uint64) uint64 {
	m := uint64(0)
	for _, v := range blk {
		if v > 0 && (m == 0 || v < m) {
			m = v
		}
	}
	if m == 0 {
		return 1
	}
	return m
}
