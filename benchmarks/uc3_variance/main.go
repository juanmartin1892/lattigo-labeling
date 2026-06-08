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

// Package main benchmarks UC3 (variance) comparing three variants:
//
//   - std:       MHE without labeling — standard BGV encryption + auto-HMul for sum_sq
//     + HAdd rotate-and-sum for sum + collective CKS-to-zero decryption at MaxLevel.
//   - std_modsw: identical to std, but rescales both results to level=1 before the CKS
//     threshold decrypt (spec 012). This matches label's share size, isolating whether
//     label's −50% communication is intrinsic to CF or an artifact of the decrypt level.
//   - label:     MHE with labeling (CF construction) — EncryptLabeled + auto-MultLabeled
//     for sum_sq + SumLabeled rotate-and-sum for sum + threshold decryption at level=1.
//
// Protocol: each of the two parties holds M=N/2 values. They encrypt their vectors
// once; the evaluator computes both:
//
//	sum_sq = Σxᵢ²  (depth 1: auto-product per party + accumulate)
//	sum    = Σxᵢ   (depth 0: rotate-and-sum per party + accumulate)
//
// The unnormalized variance N×sum_sq − sum² is computed in the clear by the
// aggregator after threshold decryption of both quantities.
//
// Three security parameter profiles are benchmarked (calibrated in spec 009):
//
//	"full"  — both variants correct.
//	"tight" — label fails (β at level=1 has insufficient budget with collective keys).
//	"min"   — both variants fail (Q too small for the BGV Mult noise floor).
//
// Results are written to a CSV file (default: results/uc3_variance.csv).
//
// Run with:
//
//	go run ./benchmarks/uc3_variance/ [-out path] [-reps n]
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

var crsSeed = []byte("uc3-variance-crs-seed-v1")

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

// Profiles calibrated empirically in spec 009: S2 = label fails (β at level=1,
// budget (q0×q1)/(2t) insufficient with collective keys); S3 = both fail (Q too
// small for BGV Mult noise floor). Same thresholds apply here because UC3's
// depth-1 auto-product uses the same key structure as UC2's cross-product.
var profiles = []paramProfile{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
	{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
	{"min", []int{35, 35}, []int{35, 35}},
}

func main() {
	out := flag.String("out", "results/uc3_variance.csv", "output CSV path")
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
				for _, variant := range []string{"std", "std_modsw", "label"} {
					run := runVariant(variant, params, ds, db.label, rep, profile.name)
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

// expectedSumAndSumSq returns (Σxᵢ mod t, Σxᵢ² mod t) for all values in ds.
// Each xᵢ ≤ 1000, so xᵢ² ≤ 10^6 < t. Running sum ≤ N×10^6 ≤ 10^12 < 2^64.
func expectedSumAndSumSq(ds harness.Dataset) (sum, sumSq uint64) {
	t := ds.PlaintextModulus
	for _, v := range ds.Values {
		sum = (sum + v) % t
		sumSq = (sumSq + v*v%t) % t
	}
	return
}

// varUnnorm computes (N × sumSq − sum²) mod t, the unnormalized variance ×N².
func varUnnorm(n int, sum, sumSq, t uint64) uint64 {
	a := (uint64(n) * sumSq) % t
	b := (sum * sum) % t
	return (a - b + t) % t
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

// rotationGaloisEls returns the log₂(blockSize)=13 Galois elements for the
// rotate-and-sum tree: steps blockSize/2, blockSize/4, ..., 1.
func rotationGaloisEls(params labeling.Parameters) []uint64 {
	var galEls []uint64
	for step := blockSize / 2; step >= 1; step /= 2 {
		galEls = append(galEls, params.GaloisElementForColRotation(step))
	}
	return galEls
}

// genCollectiveGaloisKeys runs the 1-round collective Galois key generation for each galEl.
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
		UseCase:      "UC3",
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
		phases, run.CommBytes, run.Rounds, run.Correct = runStd(params, ds, expSum, expSumSq, false)
	case "std_modsw":
		phases, run.CommBytes, run.Rounds, run.Correct = runStd(params, ds, expSum, expSumSq, true)
	case "label":
		phases, run.CommBytes, run.Rounds, run.Correct = runLabel(params, ds, expSum, expSumSq)
	default:
		log.Fatalf("unknown variant %q", variant)
	}
	run.Phases = phases
	return run
}

// runStd benchmarks the std MHE variant for UC3:
// BGV encrypt + auto-HMul rotate-and-sum (sum_sq) + HAdd rotate-and-sum (sum)
// + two CKS-to-zero threshold decrypts.
//
// When modswitch is true (the std_modsw variant), both result ciphertexts are rescaled
// to level=1 before the CKS threshold decrypt. This matches the share size of the label
// variant (which decrypts at level=1), isolating whether label's communication advantage
// is intrinsic to CF or just an artifact of operating at a lower level. See spec 012.
func runStd(
	params labeling.Parameters,
	ds harness.Dataset,
	expSum, expSumSq uint64,
	modswitch bool,
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
		// partition is done outside; this phase captures dataset preparation cost
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

		// sum_sq: auto-product per block, rotate-and-sum, accumulate across parties
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

		// sum: rotate-and-sum per block, accumulate across parties
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
		ctSumSqDec, ctSumDec := ctSumSq, ctSum
		if modswitch {
			var err error
			if ctSumSqDec, err = labeling.RescaleToLevel(params, ctSumSq, 1); err != nil {
				log.Fatalf("RescaleToLevel sum_sq: %v", err)
			}
			if ctSumDec, err = labeling.RescaleToLevel(params, ctSum, 1); err != nil {
				log.Fatalf("RescaleToLevel sum: %v", err)
			}
		}
		decSumSq = stdCKSDecrypt(bgvParams, skShares[:], ctSumSqDec, params, &commBytes)
		decSum = stdCKSDecrypt(bgvParams, skShares[:], ctSumDec, params, &commBytes)
	}))
	return phases, commBytes, 1, decSumSq == expSumSq && decSum == expSum
}

// stdCKSDecrypt performs a collective key-switch-to-zero on ct, decodes slot 0,
// and adds the share communication bytes to the running total.
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

// runLabel benchmarks the label CF variant for UC3:
// EncryptLabeled + auto-MultLabeled rotate-and-sum (sum_sq)
// + SumLabeled rotate-and-sum (sum) + two threshold decrypts.
func runLabel(
	params labeling.Parameters,
	ds harness.Dataset,
	expSum, expSumSq uint64,
) (phases []harness.PhaseResult, commBytes int64, rounds int, correct bool) {
	bgvParams := params.Parameters
	M := ds.N / 2
	v1 := ds.Values[:M]
	v2 := ds.Values[M : 2*M]

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

	var lctSumSq, lctSum *labeling.PlaintextLabeledciphertext
	phases = append(phases, harness.Run("eval", func() {
		lctSumSq, lctSum = nil, nil

		// sum_sq: auto-MultLabeled per block, rotate-and-sum, accumulate
		for b := range blks1 {
			for _, lct := range []labeling.PlaintextLabeledciphertext{lcts1[b], lcts2[b]} {
				lct := lct // capture
				lctSq, err := labeling.MultLabeled(ctx, rlk, lct, lct)
				if err != nil {
					log.Fatalf("MultLabeled sq blk %d: %v", b, err)
				}
				for step := blockSize / 2; step >= 1; step /= 2 {
					lctRot, err := labeling.RotateColumns(params, lctSq, step, evk)
					if err != nil {
						log.Fatalf("RotateColumns sq step=%d: %v", step, err)
					}
					lctSq, err = labeling.SumLabeled(ctx, lctSq, lctRot)
					if err != nil {
						log.Fatalf("SumLabeled sq step=%d: %v", step, err)
					}
				}
				if lctSumSq == nil {
					tmp := lctSq
					lctSumSq = &tmp
				} else {
					sum, err := labeling.SumLabeled(ctx, *lctSumSq, lctSq)
					if err != nil {
						log.Fatalf("SumLabeled sq acc: %v", err)
					}
					*lctSumSq = sum
				}
			}
		}

		// sum: SumLabeled rotate-and-sum per block (no multiplication)
		for b := range blks1 {
			for _, lct := range []labeling.PlaintextLabeledciphertext{lcts1[b], lcts2[b]} {
				lct := lct // capture
				lctS := lct
				for step := blockSize / 2; step >= 1; step /= 2 {
					lctRot, err := labeling.RotateColumns(params, lctS, step, evk)
					if err != nil {
						log.Fatalf("RotateColumns sum step=%d: %v", step, err)
					}
					lctS, err = labeling.SumLabeled(ctx, lctS, lctRot)
					if err != nil {
						log.Fatalf("SumLabeled sum step=%d: %v", step, err)
					}
				}
				if lctSum == nil {
					tmp := lctS
					lctSum = &tmp
				} else {
					s, err := labeling.SumLabeled(ctx, *lctSum, lctS)
					if err != nil {
						log.Fatalf("SumLabeled sum acc: %v", err)
					}
					*lctSum = s
				}
			}
		}
	}))

	var decSumSq, decSum uint64
	phases = append(phases, harness.Run("decrypt", func() {
		decSumSq = labelThresholdDecrypt(ctx, skShares[:], *lctSumSq, params, &commBytes)
		decSum = labelThresholdDecrypt(ctx, skShares[:], *lctSum, params, &commBytes)
	}))
	return phases, commBytes, 1, decSumSq == expSumSq && decSum == expSum
}

// labelThresholdDecrypt performs GenLabeledDecryptionShare + Aggregate + Decrypt
// for a single labeled ciphertext, adding share sizes to commBytes.
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
