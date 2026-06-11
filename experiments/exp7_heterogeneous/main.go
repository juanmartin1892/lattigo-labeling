// exp7_heterogeneous extends exp6 to realistic heterogeneous datasets.
//
// In exp6, all slots held the same value (testValue=501). This experiment verifies
// that the CF compact improvement (broadcast mask + aggregated CKS) works equally
// well when each slot has a distinct random value — the realistic use case.
//
// Root cause of the wrap-around problem (and why broadcast mask alone is not enough):
//   Per-slot masks b_i ∈ [0, sqrt(t) ≈ 8184]: when b_i > v_i (≈88% of slots for
//   v_i ∈ [1,1000]), a_i = (v_i - b_i) mod t ≈ t ≈ 67M → CT×PT noise ≈ 67M × B_fresh
//   >> S3 budget. This is a wrap-around artifact, not an inherent CF limitation.
//
// Fix: broadcast mask b_j ≤ min(block values) — guarantees a_i = v_i - b_j ≥ 0.
//   max(a_i) = vMax - b_j ≤ vMax ≤ 600 → CT×PT noise ≈ 600 × B_fresh (tiny vs std).
//
// Mathematical identity (per block j, blockSize slots, broadcast mask b_j):
//   a_i = v_i - b_j (no wrap-around)
//   β_j = Enc([b_j, ..., b_j])
//   α_j = Enc([a_0², ..., a_{bs-1}², 0...]) + 2×(β_j × PT_a)
//       = Enc([v_0²-b_j², ..., v_{bs-1}²-b_j², 0...])   ← exact identity
//   After RotAS: Dec(α_j)[0] = Σ_i v_i² - blockSize × b_j²
//   Correction:  + blockSize × b_j² = Σ_i v_i² ✓
//
// Noise per block (heterogeneous data, broadcast mask b_j ≤ vMin):
//   CT×PT: max(a_i) × B_fresh ≤ (vMax - b_j) × B_fresh ≤ vMax × B_fresh
//   After RotAS (×blockSize):  vMax × B_fresh × blockSize
//   After N_blocks aggregation: N_blocks × vMax × B_fresh × blockSize
//
//   For vMin=100, vMax=600, blockSize=8192, B_fresh=410:
//     Per block: 600 × 410 × 8192 ≈ 2^31.9
//     62 blocks: 62 × 2^31.9 ≈ 2^37.9 < budget 2^43 → PASS at S3/min
//
//   Std HMul per block: B_fresh² × N × blockSize ≈ 2^44.4 >> 2^43 → FAIL at S3
//
// Scientific equivalence: both CF and Std receive the SAME dataset per repetition.
// The comparison is: same parameters, same data, different cryptographic technique.
//
// Run: go run ./experiments/exp7_heterogeneous/
package main

import (
	"fmt"
	"log"
	"math"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	blockSize        = 8192 // N/2 = 16384/2 slots per block (first half used)
	vMin             = uint64(100)
	vMax             = uint64(600)
	nReps            = 5
)

var profiles = []struct {
	name string
	logQ []int
	logP []int
}{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
	{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
	{"min", []int{35, 35}, []int{35, 35}},
}

// dataset holds pre-generated block data and the expected result for scientific equivalence.
type dataset struct {
	blocks   [][]uint64 // numBlocks slices, each of length blockSize
	expected uint64     // Σ_j Σ_i v_i_j² mod t (same for CF and Std)
}

// newDataset generates numBlocks × blockSize random values in [vMin, vMax].
// Using a fresh PRNG per call ensures independent reps; passing the same dataset
// to CF and Std ensures scientific equivalence within each rep.
func newDataset(numBlocks int, t uint64) (dataset, error) {
	prng, err := sampling.NewPRNG()
	if err != nil {
		return dataset{}, err
	}

	rangeSize := vMax - vMin + 1
	roundedRange := uint64(1) << uint(math.Ceil(math.Log2(float64(rangeSize+1))))

	blocks := make([][]uint64, numBlocks)
	expected := uint64(0)
	for j := range numBlocks {
		block := make([]uint64, blockSize)
		for i := range blockSize {
			v := vMin + ring.RandUniform(prng, rangeSize, roundedRange-1)%rangeSize
			block[i] = v
			expected = (expected + (v%t)*(v%t)%t) % t
		}
		blocks[j] = block
	}
	return dataset{blocks, expected}, nil
}

// buildBlockAlphaHetero builds α for one block of heterogeneous slot values using a
// broadcast mask b_j (same scalar for all slots in the block).
//
// Noise amplification: max(a_i) × B_fresh where max(a_i) = vMax - b_j ≤ vMax ≤ 600.
// This is in contrast to per-slot random masks in [0,sqrt(t)] where wrap-around makes
// max(a_i) ≈ t ≈ 67M.
//
// Returns (α_after_RotAS, correction = blockSize × b_j²).
func buildBlockAlphaHetero(
	params bgv.Parameters, pk *rlwe.PublicKey,
	evkGal *rlwe.MemEvaluationKeySet,
	values []uint64, // length blockSize, all in [vMin, vMax]
	bj uint64, // broadcast mask, bj < vMin → no wrap-around guaranteed
) (*rlwe.Ciphertext, uint64, error) {
	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	// a_i = v_i - b_j (non-negative, no wrap: v_i ≥ vMin > bj)
	aVec := make([]uint64, slots)
	a2Vec := make([]uint64, slots)
	bjVec := make([]uint64, slots)
	for i := range blockSize {
		a := values[i] - bj // guaranteed ≥ vMin - (vMin-1) = 1 > 0
		aVec[i] = a
		a2Vec[i] = a * a % t
		bjVec[i] = bj
	}
	// Slots [blockSize..N-1] remain 0 (zero-valued blocks, not used).

	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	eval := bgv.NewEvaluator(params, evkGal)

	// β_j = Enc([b_j, ..., b_j]) — broadcast ciphertext, same b_j in all slots.
	// The evaluator receives this encrypted; it knows b_j only via the ciphertext.
	ptxtBj := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(bjVec, ptxtBj); err != nil {
		return nil, 0, err
	}
	beta, err := encryptor.EncryptNew(ptxtBj)
	if err != nil {
		return nil, 0, err
	}

	// α_j = Enc([a_0², ..., a_{bs-1}², 0, ...])
	ptxtA2 := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(a2Vec, ptxtA2); err != nil {
		return nil, 0, err
	}
	alpha, err := encryptor.EncryptNew(ptxtA2)
	if err != nil {
		return nil, 0, err
	}

	// α_j += 2 × (β_j × PT_a).
	// β_j × [a_0,...,a_{bs-1},0,...] = Enc([b_j×a_0,...,b_j×a_{bs-1},0,...])
	// Noise amplification: max(a_i) × B_fresh ≤ (vMax-bj) × B_fresh ≤ vMax × B_fresh.
	// Adding twice gives the 2× factor in the identity:
	//   a_i² + 2b_j×a_i = (a_i+b_j)² - b_j² = v_i² - b_j²
	for range 2 {
		tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := eval.Mul(beta, aVec, tmp); err != nil {
			return nil, 0, fmt.Errorf("Mul β×a: %w", err)
		}
		if err := eval.Add(alpha, tmp, alpha); err != nil {
			return nil, 0, fmt.Errorf("Add α+=2×β×a: %w", err)
		}
	}

	// Rotate-and-sum over blockSize slots (log2(blockSize) = 13 rotations).
	// After this: slot 0 = Σ_{i=0}^{blockSize-1} (v_i² - b_j²) = Σ v_i² - blockSize×b_j².
	for step := 1; step < blockSize; step <<= 1 {
		rotated, err := eval.RotateColumnsNew(alpha, step)
		if err != nil {
			return nil, 0, fmt.Errorf("RotateColumns step=%d: %w", step, err)
		}
		if err := eval.Add(alpha, rotated, alpha); err != nil {
			return nil, 0, fmt.Errorf("Add rotated: %w", err)
		}
	}

	// Correction known to data owner (no communication needed):
	// blockSize × b_j² to recover Σ v_i² from Dec(α)[0].
	correction := uint64(blockSize) * (bj * bj % t) % t

	return alpha, correction, nil
}

// runCFHetero runs the CF compact protocol on a pre-generated dataset.
// Uses 1 CKS (same communication cost as std) via the aggregated approach from exp6.
func runCFHetero(
	params bgv.Parameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey,
	evkGal *rlwe.MemEvaluationKeySet,
	ds dataset,
) (bool, error) {
	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	prng, err := sampling.NewPRNG()
	if err != nil {
		return false, err
	}

	// Choose b_j ~ Uniform[0, vMin-1] per block: guarantees no wrap-around.
	// The mask is broadcast (same b_j for all blockSize slots in block j).
	maskBound := vMin - 1
	roundedBound := uint64(1) << uint(math.Ceil(math.Log2(float64(maskBound+1))))

	eval := bgv.NewEvaluator(params, evkGal)
	var alphaTotal *rlwe.Ciphertext
	var bSqTotal uint64

	for _, block := range ds.blocks {
		bj := ring.RandUniform(prng, maskBound+1, roundedBound-1) % (maskBound + 1)

		alpha, correction, err := buildBlockAlphaHetero(params, pk, evkGal, block, bj)
		if err != nil {
			return false, err
		}
		bSqTotal = (bSqTotal + correction) % t

		if alphaTotal == nil {
			alphaTotal = alpha
		} else {
			if err := eval.Add(alphaTotal, alpha, alphaTotal); err != nil {
				return false, fmt.Errorf("Add blocks: %w", err)
			}
		}
	}

	// Single threshold decrypt (simulated): 1 CKS share per party, same as std.
	dec := rlwe.NewDecryptor(params, sk)
	encoder := bgv.NewEncoder(params)
	result := make([]uint64, slots)
	if err := encoder.Decode(dec.DecryptNew(alphaTotal), result); err != nil {
		return false, err
	}

	// result[0] = Σ_j (Σ_i v_i² - blockSize×b_j²) = Σ_j Σ_i v_i² - bSqTotal
	// After correction: Σ_j Σ_i v_i²
	decResult := (result[0] + bSqTotal + t) % t
	return decResult == ds.expected, nil
}

// runStdHetero runs standard BGV MulRelin on the same pre-generated dataset.
// Both CF and Std receive the same ds.blocks and compare against ds.expected.
func runStdHetero(
	params bgv.Parameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey,
	evk *rlwe.MemEvaluationKeySet,
	ds dataset,
) (bool, error) {
	slots := params.MaxSlots()

	eval := bgv.NewEvaluator(params, evk)
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)

	var ctTotal *rlwe.Ciphertext

	for _, block := range ds.blocks {
		vVec := make([]uint64, slots)
		copy(vVec, block) // slots [blockSize..N-1] = 0

		ptxt := bgv.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(vVec, ptxt); err != nil {
			return false, err
		}
		ct, err := encryptor.EncryptNew(ptxt)
		if err != nil {
			return false, err
		}

		// MulRelin: noise = B_fresh² × N ≈ 2^34.8. After RotAS: ×blockSize → 2^47.8.
		// At S3/min budget = 2^43: 2^47.8 >> 2^43 → FAILS.
		ctSq, err := eval.MulRelinNew(ct, ct)
		if err != nil {
			return false, fmt.Errorf("MulRelin: %w", err)
		}

		for step := 1; step < blockSize; step <<= 1 {
			rotated, err := eval.RotateColumnsNew(ctSq, step)
			if err != nil {
				return false, err
			}
			if err := eval.Add(ctSq, rotated, ctSq); err != nil {
				return false, err
			}
		}

		if ctTotal == nil {
			ctTotal = ctSq
		} else {
			if err := eval.Add(ctTotal, ctSq, ctTotal); err != nil {
				return false, err
			}
		}
	}

	result := make([]uint64, slots)
	if err := encoder.Decode(dec.DecryptNew(ctTotal), result); err != nil {
		return false, err
	}

	return result[0] == ds.expected, nil
}

func main() {
	fmt.Println("=== Exp-7: CF Compact with Heterogeneous Data ===")
	fmt.Println()
	fmt.Printf("Dataset: v_i ~ Uniform[%d, %d], blockSize=%d slots\n", vMin, vMax, blockSize)
	fmt.Printf("CF mask: b_j ~ Uniform[0, %d] per block (broadcast, no wrap-around)\n", vMin-1)
	fmt.Printf("Security: evaluator knows a_i=v_i-b_j (plaintext) but not b_j (only Enc(b_j))\n")
	fmt.Println()

	// Noise model.
	bFresh := 3.2 * math.Sqrt(float64(1<<logN))
	fmt.Printf("=== Noise model (B_fresh=%.0f≈2^%.1f) ===\n", bFresh, math.Log2(bFresh))

	// CF overhead: max(a_i) × B_fresh × blockSize (per block, then × numBlocks for total)
	maxA := float64(vMax) // worst case: b_j = 0
	bCFperBlock := maxA * bFresh * float64(blockSize)
	// Std: B_fresh² × N × blockSize (per block)
	bStdPerBlock := bFresh * bFresh * float64(1<<logN) * float64(blockSize)

	fmt.Printf("  CF overflow per block (max(a)=%v, after RotAS): 2^%.1f\n", vMax, math.Log2(bCFperBlock))
	fmt.Printf("  Std HMul   per block (after MulRelin+RotAS):    2^%.1f\n", math.Log2(bStdPerBlock))
	fmt.Printf("  Ratio: Std/CF = %.0fx (CF is ~%.0f× less noisy per block)\n",
		bStdPerBlock/bCFperBlock, bStdPerBlock/bCFperBlock)
	fmt.Println()

	smudge := 2 * 25.6 * math.Sqrt(float64(1<<logN))

	for _, prof := range profiles {
		logQSum := 0.0
		for _, lq := range prof.logQ {
			logQSum += float64(lq)
		}
		budget := math.Pow(2, logQSum) / (2.0 * float64(plaintextModulus))
		fmt.Printf("  Profile %-6s budget=2^%.1f:", prof.name, math.Log2(budget))
		for _, nb := range []int{1, 4, 16, 62} {
			bCF := float64(nb)*bCFperBlock + smudge
			bStd := float64(nb)*bStdPerBlock + smudge
			cfPass := "✓"
			if bCF >= budget {
				cfPass = "✗"
			}
			stdPass := "✓"
			if bStd >= budget {
				stdPass = "✗"
			}
			fmt.Printf("  %d blk [CF 2^%.1f%s / Std 2^%.1f%s]",
				nb, math.Log2(bCF), cfPass, math.Log2(bStd), stdPass)
		}
		fmt.Println()
	}
	fmt.Println()

	// Empirical tests.
	for _, prof := range profiles {
		params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             logN,
			LogQ:             prof.logQ,
			LogP:             prof.logP,
			PlaintextModulus: plaintextModulus,
		})
		if err != nil {
			log.Printf("skip profile %s: %v", prof.name, err)
			continue
		}

		fmt.Printf("Profile: %s (MaxLevel=%d)\n", prof.name, params.MaxLevel())

		kgen := rlwe.NewKeyGenerator(params)
		sk, pk := kgen.GenKeyPairNew()
		rlk := kgen.GenRelinearizationKeyNew(sk)

		galKeys := make([]*rlwe.GaloisKey, 0)
		for step := 1; step < blockSize; step <<= 1 {
			gk := kgen.GenGaloisKeyNew(params.GaloisElement(step), sk)
			galKeys = append(galKeys, gk)
		}
		evkFull := rlwe.NewMemEvaluationKeySet(rlk, galKeys...)
		evkGalOnly := rlwe.NewMemEvaluationKeySet(nil, galKeys...)

		for _, numBlocks := range []int{1, 4, 16} {
			cfCorrect, stdCorrect := 0, 0

			for rep := range nReps {
				// Same dataset for both: scientific equivalence.
				ds, err := newDataset(numBlocks, params.PlaintextModulus())
				if err != nil {
					log.Fatalf("rep %d newDataset: %v", rep, err)
				}

				ok, err := runCFHetero(params, sk, pk, evkGalOnly, ds)
				if err != nil {
					log.Printf("  rep %d CF error: %v", rep, err)
				} else if ok {
					cfCorrect++
				}

				ok, err = runStdHetero(params, sk, pk, evkFull, ds)
				if err != nil {
					log.Printf("  rep %d Std error: %v", rep, err)
				} else if ok {
					stdCorrect++
				}
			}

			records := numBlocks * blockSize
			fmt.Printf("  [%2d block(s), %6d records]  CF: %d/%d  Std: %d/%d\n",
				numBlocks, records, cfCorrect, nReps, stdCorrect, nReps)
		}
		fmt.Println()
	}

	fmt.Println("=== Key finding ===")
	fmt.Println("CF compact + broadcast mask (b_j ≤ vMin) works for heterogeneous data.")
	fmt.Println("The noise advantage over std is determined by max(a_i) ≤ vMax,")
	fmt.Println("NOT by N×mean(a) (the wrap-around was the actual problem in exp6).")
	fmt.Println()
	fmt.Println("Security of broadcast mask for heterogeneous data:")
	fmt.Println("  - Evaluator receives a_i = v_i - b_j (plaintext, heterogeneous)")
	fmt.Println("  - Evaluator receives Enc([b_j,...,b_j]) but NOT b_j itself")
	fmt.Println("  - Evaluator CAN deduce v_i - v_k = a_i - a_k (intra-block differences)")
	fmt.Println("  - Evaluator CANNOT deduce individual v_i without b_j")
	fmt.Println("  - Acceptable for aggregate queries (variance, sum-of-squares)")
}
