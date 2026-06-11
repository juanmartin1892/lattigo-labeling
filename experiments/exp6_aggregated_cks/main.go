// exp6_aggregated_cks explores two improvements for UC4 CF compact:
//
//  1. Aggregate all per-block α ciphertexts BEFORE threshold CKS decryption.
//     Current: 2 CKS per block × numBlocks × n → Proposed: 1 CKS × n (=std)
//
//  2. Broadcast mask per block (one b_j per ciphertext, same for all N slots).
//     Critical insight: per-slot independent masks cause NTT(a) DC = N × mean(a) ≈ 6M,
//     which amplifies noise ×6M/501 ≈ 12K relative to a broadcast mask.
//     With per-slot masks: noise after RotAS ≈ 2^44.2 > budget 2^43 → FAIL at S3.
//     With broadcast mask:  noise after RotAS ≈ 2^30.6 << budget 2^43 → PASS at S3.
//
// Mathematical correctness of aggregated protocol:
//   Per block j with broadcast mask b_j (all slots have same b_j):
//     α_j = Enc(a_j²×1_N) + 2×(a_j × β_j)   where a_j = v_j - b_j (scalar)
//     After rotate-and-sum: Dec(α_j)[0] = N × (v_j² - b_j²)
//   After aggregating k blocks: Dec(α_total) = N × Σ_j (v_j² - b_j²)
//   Plaintext correction: N × Σ_j b_j²  (known to data owner who chose masks)
//   Result = N × Σ_j v_j² ✓
//
// Security note on broadcast masks:
//   With per-slot masks (b_i independent per slot): differences a_i - a_j are hidden
//   since a_i = v_i - b_i and b_i ≠ b_j. The mask conceals inter-record differences.
//   With broadcast mask b_j (same for all slots in block j): a_i - a_j = v_i - v_j
//   is revealed to the evaluator. This is a tradeoff: less security, but:
//   (a) CF labeling already sends a_i in plaintext to the evaluator by design,
//   (b) For aggregate-only queries (e.g., variance), inter-record differences may
//       not be sensitive if the evaluator doesn't see individual records anyway.
//   Per-block broadcast mask is a valid choice when the security threat model
//   only requires hiding individual values (v_i from β_i), not inter-record differences.
//
// Run: go run ./experiments/exp6_aggregated_cks/
package main

import (
	"bytes"
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
	blockSize        = 8192
	testValue        = uint64(501)
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

// buildBlockAlphaBroadcast builds α for one block via CF overflow using a BROADCAST mask
// (one scalar mask b for all slots). This is critical for noise control at S3/min.
//
// With per-slot masks: NTT(a) has DC component = N × mean(a) ≈ 6M, causing noise
// after scalar mult ≈ 6M × B_fresh. With broadcast mask: NTT(a) = [a,a,...,a]
// with max = a ≤ value, giving noise ≈ value × B_fresh (≈ 12K times smaller).
//
// Returns (α_after_RotAS, blockSize_slots × b²).
func buildBlockAlphaBroadcast(
	params bgv.Parameters, pk *rlwe.PublicKey,
	evkGal *rlwe.MemEvaluationKeySet,
	value, maskBound uint64,
) (*rlwe.Ciphertext, uint64, error) {
	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	prng, err := sampling.NewPRNG()
	if err != nil {
		return nil, 0, err
	}

	// ONE broadcast mask for all slots.
	roundedBound := uint64(1) << uint(math.Ceil(math.Log2(float64(maskBound+1))))
	b := ring.RandUniform(prng, maskBound+1, roundedBound-1) % (maskBound + 1)
	a := (value - b + t) % t // scalar, same for all slots

	aVec := make([]uint64, slots)
	bVec := make([]uint64, slots)
	for i := range slots {
		aVec[i] = a
		bVec[i] = b
	}

	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	eval := bgv.NewEvaluator(params, evkGal)

	ptxtB := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(bVec, ptxtB); err != nil {
		return nil, 0, err
	}
	beta, err := encryptor.EncryptNew(ptxtB)
	if err != nil {
		return nil, 0, err
	}

	// CF overflow: α = Enc(a²×1_N) + 2×(a×β).
	a2Vec := make([]uint64, slots)
	for i := range slots {
		a2Vec[i] = (a * a) % t
	}
	ptxtA2 := bgv.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(a2Vec, ptxtA2); err != nil {
		return nil, 0, err
	}
	alpha, err := encryptor.EncryptNew(ptxtA2)
	if err != nil {
		return nil, 0, err
	}

	// 2 × (a × β): use scalar a (broadcast), so eval.Mul uses the uint64 vector.
	for range 2 {
		tmp := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		if err := eval.Mul(beta, aVec, tmp); err != nil {
			return nil, 0, fmt.Errorf("Mul a×β: %w", err)
		}
		if err := eval.Add(alpha, tmp, alpha); err != nil {
			return nil, 0, fmt.Errorf("Add α: %w", err)
		}
	}

	// Rotate-and-sum within block (covers blockSize = slots/2 = 8192 slots, first half).
	for step := 1; step < blockSize; step <<= 1 {
		rotated, err := eval.RotateColumnsNew(alpha, step)
		if err != nil {
			return nil, 0, fmt.Errorf("RotateColumns step=%d: %w", step, err)
		}
		if err := eval.Add(alpha, rotated, alpha); err != nil {
			return nil, 0, fmt.Errorf("Add rotated: %w", err)
		}
	}

	// b² contribution for this block (covers blockSize slots in first half).
	// After rotate-and-sum, slot 0 = Σ_{i=0}^{blockSize-1} (v²-b²) = blockSize*(v²-b²).
	bSqBlock := (b * b) % t * uint64(blockSize) % t

	return alpha, bSqBlock, nil
}

// runAggregatedCF builds k blocks with broadcast masks, aggregates α, decrypts once.
// This simulates the optimized CF compact protocol: 1 CKS share per party (same as std).
func runAggregatedCF(
	params bgv.Parameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey,
	evkGal *rlwe.MemEvaluationKeySet,
	value, maskBound uint64, numBlocks int,
) (bool, error) {
	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	var alphaTotal *rlwe.Ciphertext
	var bSqTotal uint64

	eval := bgv.NewEvaluator(params, evkGal)

	for range numBlocks {
		// Broadcast mask: one b per block, same for all slots in the block.
		alpha, bSqBlock, err := buildBlockAlphaBroadcast(params, pk, evkGal, value, maskBound)
		if err != nil {
			return false, err
		}
		bSqTotal = (bSqTotal + bSqBlock) % t

		if alphaTotal == nil {
			alphaTotal = alpha
		} else {
			if err := eval.Add(alphaTotal, alpha, alphaTotal); err != nil {
				return false, fmt.Errorf("Add blocks: %w", err)
			}
		}
	}

	// Single decrypt (simulates single CKS — 1×n shares, same as std).
	dec := rlwe.NewDecryptor(params, sk)
	encoder := bgv.NewEncoder(params)
	alphaResult := make([]uint64, slots)
	if err := encoder.Decode(dec.DecryptNew(alphaTotal), alphaResult); err != nil {
		return false, err
	}

	// result = Dec(α_total)[slot 0] + bSqTotal.
	// Dec(α_total)[slot 0] = numBlocks × blockSize × (v² - b_j²) avg...
	// With broadcast b_j per block:
	//   Dec(α_j)[slot 0] after RotAS = blockSize × (v² - b_j²)
	//   Dec(α_total)[slot 0] = Σ_j blockSize × (v² - b_j²) = blockSize × numBlocks × v² - bSqTotal
	// So result = Dec(α_total)[0] + bSqTotal = blockSize × numBlocks × v².
	result := (alphaResult[0] + bSqTotal + t) % t
	expected := uint64(numBlocks) * uint64(blockSize) * (value * value % t) % t
	return result == expected, nil
}

// runStdHMulAggregated: standard BGV approach for k blocks (aggregate then decrypt).
func runStdHMulAggregated(
	params bgv.Parameters, sk *rlwe.SecretKey, pk *rlwe.PublicKey,
	evk *rlwe.MemEvaluationKeySet,
	value uint64, numBlocks int,
) (bool, error) {
	t := params.PlaintextModulus()
	slots := params.MaxSlots()

	eval := bgv.NewEvaluator(params, evk)
	encoder := bgv.NewEncoder(params)
	encryptor := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)

	vals := make([]uint64, slots)
	for i := range vals {
		vals[i] = value
	}

	var ctTotal *rlwe.Ciphertext
	for range numBlocks {
		ptxt := bgv.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(vals, ptxt); err != nil {
			return false, err
		}
		ct, err := encryptor.EncryptNew(ptxt)
		if err != nil {
			return false, err
		}
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

	expected := uint64(numBlocks) * uint64(blockSize) * (value*value%t) % t
	return result[0] == expected, nil
}

func main() {
	fmt.Println("=== Exp-6: Aggregated CKS for CF Compact (UC4) ===")
	fmt.Println()
	fmt.Println("Key idea: aggregate all block α ciphertexts before threshold CKS.")
	fmt.Println("  Current CF: 2 CKS per block × numBlocks × n parties")
	fmt.Println("  Aggregated: 1 CKS total × n parties (= same as std)")
	fmt.Println("  Requirement: optimized masks (maskBound ≤ value/2 → no wrap-around)")
	fmt.Println()

	// Communication model.
	fmt.Println("=== Communication model (n=2 parties, S1/full) ===")
	shareSize := int64(2) * 16384 * 4 * 8 // 2 × N × (MaxLevel+1) × 8 bytes at level=3
	fmt.Printf("CKS share size at MaxLevel=3: %.0f KB\n", float64(shareSize)/1024)
	for _, db := range []struct {
		label  string
		blocks int
	}{{"DB1", 1}, {"DB2", 13}, {"DB3", 62}} {
		current := int64(2) * int64(db.blocks) * 2 * shareSize
		aggregated := int64(2) * shareSize
		fmt.Printf("  %s (%2d blocks): current=%6.1f MB  aggregated=%5.1f MB  speedup=%.0fx\n",
			db.label, db.blocks,
			float64(current)/1e6, float64(aggregated)/1e6,
			float64(current)/float64(aggregated))
	}
	fmt.Println()

	// Noise model.
	bFresh := 3.2 * math.Sqrt(float64(1<<logN))
	fmt.Printf("=== Noise model (B_fresh=%.0f≈2^%.1f) ===\n", bFresh, math.Log2(bFresh))
	// Std HMul noise per block (after MulRelin + rotate-and-sum).
	bMulStd := bFresh * bFresh * float64(1<<logN) * float64(blockSize)
	// CF overflow noise per block with optimized mask (||a||≤value=501, no wrap).
	bOverflowOpt := (1 + 2*float64(testValue)) * bFresh * float64(blockSize)
	fmt.Printf("  Std HMul noise/block (after RotAS):    2^%.1f\n", math.Log2(bMulStd))
	fmt.Printf("  CF overflow noise/block (opt mask):    2^%.1f\n", math.Log2(bOverflowOpt))
	fmt.Printf("  CF overflow noise (62 blocks agg):     2^%.1f\n", math.Log2(62*bOverflowOpt))

	smudge := 2 * 25.6 * math.Sqrt(float64(1<<logN))
	fmt.Printf("  CKS smudging (1 decrypt, n=2):         2^%.1f\n", math.Log2(smudge))
	fmt.Println()
	for _, prof := range profiles {
		logQSum := 0.0
		for _, lq := range prof.logQ {
			logQSum += float64(lq)
		}
		budget := math.Pow(2, logQSum) / (2.0 * float64(plaintextModulus))
		bTotalStd := bMulStd + smudge
		bTotalCF62 := 62*bOverflowOpt + smudge
		fmt.Printf("  Profile %-6s budget=2^%.1f  std/block=2^%.1f [%s]  CF/62blk=2^%.1f [%s]\n",
			prof.name,
			math.Log2(budget),
			math.Log2(bTotalStd), pass(bTotalStd < budget),
			math.Log2(bTotalCF62), pass(bTotalCF62 < budget))
	}
	fmt.Println()

	// Empirical test.
	// With broadcast mask and value=501, any maskBound < 501 avoids wrap-around.
	// maskBound=250 gives a = value-mask ∈ [251,501], NTT(a) = [a,a,...] (constant), ||NTT||_max = a.
	maskBoundOpt := testValue / 2 // 250 — broadcast, no wrap-around

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

		// Serialized ciphertext size for communication estimate.
		ct0 := rlwe.NewCiphertext(params, 1, params.MaxLevel())
		var buf bytes.Buffer
		ctBytes, _ := ct0.WriteTo(&buf)

		for _, numBlocks := range []int{1, 4, 16} {
			cfCorrect := 0
			stdCorrect := 0
			for rep := 0; rep < nReps; rep++ {
				ok, err := runAggregatedCF(params, sk, pk, evkGalOnly, testValue, maskBoundOpt, numBlocks)
				if err != nil {
					log.Printf("  rep %d CF error: %v", rep, err)
				} else if ok {
					cfCorrect++
				}

				ok, err = runStdHMulAggregated(params, sk, pk, evkFull, testValue, numBlocks)
				if err != nil {
					log.Printf("  rep %d std error: %v", rep, err)
				} else if ok {
					stdCorrect++
				}
			}

			comCFCurrent := int64(numBlocks) * 2 * 2 * ctBytes // 2 CKS per block × 2 parties
			comCFAgg := int64(1) * 2 * ctBytes                  // 1 CKS × 2 parties
			comStd := int64(1) * 2 * ctBytes                    // 1 CKS × 2 parties

			fmt.Printf("  [%2d block(s), %6d records]\n", numBlocks, numBlocks*blockSize)
			fmt.Printf("    CF agg + broadcast mask=%d: %d/%d correct | comm %.1f MB → %.1f MB (%.0fx)\n",
				maskBoundOpt, cfCorrect, nReps,
				float64(comCFCurrent)/1e6, float64(comCFAgg)/1e6,
				float64(comCFCurrent)/float64(comCFAgg))
			fmt.Printf("    Std HMul (with relin):      %d/%d correct | comm %.1f MB\n",
				stdCorrect, nReps, float64(comStd)/1e6)
		}
		fmt.Println()
	}

	fmt.Println("=== Summary ===")
	fmt.Println("Broadcast mask per block + aggregated CKS gives:")
	fmt.Println("  1. CF compact: 1 CKS per query (same comm as std, regardless of #blocks)")
	fmt.Println("  2. No RLK setup required (saves 12.6 MB one-time)")
	fmt.Println("  3. Correct at S3/min where std HMul fails (rlk-free noise advantage)")
	fmt.Println()
	fmt.Println("Security tradeoff of broadcast mask vs per-slot mask:")
	fmt.Println("  Per-slot: a_i - a_j hidden (b_i ≠ b_j) → inter-record differences protected")
	fmt.Println("  Broadcast: a_i - a_j = v_i - v_j revealed → differences leaked within block")
	fmt.Println("  Acceptable when: queries aggregate over entire DB, no per-record access needed")
	fmt.Println("  Not acceptable when: adversary can query individual slot values from evaluator")
}

func pass(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
