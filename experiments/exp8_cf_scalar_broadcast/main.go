// exp8: CF scalar-broadcast vs Std at S3/min for heterogeneous UC4 variance query.
//
// Key insight: when using a broadcast mask (constant b_j per block), the cross-term
//   Σ(a_i × b_j) = b_j × Σa_i
// becomes a SCALAR×CT multiplication (not CT×heterogeneous_PT), because Σa_i is a
// public scalar. This avoids the catastrophic noise from encoding heterogeneous
// slot values into BGV's ring Z_t[X]/(X^N+1), where coefficients grow to O(t/2).
//
// CF-scalar protocol per block (blockSize = N/2 users, broadcast mask b_j):
//   Public: a_i = v_i - b_j,  S = Σa_i,  S2 = Σa_i²
//   Ciphertexts: β = Enc([b_j,...,b_j]),  β_sq = Enc([b_j²,...,b_j²])
//   α = 2·S·β + blockSize·β_sq           (two scalar×CT mults + one CT-add)
//   Threshold-decrypt α → X in slot 0
//   Result = X + S2 = 2·S·b_j + blockSize·b_j² + Σa_i² = Σv_i²  ✓
//
// RotAS note: BGV with LogN=14 has MaxSlots()=N=16384, but the two-row structure
// means column rotation by blockSize=N/2 is identity within each row. We restrict
// RotAS to steps 1..blockSize/2 so that it sums exactly one block (N/2 = 8192 slots).
//
// Run: go run ./experiments/exp8_cf_scalar_broadcast/main.go
package main

import (
	"fmt"
	"log"
	"math"
	"math/rand/v2"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

func main() {
	const (
		logN   = 14
		t      = uint64(0x3ee0001) // ≈ 65.9M
		trials = 5
	)

	// Parameter profiles.
	profiles := []struct {
		name string
		logQ []int
		logP []int
	}{
		{"S3/min  [35,35]", []int{35, 35}, []int{35, 35}},
		{"S3/full [38,37,50]", []int{38, 37, 50}, []int{50, 50}},
		{"full    [56,55,55,54]", []int{56, 55, 55, 54}, []int{55, 55}},
	}

	// Data configurations (heterogeneous).
	datasets := []struct {
		vMin, vMax uint64
	}{
		{100, 500},
		{100, 5000},
		{1000, 50000},
	}

	for _, prof := range profiles {
		params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
			LogN:             logN,
			LogQ:             prof.logQ,
			LogP:             prof.logP,
			PlaintextModulus: t,
		})
		if err != nil {
			log.Printf("skip %s: %v", prof.name, err)
			continue
		}
		budget := noiseBudget(params)
		// blockSize = N/2: one row of the two-row BGV plaintext structure.
		// RotateColumns(step) for step >= N/2 is identity within each row,
		// so RotAS must use steps 1..blockSize/2 to sum exactly blockSize slots.
		N := params.N()
		blockSize := N / 2 // 8192 for LogN=14
		fmt.Printf("=== Profile %s  MaxLevel=%d  budget=2^%.1f  blockSize=%d ===\n",
			prof.name, params.MaxLevel(), budget, blockSize)

		kgen := rlwe.NewKeyGenerator(params)
		sk, pk := kgen.GenKeyPairNew()
		rlk := kgen.GenRelinearizationKeyNew(sk)

		// Galois keys for RotAS over blockSize slots (steps 1..blockSize/2).
		galKeys := make([]*rlwe.GaloisKey, 0)
		for step := 1; step < blockSize; step <<= 1 {
			galKeys = append(galKeys, kgen.GenGaloisKeyNew(params.GaloisElement(step), sk))
		}
		evk := rlwe.NewMemEvaluationKeySet(rlk, galKeys...)
		encoder := bgv.NewEncoder(params)
		encryptor := rlwe.NewEncryptor(params, pk)
		dec := rlwe.NewDecryptor(params, sk)
		eval := bgv.NewEvaluator(params, evk)

		bFresh := 3.2 * math.Sqrt(float64(N))

		for _, ds := range datasets {
			vMin, vMax := ds.vMin, ds.vMax
			// Broadcast mask: b_j = vMin - 1 ensures a_i = v_i - b_j ≥ 1 > 0.
			bj := vMin - 1

			// Generate deterministic data: blockSize users per block.
			rng := rand.New(rand.NewPCG(0xdeadbeef, 0xcafebabe))
			vVec := make([]uint64, blockSize)
			for i := range blockSize {
				vVec[i] = vMin + rng.Uint64()%(vMax-vMin+1)
			}

			// Public values (computed by each user client, then aggregated).
			S := uint64(0)  // Σa_i mod t
			S2 := uint64(0) // Σa_i² mod t
			for _, v := range vVec {
				ai := (v - bj) % t
				S = (S + ai) % t
				S2 = (S2 + ai*ai%t) % t
			}
			bjSq := bj * bj % t

			// Noise model estimates.
			// CF-scalar: 2·S·β uses scalar=2S as CT×constantPT.
			// Noise = |2S| × B_fresh + blockSize × B_fresh (both terms).
			sumA := float64(0)
			for _, v := range vVec {
				sumA += float64(v - bj)
			}
			noiseCF := 2*sumA*bFresh + float64(blockSize)*bFresh
			// Std: CT×CT MulRelin noise scales with ||m||_inf of encoded plaintext.
			// For heterogeneous data, ||m||_inf ≈ t/2 ≈ 2^25.9 (INTT distributes coefficients).
			// After RotAS (×2^13 = 8192): total noise grows dramatically.
			noiseStd := float64(N) * float64(t/2) * bFresh * float64(blockSize)

			// Expected result: Σ v_i² mod t over blockSize users.
			expected := uint64(0)
			for _, v := range vVec {
				expected = (expected + v*v%t) % t
			}

			cfPasses, stdPasses := 0, 0
			for range trials {
				// ------ CF-scalar protocol ------
				// Encrypt constant vectors for β and β².
				bjVec := make([]uint64, blockSize)
				bjSqVec := make([]uint64, blockSize)
				for i := range blockSize {
					bjVec[i] = bj
					bjSqVec[i] = bjSq
				}
				ptBeta := bgv.NewPlaintext(params, params.MaxLevel())
				encoder.Encode(bjVec, ptBeta)
				ctBeta, _ := encryptor.EncryptNew(ptBeta)

				ptBetaSq := bgv.NewPlaintext(params, params.MaxLevel())
				encoder.Encode(bjSqVec, ptBetaSq)
				ctBetaSq, _ := encryptor.EncryptNew(ptBetaSq)

				// α = 2·S·β + blockSize·β_sq  (two scalar×CT mults using constant PT vectors).
				// Noise is proportional to max(|scalar|) × B_fresh, not to plaintext L1-norm.
				scalar2S := make([]uint64, blockSize)
				scalarBS := make([]uint64, blockSize)
				for i := range blockSize {
					scalar2S[i] = (2 * S) % t
					scalarBS[i] = uint64(blockSize) % t
				}
				ctAlpha, err := eval.MulNew(ctBeta, scalar2S) // 2·S·β
				if err != nil {
					log.Fatalf("CF MulNew 2S*beta: %v", err)
				}
				ctTmp, err := eval.MulNew(ctBetaSq, scalarBS) // blockSize·β_sq
				if err != nil {
					log.Fatalf("CF MulNew BS*betaSq: %v", err)
				}
				if err := eval.Add(ctAlpha, ctTmp, ctAlpha); err != nil {
					log.Fatalf("CF Add: %v", err)
				}

				// Decrypt slot 0 and add public correction S2.
				decVec := make([]uint64, blockSize)
				encoder.Decode(dec.DecryptNew(ctAlpha), decVec)
				resultCF := (decVec[0] + S2) % t
				if resultCF == expected {
					cfPasses++
				}

				// ------ Std protocol ------
				// Encrypt packed [v_i] and compute self-product via MulRelin + RotAS.
				// blockSize slots are used; remaining slots in the plaintext stay zero.
				ptV := bgv.NewPlaintext(params, params.MaxLevel())
				encoder.Encode(vVec, ptV)
				ctV, _ := encryptor.EncryptNew(ptV)

				ctVsq, err := eval.MulRelinNew(ctV, ctV)
				if err != nil {
					log.Fatalf("MulRelinNew: %v", err)
				}
				// RotAS over blockSize slots only (steps 1..blockSize/2 = 4096).
				// Stopping at step < blockSize avoids the identity-doubling artifact
				// from rotating by N/2 in the two-row BGV structure.
				for step := 1; step < blockSize; step <<= 1 {
					rotated, _ := eval.RotateColumnsNew(ctVsq, step)
					eval.Add(ctVsq, rotated, ctVsq)
				}
				decStd := make([]uint64, blockSize)
				encoder.Decode(dec.DecryptNew(ctVsq), decStd)
				if decStd[0] == expected {
					stdPasses++
				}
			}

			maxA := float64(vMax - bj)
			fmt.Printf("  vMin=%5d vMax=%6d maxA=%6.0f  sumA=2^%.1f  noiseCF=2^%.1f noiseSt=2^%.1f  CF=%d/%d  Std=%d/%d\n",
				vMin, vMax, maxA, math.Log2(sumA), math.Log2(noiseCF+1), math.Log2(noiseStd+1),
				cfPasses, trials, stdPasses, trials)
		}
		fmt.Println()
	}
}

// noiseBudget returns log2(Q/(2t)) for the given BGV parameters.
func noiseBudget(params bgv.Parameters) float64 {
	logQ := 0.0
	for _, q := range params.Q() {
		logQ += math.Log2(float64(q))
	}
	return logQ - math.Log2(float64(params.PlaintextModulus())) - 1
}
