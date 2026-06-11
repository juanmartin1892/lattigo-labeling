// exp3_noise_model derives the theoretical noise bounds for std vs CF labeling and
// determines analytically whether CF can ever outperform std in any parameter regime.
//
// Noise model (BGV, simplified):
//
//	B_fresh = σ × √N              (fresh RLWE ciphertext noise bound)
//	B_smudge = n × σ_smudge × √N (smudging noise per threshold decrypt)
//
//	std path (HMul + Relin + L rotate-and-sum):
//	  After MulRelin: B_mul ≈ B_fresh² × N (tensor product, then relin adds B_ks ≈ 0 for good P)
//	  After L rotate-and-sum: B_total_std ≈ 2^L × B_mul
//	  Smudge: B_smudge (single decrypt)
//	  Total: 2^L × B_fresh² × N + B_smudge
//
//	CF label path (Mult = MulRelin(β1×β2) + a1×β2 + a2×β1 + Enc(r)):
//	  After Mult: B_mul_cf ≈ B_fresh² × N  (from MulRelin β1×β2)
//	              + 2 × ||a||_∞ × B_fresh   (from scalar multiplications)
//	              + B_fresh                  (from Enc(r))
//	  After L rotate-and-sum: B_total_cf ≈ 2^L × (B_fresh² × N + 2×||a||_∞×B_fresh + B_fresh)
//	  Smudge: B_smudge
//	  Total: 2^L × (B_fresh² × N + (2||a||+1) × B_fresh) + B_smudge
//
// Note: CF label's Mult ALSO uses MulRelin for β1×β2, so UC2/UC3 label is ALWAYS noisier
// than std (by the extra 2×||a||_∞×B_fresh term). The "rlk-free" claim only holds for UC4
// (MultOverflowLabeledFree which uses scalar-CT multiplications only).
//
//	CF overflow path (UC4, no relin):
//	  After MultOverflow: α noise ≈ B_fresh           (from Enc(a1×a2))
//	                               + 2 × ||a||_∞ × B_fresh  (from a1×β2 + a2×β1)
//	  After L rotate-and-sum: 2^L × (1 + 2||a||) × B_fresh
//	  Smudge: 2 × B_smudge per block (α + β_orig CKS)
//
//	std UC4 (HMul + Relin):
//	  Same as std above: 2^L × B_fresh² × N + B_smudge
//
// Crossover condition (where CF overflow < std for UC4):
//   (1 + 2||a||) × B_fresh < B_fresh² × N
//   (1 + 2||a||) < B_fresh × N = σ × N^{3/2}
//   ||a|| < σ × N^{3/2} / 2
//
// For logN=14 (N=16384), σ=3.2: crossover when ||a|| < 3.2 × 16384^{3/2} / 2 ≈ 3.35 × 10^6
// This is >>t = 67M — so in practice, a_i can be up to t-1 and CF overflow is still noisier
// than std HMul for our parameters? Let's compute.
//
// Run: go run ./experiments/exp3_noise_model/
package main

import (
	"fmt"
	"math"
)

const (
	logN             = 14
	N                = 1 << logN    // 16384
	sigma            = 3.2          // rlwe.DefaultNoise
	sigmaSmudge      = 8 * sigma    // smudging noise sigma
	nParties         = 2
	logT             = 26           // t ≈ 2^26
	T                = uint64(0x3ee0001) // 66977793 ≈ 67M
	sqrtT            = 8184         // floor(√T)
	blockSize        = 8192
	L                = 13           // log2(blockSize) = 13 rotate-and-sum steps
	rotateSteps      = 1 << L       // 8192
)

type noiseResult struct {
	name         string
	noiseAfterMult  float64
	noiseAfterRotAS float64
	noiseSmudge     float64
	noiseTotal      float64
	budget          float64
	correct         bool
}

func computeNoise(name string, noiseMult float64, budget float64) noiseResult {
	noiseRotAS := float64(rotateSteps) * noiseMult
	noiseSmudge := float64(nParties) * sigmaSmudge * math.Sqrt(N)
	total := noiseRotAS + noiseSmudge
	return noiseResult{
		name:            name,
		noiseAfterMult:  noiseMult,
		noiseAfterRotAS: noiseRotAS,
		noiseSmudge:     noiseSmudge,
		noiseTotal:      total,
		budget:          budget,
		correct:         total < budget,
	}
}

func logBase2(x float64) float64 {
	if x <= 0 {
		return math.Inf(-1)
	}
	return math.Log2(x)
}

type paramProfile struct {
	name   string
	logQ   []int
	level1 bool // if true, decrypt at level=1; else decrypt at MaxLevel
}

// budgetAtLevel computes q_level/(2t) for a given list of LogQ primes.
// level 0 = first prime only, level k = product of first k+1 primes.
func budgetAtLevel(logQ []int, level int) float64 {
	sumLogQ := 0.0
	for i := 0; i <= level && i < len(logQ); i++ {
		sumLogQ += float64(logQ[i])
	}
	return math.Pow(2, sumLogQ) / (2.0 * float64(T))
}

func main() {
	fmt.Printf("=== Exp-3: Theoretical Noise Model — std vs CF labeling ===\n\n")
	fmt.Printf("Parameters: logN=%d, N=%d, σ=%.1f, σ_smudge=%.1f, n=%d, t=0x%x≈2^%d\n",
		logN, N, sigma, sigmaSmudge, nParties, T, logT)
	fmt.Printf("Rotate-and-sum: %d steps (blockSize=%d → noise×2^13 per decryption)\n\n",
		L, blockSize)

	bFresh := sigma * math.Sqrt(N)
	fmt.Printf("B_fresh = σ × √N = %.1f × %.1f = %.1f ≈ 2^%.1f\n",
		sigma, math.Sqrt(N), bFresh, logBase2(bFresh))
	fmt.Printf("Smudge noise per decrypt: n × σ_smudge × √N = %d × %.1f × %.1f = %.1f ≈ 2^%.1f\n\n",
		nParties, sigmaSmudge, math.Sqrt(N),
		float64(nParties)*sigmaSmudge*math.Sqrt(N),
		logBase2(float64(nParties)*sigmaSmudge*math.Sqrt(N)))

	// Noise after HMul + Relin (BGV tensor product).
	// B_mul_std ≈ B_fresh^2 × N (dominant term; B_relin << this for good P).
	bMulStd := bFresh * bFresh * N
	fmt.Printf("Std HMul noise:    B_fresh² × N = %.1f² × %d = %.2e ≈ 2^%.1f\n",
		bFresh, N, bMulStd, logBase2(bMulStd))

	// Noise after CF Mult (includes MulRelin PLUS scalar mults).
	// ||a||_inf = max value of a_i; depends on mask range and message range.
	aLarge := float64(T - 1) // worst case: a_i ≈ t-1 (full mod-t wrap)
	aSqrtT := float64(sqrtT) // as currently implemented: mask ∈ [0, √t], a_i can be ≈ t-1 (wrap)
	aOptimized := float64(1500) // if mask ∈ [0, 500], values ∈ [1,1000]: max a_i = 1000+500 = 1500
	aVerySmall := float64(20) // if values ∈ [1,10] and mask ∈ [0,10]

	// Note: in current implementation mask ∈ [0, √t] but a_i = (v_i - mask_i) mod t.
	// When mask_i > v_i, a_i wraps to ≈ t-1. So effective ||a||_inf is ≈ t-1.
	fmt.Printf("\n--- Mask impact on ||a||_∞ ---\n")
	fmt.Printf("Worst case (t-1 wrap):       ||a||_∞ ≈ %.2e ≈ 2^%.1f\n", aLarge, logBase2(aLarge))
	fmt.Printf("Current implementation (√t): ||a||_∞ ≈ %.2e ≈ 2^%.1f  [mask range [0,√t], values can exceed mask]\n", aSqrtT, logBase2(aSqrtT))
	fmt.Printf("Optimized (values [1,1000]):  ||a||_∞ ≈ %.2e ≈ 2^%.1f  [mask range [0,500], no wrap-around]\n", aOptimized, logBase2(aOptimized))
	fmt.Printf("Very small (values [1,10]):   ||a||_∞ ≈ %.2e ≈ 2^%.1f  [mask range [0,10]]\n", aVerySmall, logBase2(aVerySmall))

	computeCFMult := func(aInf float64) float64 {
		// B_mul_cf = B_mul_std (from MulRelin β1×β2) + 2×||a||_∞×B_fresh (scalar mults) + B_fresh (Enc(r))
		return bMulStd + 2*aInf*bFresh + bFresh
	}

	computeOverflowMult := func(aInf float64) float64 {
		// B_overflow = B_fresh (Enc(a1×a2)) + 2×||a||_∞×B_fresh (scalar mults a1β2 + a2β1)
		// No MulRelin β1×β2 (stays as [β1,β2] in elementsB)
		return bFresh + 2*aInf*bFresh
	}

	profiles := []struct {
		name     string
		logQ     []int
		maxLevel int
	}{
		{"full (LogQ≈220, MaxLevel=3)", []int{56, 55, 55, 54}, 3},
		{"tight (LogQ≈175, MaxLevel=3)", []int{38, 37, 50, 50}, 3},
		{"min (LogQ≈70, MaxLevel=1)", []int{35, 35}, 1},
	}

	aCases := []struct{ name string; aInf float64 }{
		{"current impl (wrap→t-1)", aLarge},
		{"current impl (√t mask)", aSqrtT},
		{"optimized (values [1,1000])", aOptimized},
		{"very small (values [1,10])", aVerySmall},
	}

	for _, prof := range profiles {
		fmt.Printf("\n═══ Profile: %s ═══\n", prof.name)
		budgetMaxLevel := budgetAtLevel(prof.logQ, prof.maxLevel)
		budgetLevel1 := budgetAtLevel(prof.logQ, 1)
		fmt.Printf("Budget at MaxLevel: 2^%.1f  |  Budget at level=1: 2^%.1f\n",
			logBase2(budgetMaxLevel), logBase2(budgetLevel1))

		// Std path.
		resStdMax := computeNoise("std (MaxLevel)", bMulStd, budgetMaxLevel)
		resStdL1 := computeNoise("std_modsw (level=1)", bMulStd, budgetLevel1)
		fmt.Printf("\n  std HMul noise after mult: 2^%.1f\n", logBase2(bMulStd))
		for _, r := range []noiseResult{resStdMax, resStdL1} {
			fmt.Printf("  %-32s total=2^%.1f  budget=2^%.1f  correct=%-5v\n",
				r.name, logBase2(r.noiseTotal), logBase2(r.budget), r.correct)
		}

		fmt.Println()
		fmt.Println("  CF Mult path (β1×β2 via MulRelin + scalar mults):")
		for _, ac := range aCases {
			bMulCF := computeCFMult(ac.aInf)
			rCFMax := computeNoise("label_max", bMulCF, budgetMaxLevel)
			rCFL1 := computeNoise("label (level=1)", bMulCF, budgetLevel1)
			fmt.Printf("  [%s] ||a||=2^%.1f: mult_noise=2^%.1f\n",
				ac.name, logBase2(ac.aInf), logBase2(bMulCF))
			fmt.Printf("    %-25s total=2^%.1f  budget=2^%.1f  correct=%-5v\n",
				rCFMax.name, logBase2(rCFMax.noiseTotal), logBase2(rCFMax.budget), rCFMax.correct)
			fmt.Printf("    %-25s total=2^%.1f  budget=2^%.1f  correct=%-5v\n",
				rCFL1.name, logBase2(rCFL1.noiseTotal), logBase2(rCFL1.budget), rCFL1.correct)
		}

		fmt.Println()
		fmt.Println("  CF Overflow path (UC4, NO relin — only scalar mults):")
		for _, ac := range aCases {
			bOverflow := computeOverflowMult(ac.aInf)
			rOvMax := computeNoise("label_compact_max", bOverflow, budgetMaxLevel)
			rOvL1 := computeNoise("label_compact", bOverflow, budgetLevel1)
			fmt.Printf("  [%s] ||a||=2^%.1f: overflow_noise=2^%.1f  (NO relin, no B_fresh²×N)\n",
				ac.name, logBase2(ac.aInf), logBase2(bOverflow))
			fmt.Printf("    %-25s total=2^%.1f  budget=2^%.1f  correct=%-5v\n",
				rOvMax.name, logBase2(rOvMax.noiseTotal), logBase2(rOvMax.budget), rOvMax.correct)
			fmt.Printf("    %-25s total=2^%.1f  budget=2^%.1f  correct=%-5v\n",
				rOvL1.name, logBase2(rOvL1.noiseTotal), logBase2(rOvL1.budget), rOvL1.correct)
		}
	}

	// Crossover analysis: find ||a||_max where CF overflow < std.
	fmt.Println("\n═══ Crossover Analysis (UC4 overflow path) ═══")
	fmt.Printf("CF overflow noise < std HMul noise  when:\n")
	fmt.Printf("  (1 + 2||a||) × B_fresh < B_fresh² × N\n")
	fmt.Printf("  1 + 2||a|| < B_fresh × N = %.1f × %d = %.2e\n", bFresh, N, bFresh*N)
	crossover := (bFresh*N - 1) / 2
	fmt.Printf("  ||a|| < %.2e ≈ 2^%.1f\n", crossover, logBase2(crossover))
	fmt.Printf("\n  Current √t mask: ||a||_∞ can reach t-1 = %.2e ≈ 2^%.1f → %.v crossover\n",
		aLarge, logBase2(aLarge), aLarge < crossover)
	fmt.Printf("  Optimized [1,1000] values: ||a|| ≈ %.0f → %v crossover (CF ≈ %.1f× less noise)\n",
		aOptimized, aOptimized < crossover,
		bMulStd/(computeOverflowMult(aOptimized)))
	fmt.Printf("\n  For CF overflow to beat std, messages must be in [0, M] with M < %.2e\n", crossover/2)
	fmt.Printf("  (to guarantee mask size ~ M/2 and ||a|| < M)\n")
	fmt.Printf("\n  With N=16384, σ=3.2: B_fresh×N = %.2e ≈ 2^%.1f\n",
		bFresh*N, logBase2(bFresh*N))
	fmt.Printf("  Messages must be small enough that mask range < B_fresh×N/2 ≈ 2^%.1f\n",
		logBase2(bFresh*N/2))
	fmt.Printf("  This means messages bounded by ~2^%.1f (= %d) for CF overflow to beat std HMul\n",
		logBase2(bFresh*N/2), int(bFresh*N/2))
}
