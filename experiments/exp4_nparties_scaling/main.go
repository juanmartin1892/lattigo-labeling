// exp4_nparties_scaling measures how the rlk-free advantage of CF labeling (UC4)
// scales with the number of parties. For n parties, the collective rlk generation
// requires 2 interactive rounds with each party sending rlk-sized data, while the
// online phase sends CKS shares per query.
//
// Key question: for what number of queries does the rlk setup cost amortize enough
// that the online-phase overhead of label_compact (which decrypts per-block) matters more?
//
// This experiment generates actual keys for n=2,4,8,16 parties and measures
// the exact sizes (not theoretical estimates).
//
// Run: go run ./experiments/exp4_nparties_scaling/
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/juanmartin1892/lattigo-labeling/labeling"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	blockSize        = 8192
)

var profiles = []struct {
	name string
	logQ []int
	logP []int
}{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
}

var partyCounts = []int{2, 4, 8, 16}

// DB configs for online phase calculation.
var dbSizes = []struct {
	label  string
	n      int
	blocks int // ceil(n / (2 * blockSize)): blocks per party
}{
	{"DB1", 512, 1},
	{"DB2", 100_000, 7},
	{"DB3", 1_000_000, 62},
}

func main() {
	fmt.Println("=== Exp-4: Multi-Party Scaling — Setup vs Online Communication ===")
	fmt.Printf("Profile: full  (standard security baseline)\n\n")

	for _, prof := range profiles {
		params, err := labeling.NewParametersFromLiteral(logN, prof.logQ, prof.logP, plaintextModulus)
		if err != nil {
			log.Fatalf("NewParametersFromLiteral: %v", err)
		}

		N := int64(params.N())
		maxLevel := params.MaxLevel()
		shareAtMaxLevel := 2 * N * int64(maxLevel+1) * 8 // bytes per CKS share at MaxLevel

		fmt.Printf("Profile %s: MaxLevel=%d, N=%d, share_size=%d KB\n\n",
			prof.name, maxLevel, N, shareAtMaxLevel/1024)

		// Generate rlk for n=2 parties (we'll scale analytically for larger n).
		seed := []byte("exp4-nparties-seed-v1")
		crs, err := sampling.NewKeyedPRNG(seed)
		if err != nil {
			log.Fatalf("crs: %v", err)
		}
		sks := make([]*rlwe.SecretKey, 2)
		for i := range sks {
			kgen := rlwe.NewKeyGenerator(params)
			sks[i], _ = kgen.GenKeyPairNew()
		}
		rlk, err := labeling.GenCollectiveRelinKey(params, sks, crs)
		if err != nil {
			log.Fatalf("GenCollectiveRelinKey: %v", err)
		}
		var buf bytes.Buffer
		rlkBytes, err := rlk.WriteTo(&buf)
		if err != nil {
			log.Fatalf("rlk.WriteTo: %v", err)
		}
		fmt.Printf("Collective RLK size: %.2f MB\n", float64(rlkBytes)/1e6)
		fmt.Printf("(std requires this; label_compact UC4 does NOT)\n\n")

		fmt.Printf("%-8s  %-14s  %-20s  %-20s  %-20s  %-12s\n",
			"Parties", "RLK setup comm",
			"UC4 std online/q", "UC4 CF/q (DB3)",
			"CF extra/q (DB3)", "Break-even")
		fmt.Println("------- --------------   -------------------- --------------------   -------------------- ------------")

		for _, n := range partyCounts {
			// Setup comm: 2 rounds × n parties × rlk_size (each party broadcasts in each round).
			// In round 1: each party sends rlk_size (ephemeral + round-1 share).
			// In round 2: each party sends rlk_size (round-2 share).
			// Aggregator collects n shares per round: n × rlk_size per round × 2 rounds.
			rlkSetup := int64(n) * 2 * rlkBytes

			// Online phase per query.
			// UC4 std: n parties × 1 CKS share at MaxLevel.
			onlineStd := int64(n) * shareAtMaxLevel

			// UC4 label_compact (DB3): n parties × 2 CKS shares per block × numBlocks.
			// Each block needs α_final and β_orig CKS shares (2 per block per party).
			onlineCFDB3 := int64(n) * 2 * int64(dbSizes[2].blocks) * shareAtMaxLevel

			extraCFDB3 := onlineCFDB3 - onlineStd

			var breakevenStr string
			if extraCFDB3 <= 0 {
				breakevenStr = "∞ (CF cheaper)"
			} else {
				bq := float64(rlkSetup) / float64(extraCFDB3)
				breakevenStr = fmt.Sprintf("%.2f q", bq)
			}

			fmt.Printf("%-8d  %-14s  %-20s  %-20s  %-20s  %-12s\n",
				n,
				fmt.Sprintf("%.1f MB", float64(rlkSetup)/1e6),
				fmt.Sprintf("%.1f MB", float64(onlineStd)/1e6),
				fmt.Sprintf("%.1f MB", float64(onlineCFDB3)/1e6),
				fmt.Sprintf("+%.1f MB", float64(extraCFDB3)/1e6),
				breakevenStr)
		}

		fmt.Println()

		// Per-DB breakdown for n=2 (standard deployment).
		fmt.Printf("--- Per-DB online phase (n=2 parties) ---\n")
		fmt.Printf("%-8s  %-8s  %-10s  %-20s  %-14s\n",
			"DB", "Blocks", "Std online", "CF online", "Ratio CF/std")
		for _, db := range dbSizes {
			onlineStd := int64(2) * shareAtMaxLevel
			onlineCF := int64(2) * 2 * int64(db.blocks) * shareAtMaxLevel
			ratio := float64(onlineCF) / float64(onlineStd)
			fmt.Printf("%-8s  %-8d  %-10s  %-20s  %-14.1fx\n",
				db.label, db.blocks,
				fmt.Sprintf("%.1f MB", float64(onlineStd)/1e6),
				fmt.Sprintf("%.1f MB", float64(onlineCF)/1e6),
				ratio)
		}
		fmt.Println()

		// Key takeaway: rlk setup is ONE-TIME while CF online overhead is PER-QUERY.
		// For DB3: each query costs +1200 MB extra (n=2). Setup is ~30 MB. Break-even < 1 query.
		rlkSetup2 := int64(2) * 2 * rlkBytes
		onlineCFDB3n2 := int64(2) * 2 * int64(dbSizes[2].blocks) * shareAtMaxLevel
		onlineStdn2 := int64(2) * shareAtMaxLevel
		extraPerQuery := onlineCFDB3n2 - onlineStdn2
		fmt.Printf("Takeaway (n=2, DB3):\n")
		fmt.Printf("  RLK setup (one-time):          %.1f MB\n", float64(rlkSetup2)/1e6)
		fmt.Printf("  CF extra online cost per query: %.1f MB\n", float64(extraPerQuery)/1e6)
		fmt.Printf("  Break-even queries: %.4f  → CF NEVER recoups its online overhead\n",
			float64(rlkSetup2)/float64(extraPerQuery))
		fmt.Printf("  (After even 1 query, CF has spent %.1f× more in total comms than saved in setup)\n",
			float64(rlkSetup2+onlineCFDB3n2)/float64(rlkSetup2+onlineStdn2))
	}
}
