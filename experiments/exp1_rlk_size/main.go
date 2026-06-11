// exp1_rlk_size measures the serialized size of the collective relinearization key for
// each parameter profile and compares it to the per-query online-phase communication
// (CKS threshold-decryption shares). The goal is to determine whether the rlk-free
// advantage of CF labeling (UC4) is meaningful once setup cost is amortized over queries.
//
// Run: go run ./experiments/exp1_rlk_size/
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/juanmartin1892/lattigo-labeling/labeling"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const (
	logN             = 14
	plaintextModulus = uint64(0x3ee0001)
	nParties         = 2
)

type profile struct {
	name string
	logQ []int
	logP []int
}

var profiles = []profile{
	{"full", []int{56, 55, 55, 54}, []int{55, 55}},
	{"tight", []int{38, 37, 50, 50}, []int{50, 50}},
	{"min", []int{35, 35}, []int{35, 35}},
}

func main() {
	fmt.Println("=== Exp-1: RLK Size vs Online Phase Communication ===")
	fmt.Println()

	for _, p := range profiles {
		params, err := labeling.NewParametersFromLiteral(logN, p.logQ, p.logP, plaintextModulus)
		if err != nil {
			log.Printf("skip profile %s: %v", p.name, err)
			continue
		}

		maxLevel := params.MaxLevel()
		N := params.N()

		// Generate collective rlk.
		seed := []byte("exp1-rlk-size-seed-v1")
		crs, err := sampling.NewKeyedPRNG(seed)
		if err != nil {
			log.Fatalf("crs: %v", err)
		}

		sks := make([]*rlwe.SecretKey, nParties)
		for i := range sks {
			kgen := rlwe.NewKeyGenerator(params)
			sks[i], _ = kgen.GenKeyPairNew()
		}

		rlk, err := labeling.GenCollectiveRelinKey(params, sks, crs)
		if err != nil {
			log.Fatalf("GenCollectiveRelinKey: %v", err)
		}

		// Serialize rlk to measure its byte size.
		var buf bytes.Buffer
		n, err := rlk.WriteTo(&buf)
		if err != nil {
			log.Fatalf("rlk.WriteTo: %v", err)
		}
		rlkBytes := n

		// Collective public key size (also part of setup, but small).
		crs2, _ := sampling.NewKeyedPRNG(seed)
		ctx, err := labeling.NewMHEContext(params, sks, multiparty.CRS(crs2))
		if err != nil {
			log.Fatalf("NewMHEContext: %v", err)
		}
		var pkBuf bytes.Buffer
		pkN, _ := ctx.CollectivePK.WriteTo(&pkBuf)
		pkBytes := pkN

		// Online phase: CKS share size = 2 × N × (level+1) × 8 bytes (two ring.Poly at level ℓ).
		// Each party sends one share per decryption.
		shareAtMaxLevel := 2 * int64(N) * int64(maxLevel+1) * 8
		shareAtLevel1 := 2 * int64(N) * int64(2) * 8 // level=1 → 2 primes

		// For UC2/UC3: one share per query (both parties combined = 2 × share).
		onlineUC2MaxLevel := 2 * shareAtMaxLevel    // std (MaxLevel)
		onlineUC2Level1 := 2 * shareAtLevel1       // std_modsw / label (level=1)

		// For UC4 std: one share per query (single aggregated decrypt).
		onlineUC4Std := 2 * shareAtMaxLevel

		// For UC4 label_compact: 2 CKS shares per BLOCK (α_final + β_orig per block).
		// DB3 = 1 million values, blockSize = 8192 → numBlocks ≈ 1M / 8192 / 2 ≈ 61.
		// (divided by 2 for nParties split: each party contributes M=N/2 values → M/blockSize blocks)
		// Actually: numBlocks per party = ceil(N/(2*blockSize)), total = numBlocks per party * 2
		// For DB3 (N=1M): ceil(1M/(2*8192)) = ceil(61.04) = 62 blocks per party; each has β + α shares
		blocksDB3 := (1_000_000 + 2*8192 - 1) / (2 * 8192) // blocks per party
		totalBlocksDB3 := blocksDB3                          // one party processes its own blocks
		onlineUC4LabelDB3 := int64(totalBlocksDB3) * 2 * 2 * shareAtMaxLevel // 2 CKS per block × 2 parties

		// 2-round rlk generation: each party sends ~rlk_size bytes per round, 2 rounds.
		rlkSetupComm := int64(nParties) * 2 * rlkBytes

		fmt.Printf("Profile: %s  (MaxLevel=%d, N=%d)\n", p.name, maxLevel, N)
		fmt.Printf("  Collective PK size:         %10.1f KB  (one-time setup)\n", float64(pkBytes)/1024)
		fmt.Printf("  Collective RLK size:        %10.1f MB  (one-time setup)\n", float64(rlkBytes)/1e6)
		fmt.Printf("  RLK 2-round setup comm:     %10.1f MB  (std needs this; label_compact does NOT)\n", float64(rlkSetupComm)/1e6)
		fmt.Println()
		fmt.Printf("  --- Online phase (per query) ---\n")
		fmt.Printf("  UC2/UC3 std (MaxLevel):     %10.1f MB\n", float64(onlineUC2MaxLevel)/1e6)
		fmt.Printf("  UC2/UC3 std_modsw/label:    %10.1f MB  (level=1, same bytes)\n", float64(onlineUC2Level1)/1e6)
		fmt.Printf("  UC4 std (MaxLevel):         %10.1f MB\n", float64(onlineUC4Std)/1e6)
		fmt.Printf("  UC4 label_compact (DB3):    %10.1f MB  (%d blocks × 2 CKS × 2 parties)\n",
			float64(onlineUC4LabelDB3)/1e6, totalBlocksDB3)
		fmt.Println()

		// Break-even: after how many queries is rlk setup amortized?
		// For UC2/UC3: std and label have SAME online cost (at equal level).
		// For UC4: label_compact saves rlk setup comm but pays onlineUC4LabelDB3 vs onlineUC4Std.
		// Never a break-even for UC4 DB3: label is always more expensive online (+overhead) AND
		// saves setup rlkSetupComm one time. Break-even Q s.t.: Q × (label_online - std_online) = rlk_setup
		// → Q = rlk_setup / (label_online - std_online) — label pays MORE online, so break-even doesn't exist.
		labelOnlineExtraDB3 := onlineUC4LabelDB3 - onlineUC4Std
		if labelOnlineExtraDB3 > 0 {
			breakevenFloat := float64(rlkSetupComm) / float64(labelOnlineExtraDB3)
			fmt.Printf("  UC4 DB3: label_compact costs +%.1f MB/query MORE than std\n",
				float64(labelOnlineExtraDB3)/1e6)
			fmt.Printf("  Break-even queries (label savings ≥ extra online):  %.2f queries\n", breakevenFloat)
			fmt.Printf("  → label_compact NEVER recoups rlk savings (break-even < 1 query)\n")
		}
		fmt.Println("---")
		fmt.Println()
	}
}
