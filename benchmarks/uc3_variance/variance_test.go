package main

import (
	"testing"

	"github.com/juanmartin1892/lattigo-labeling/benchmarks/internal/harness"
)

const testModulus = uint64(0x3ee0001)

// TestExpectedSumAndSumSq verifies the helper that computes expected values for UC3.
func TestExpectedSumAndSumSq(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		values      []uint64
		wantSum     uint64
		wantSumSq   uint64
	}{
		{
			name:      "small_values",
			values:    []uint64{1, 2, 3, 4},
			wantSum:   10,
			wantSumSq: 30, // 1+4+9+16
		},
		{
			name:      "single_value",
			values:    []uint64{5},
			wantSum:   5,
			wantSumSq: 25,
		},
		{
			name:      "zero_values",
			values:    []uint64{0, 0, 0},
			wantSum:   0,
			wantSumSq: 0,
		},
		{
			name:   "modular_reduction_sum",
			values: []uint64{testModulus - 1, 2},
			// sum = (t-1+2) mod t = 1
			wantSum: 1,
			// sumSq = (t-1)² mod t + 4 mod t = 1 + 4 = 5
			wantSumSq: 5,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ds := harness.Dataset{
				Values:          tc.values,
				N:               len(tc.values),
				PlaintextModulus: testModulus,
			}
			gotSum, gotSumSq := expectedSumAndSumSq(ds)
			if gotSum != tc.wantSum {
				t.Errorf("sum = %d, want %d", gotSum, tc.wantSum)
			}
			if gotSumSq != tc.wantSumSq {
				t.Errorf("sumSq = %d, want %d", gotSumSq, tc.wantSumSq)
			}
		})
	}
}

// TestBlocks verifies the SIMD block partitioning for UC3 (same as UC2).
func TestBlocks(t *testing.T) {
	t.Parallel()
	const maxSlots = 16

	t.Run("single_block_padded", func(t *testing.T) {
		t.Parallel()
		values := []uint64{1, 2, 3}
		result := blocks(values, maxSlots)
		if len(result) != 1 {
			t.Fatalf("K = %d, want 1", len(result))
		}
		if len(result[0]) != maxSlots {
			t.Errorf("block len = %d, want %d", len(result[0]), maxSlots)
		}
		// first 3 slots contain values, rest are zero
		for i, v := range values {
			if result[0][i] != v {
				t.Errorf("block[0][%d] = %d, want %d", i, result[0][i], v)
			}
		}
		for i := len(values); i < maxSlots; i++ {
			if result[0][i] != 0 {
				t.Errorf("padding slot %d = %d, want 0", i, result[0][i])
			}
		}
	})

	t.Run("two_blocks", func(t *testing.T) {
		t.Parallel()
		// half = maxSlots/2 = 8; values of size 10 → 2 blocks
		values := make([]uint64, 10)
		for i := range values {
			values[i] = uint64(i + 1)
		}
		result := blocks(values, maxSlots)
		if len(result) != 2 {
			t.Fatalf("K = %d, want 2", len(result))
		}
		// first block: values[0..7]
		for i := 0; i < 8; i++ {
			if result[0][i] != uint64(i+1) {
				t.Errorf("block[0][%d] = %d, want %d", i, result[0][i], i+1)
			}
		}
		// second block: values[8..9] then zeros
		if result[1][0] != 9 || result[1][1] != 10 {
			t.Errorf("block[1][0..1] = %d,%d, want 9,10", result[1][0], result[1][1])
		}
		for i := 2; i < maxSlots; i++ {
			if result[1][i] != 0 {
				t.Errorf("padding slot %d = %d, want 0", i, result[1][i])
			}
		}
	})

	t.Run("empty_produces_one_zero_block", func(t *testing.T) {
		t.Parallel()
		result := blocks(nil, maxSlots)
		if len(result) != 1 {
			t.Fatalf("K = %d, want 1", len(result))
		}
		for i, v := range result[0] {
			if v != 0 {
				t.Errorf("slot %d = %d, want 0", i, v)
			}
		}
	})
}

// TestVarUnnorm verifies the unnormalized variance formula N×sum_sq − sum².
func TestVarUnnorm(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		n       int
		sum     uint64
		sumSq   uint64
		want    uint64
		modulus uint64
	}{
		{
			// values=[1,2,3,4]: sum=10, sumSq=30, N=4
			// N×sumSq - sum² = 4×30 - 100 = 120 - 100 = 20
			name: "simple", n: 4, sum: 10, sumSq: 30, want: 20, modulus: testModulus,
		},
		{
			// values=[2,2]: sum=4, sumSq=8, N=2
			// N×sumSq - sum² = 2×8 - 16 = 16 - 16 = 0 → zero variance
			name: "zero_variance", n: 2, sum: 4, sumSq: 8, want: 0, modulus: testModulus,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := varUnnorm(tc.n, tc.sum, tc.sumSq, tc.modulus)
			if got != tc.want {
				t.Errorf("varUnnorm = %d, want %d", got, tc.want)
			}
		})
	}
}
