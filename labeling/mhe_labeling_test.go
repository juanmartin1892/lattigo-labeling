package labeling

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// --- Homomorphic operations helpers (spec 004) ---

// mheRLKCRSSeed is the fixed CRS seed for collective relinearization key generation
// tests. Kept separate from mhe002CRSSeed so PKGen and RLK gen each consume an
// independent PRNG stream.
var mheRLKCRSSeed = []byte("mhe-rlk-test-crs-seed")

func newMHERLKCRS(t *testing.T) multiparty.CRS {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG(mheRLKCRSSeed)
	if err != nil {
		t.Fatalf("sampling.NewKeyedPRNG: %v", err)
	}
	return crs
}

// buildMHESetupWithRLK extends buildMHETestSetup by also generating the collective
// relinearization key required by MultLabeled.
func buildMHESetupWithRLK(t *testing.T, params Parameters, n int) (MHEContext, []*rlwe.SecretKey, *rlwe.SecretKey, *rlwe.RelinearizationKey) {
	t.Helper()
	ctx, shares, skIdeal := buildMHETestSetup(t, params, n)
	rlk, err := GenCollectiveRelinKey(params, shares, newMHERLKCRS(t))
	if err != nil {
		t.Fatalf("GenCollectiveRelinKey: %v", err)
	}
	return ctx, shares, skIdeal, rlk
}

// decryptThreshold is a convenience wrapper that runs the full N-of-N decryption
// protocol on lct and returns the recovered plaintext slots.
func decryptThreshold(t *testing.T, ctx MHEContext, shares []*rlwe.SecretKey, lct PlaintextLabeledciphertext) []uint64 {
	t.Helper()
	combined := genThresholdDecryption(t, ctx, shares, lct)
	result, err := DecryptThresholdLabeled(ctx, combined, lct)
	if err != nil {
		t.Fatalf("DecryptThresholdLabeled: %v", err)
	}
	return result
}

// TestGenCollectiveRelinKey verifies collective relinearization key generation
// for various party counts and error conditions (spec 004).
func TestGenCollectiveRelinKey(t *testing.T) {
	params := testParameters(t)

	t.Run("HappyPath", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
		}{
			{name: "N=2", nParties: 2},
			{name: "N=3", nParties: 3},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, shares, _ := buildMHETestSetup(t, params, tc.nParties)
				rlk, err := GenCollectiveRelinKey(params, shares, newMHERLKCRS(t))
				if err != nil {
					t.Fatalf("GenCollectiveRelinKey: %v", err)
				}
				if rlk == nil {
					t.Fatal("returned rlk must not be nil")
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		kgen := rlwe.NewKeyGenerator(params)
		validSK := kgen.GenSecretKeyNew()
		validCRS := newMHERLKCRS(t)

		cases := []struct {
			name     string
			skShares []*rlwe.SecretKey
			crs      multiparty.CRS
		}{
			{
				name:     "empty_skShares",
				skShares: []*rlwe.SecretKey{},
				crs:      validCRS,
			},
			{
				name:     "nil_skShares",
				skShares: nil,
				crs:      validCRS,
			},
			{
				name:     "nil_sk_at_index_0",
				skShares: []*rlwe.SecretKey{nil},
				crs:      validCRS,
			},
			{
				name:     "nil_sk_at_index_1",
				skShares: []*rlwe.SecretKey{validSK, nil},
				crs:      validCRS,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := GenCollectiveRelinKey(params, tc.skShares, tc.crs)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestSumLabeled verifies SumLabeled round-trips and error conditions (spec 004).
func TestSumLabeled(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()

	t.Run("RoundTrip", func(t *testing.T) {
		cases := []struct {
			name   string
			v1, v2 uint64
			want   uint64
		}{
			{name: "3+4=7", v1: 3, v2: 4, want: 7},
			{name: "0+0=0", v1: 0, v2: 0, want: 0},
			{name: "(PT-1)+1=0", v1: pt - 1, v2: 1, want: 0},
			{name: "10+20=30", v1: 10, v2: 20, want: 30},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _ := buildMHETestSetup(t, params, 2)

				lct1, err := EncryptLabeled(ctx, fillSlots(params, tc.v1))
				if err != nil {
					t.Fatalf("EncryptLabeled lct1: %v", err)
				}
				lct2, err := EncryptLabeled(ctx, fillSlots(params, tc.v2))
				if err != nil {
					t.Fatalf("EncryptLabeled lct2: %v", err)
				}

				sum, err := SumLabeled(ctx, lct1, lct2)
				if err != nil {
					t.Fatalf("SumLabeled: %v", err)
				}

				got := decryptThreshold(t, ctx, shares, sum)
				for i, v := range got {
					if v != tc.want {
						t.Errorf("slot %d: got %d, want %d", i, v, tc.want)
					}
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _ := buildMHETestSetup(t, params, 2)
		validLct, err := EncryptLabeled(ctx, fillSlots(params, 1))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}

		cases := []struct {
			name string
			lct1 PlaintextLabeledciphertext
			lct2 PlaintextLabeledciphertext
		}{
			{name: "empty_lct1", lct1: PlaintextLabeledciphertext{}, lct2: validLct},
			{name: "empty_lct2", lct1: validLct, lct2: PlaintextLabeledciphertext{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := SumLabeled(ctx, tc.lct1, tc.lct2)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestMultLabeled verifies MultLabeled round-trips and error conditions (spec 004).
func TestMultLabeled(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()

	t.Run("RoundTrip", func(t *testing.T) {
		cases := []struct {
			name   string
			v1, v2 uint64
			want   uint64
		}{
			{name: "3x4=12", v1: 3, v2: 4, want: 12},
			{name: "1x0=0", v1: 1, v2: 0, want: 0},
			{name: "7x8=56", v1: 7, v2: 8, want: 56},
			{name: "(PT-1)x2", v1: pt - 1, v2: 2, want: (pt - 1) * 2 % pt},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 2)

				lct1, err := EncryptLabeled(ctx, fillSlots(params, tc.v1))
				if err != nil {
					t.Fatalf("EncryptLabeled lct1: %v", err)
				}
				lct2, err := EncryptLabeled(ctx, fillSlots(params, tc.v2))
				if err != nil {
					t.Fatalf("EncryptLabeled lct2: %v", err)
				}

				prod, err := MultLabeled(ctx, rlk, lct1, lct2)
				if err != nil {
					t.Fatalf("MultLabeled: %v", err)
				}

				got := decryptThreshold(t, ctx, shares, prod)
				for i, v := range got {
					if v != tc.want {
						t.Errorf("slot %d: got %d, want %d", i, v, tc.want)
					}
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _, rlk := buildMHESetupWithRLK(t, params, 2)
		validLct, err := EncryptLabeled(ctx, fillSlots(params, 3))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}

		cases := []struct {
			name string
			rlk  *rlwe.RelinearizationKey
			lct1 PlaintextLabeledciphertext
			lct2 PlaintextLabeledciphertext
		}{
			{name: "nil_rlk", rlk: nil, lct1: validLct, lct2: validLct},
			{name: "empty_lct1", rlk: rlk, lct1: PlaintextLabeledciphertext{}, lct2: validLct},
			{name: "empty_lct2", rlk: rlk, lct1: validLct, lct2: PlaintextLabeledciphertext{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := MultLabeled(ctx, tc.rlk, tc.lct1, tc.lct2)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestSumLabeledCommutativity verifies that SumLabeled(a, b) and SumLabeled(b, a)
// decrypt to the same result (spec 004).
func TestSumLabeledCommutativity(t *testing.T) {
	params := testParameters(t)
	ctx, shares, _ := buildMHETestSetup(t, params, 2)

	lct1, err := EncryptLabeled(ctx, fillSlots(params, 13))
	if err != nil {
		t.Fatalf("EncryptLabeled lct1: %v", err)
	}
	lct2, err := EncryptLabeled(ctx, fillSlots(params, 29))
	if err != nil {
		t.Fatalf("EncryptLabeled lct2: %v", err)
	}

	sum12, err := SumLabeled(ctx, lct1, lct2)
	if err != nil {
		t.Fatalf("SumLabeled(lct1,lct2): %v", err)
	}
	sum21, err := SumLabeled(ctx, lct2, lct1)
	if err != nil {
		t.Fatalf("SumLabeled(lct2,lct1): %v", err)
	}

	got12 := decryptThreshold(t, ctx, shares, sum12)
	got21 := decryptThreshold(t, ctx, shares, sum21)

	for i := range got12 {
		if got12[i] != got21[i] {
			t.Errorf("slot %d: Sum(a,b)=%d != Sum(b,a)=%d", i, got12[i], got21[i])
		}
		if got12[i] != 42 {
			t.Errorf("slot %d: got %d, want 42", i, got12[i])
		}
	}
}

// TestMHEHomomorphicOpsN3 verifies SumLabeled and MultLabeled with three parties
// to confirm the collective key protocol scales correctly (spec 004).
func TestMHEHomomorphicOpsN3(t *testing.T) {
	params := testParameters(t)

	t.Run("Sum", func(t *testing.T) {
		ctx, shares, _ := buildMHETestSetup(t, params, 3)

		lct1, err := EncryptLabeled(ctx, fillSlots(params, 5))
		if err != nil {
			t.Fatalf("EncryptLabeled lct1: %v", err)
		}
		lct2, err := EncryptLabeled(ctx, fillSlots(params, 6))
		if err != nil {
			t.Fatalf("EncryptLabeled lct2: %v", err)
		}

		sum, err := SumLabeled(ctx, lct1, lct2)
		if err != nil {
			t.Fatalf("SumLabeled: %v", err)
		}

		got := decryptThreshold(t, ctx, shares, sum)
		for i, v := range got {
			if v != 11 {
				t.Errorf("slot %d: got %d, want 11", i, v)
			}
		}
	})

	t.Run("Mult", func(t *testing.T) {
		ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 3)

		lct1, err := EncryptLabeled(ctx, fillSlots(params, 5))
		if err != nil {
			t.Fatalf("EncryptLabeled lct1: %v", err)
		}
		lct2, err := EncryptLabeled(ctx, fillSlots(params, 6))
		if err != nil {
			t.Fatalf("EncryptLabeled lct2: %v", err)
		}

		prod, err := MultLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultLabeled: %v", err)
		}

		got := decryptThreshold(t, ctx, shares, prod)
		for i, v := range got {
			if v != 30 {
				t.Errorf("slot %d: got %d, want 30", i, v)
			}
		}
	})
}

// --- Threshold Decryption helpers ---

// genThresholdDecryption simulates the full N-of-N CKS protocol in a single process:
// each party generates a share, then all shares are aggregated and returned.
// This is a test helper only; in production each party runs in a separate process.
func genThresholdDecryption(t *testing.T, ctx MHEContext, skShares []*rlwe.SecretKey, lct PlaintextLabeledciphertext) LabeledDecryptionShare {
	t.Helper()
	shares := make([]LabeledDecryptionShare, len(skShares))
	for i, sk := range skShares {
		s, err := GenLabeledDecryptionShare(ctx, sk, lct)
		if err != nil {
			t.Fatalf("GenLabeledDecryptionShare[%d]: %v", i, err)
		}
		shares[i] = s
	}
	combined, err := AggregateLabeledDecryptionShares(ctx, shares)
	if err != nil {
		t.Fatalf("AggregateLabeledDecryptionShares: %v", err)
	}
	return combined
}

// mhe002CRSSeed is the fixed CRS seed for public key generation tests.
var mhe002CRSSeed = []byte("mhe-002-test-crs-seed")

func newMHE002CRS(t *testing.T) multiparty.CRS {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG(mhe002CRSSeed)
	if err != nil {
		t.Fatalf("sampling.NewKeyedPRNG: %v", err)
	}
	return crs
}

// buildMHETestSetup generates n secret key shares, derives the ideal secret key
// (sum of shares), builds an MHEContext via NewMHEContext, and returns all three.
// skIdeal is used only as a test oracle — it is never part of production code.
func buildMHETestSetup(t *testing.T, params Parameters, n int) (MHEContext, []*rlwe.SecretKey, *rlwe.SecretKey) {
	t.Helper()
	kgen := rlwe.NewKeyGenerator(params)
	shares := make([]*rlwe.SecretKey, n)
	skIdeal := rlwe.NewSecretKey(params)
	for i := range shares {
		shares[i] = kgen.GenSecretKeyNew()
		params.RingQP().Add(skIdeal.Value, shares[i].Value, skIdeal.Value)
	}
	ctx, err := NewMHEContext(params, shares, newMHE002CRS(t))
	if err != nil {
		t.Fatalf("NewMHEContext: %v", err)
	}
	return ctx, shares, skIdeal
}

// fillSlots returns a slice of length params.MaxSlots() with every element set to v.
func fillSlots(params Parameters, v uint64) []uint64 {
	s := make([]uint64, params.MaxSlots())
	for i := range s {
		s[i] = v
	}
	return s
}

// TestMHEContextCreation verifies NewMHEContext happy paths and error paths.
func TestMHEContextCreation(t *testing.T) {
	params := testParameters(t)

	t.Run("HappyPath", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
		}{
			{name: "N=1", nParties: 1},
			{name: "N=2", nParties: 2},
			{name: "N=3", nParties: 3},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, _, _ := buildMHETestSetup(t, params, tc.nParties)
				if ctx.CollectivePK == nil {
					t.Fatal("CollectivePK must not be nil")
				}
				if ctx.Params.PlaintextModulus() != params.PlaintextModulus() {
					t.Errorf("Params.PlaintextModulus: got %d, want %d",
						ctx.Params.PlaintextModulus(), params.PlaintextModulus())
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		kgen := rlwe.NewKeyGenerator(params)
		validSK := kgen.GenSecretKeyNew()
		validCRS := newMHE002CRS(t)

		cases := []struct {
			name     string
			skShares []*rlwe.SecretKey
			crs      multiparty.CRS
		}{
			{
				name:     "nil_crs",
				skShares: []*rlwe.SecretKey{validSK},
				crs:      nil,
			},
			{
				name:     "nil_skShares",
				skShares: nil,
				crs:      validCRS,
			},
			{
				name:     "empty_skShares",
				skShares: []*rlwe.SecretKey{},
				crs:      validCRS,
			},
			{
				name:     "nil_sk_at_index_0",
				skShares: []*rlwe.SecretKey{nil},
				crs:      validCRS,
			},
			{
				name:     "nil_sk_at_index_1",
				skShares: []*rlwe.SecretKey{validSK, nil},
				crs:      validCRS,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewMHEContext(params, tc.skShares, tc.crs)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestGenLabeledDecryptionShare verifies GenLabeledDecryptionShare happy paths and errors.
func TestGenLabeledDecryptionShare(t *testing.T) {
	params := testParameters(t)

	t.Run("HappyPath", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
		}{
			{name: "N=1", nParties: 1},
			{name: "N=2", nParties: 2},
			{name: "N=3", nParties: 3},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _ := buildMHETestSetup(t, params, tc.nParties)
				lct, err := EncryptLabeled(ctx, fillSlots(params, 7))
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}
				_, err = GenLabeledDecryptionShare(ctx, shares[0], lct)
				if err != nil {
					t.Fatalf("GenLabeledDecryptionShare: %v", err)
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _ := buildMHETestSetup(t, params, 2)
		validLct, err := EncryptLabeled(ctx, fillSlots(params, 7))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}

		cases := []struct {
			name string
			sk   *rlwe.SecretKey
			lct  PlaintextLabeledciphertext
		}{
			{
				name: "nil_sk",
				sk:   nil,
				lct:  validLct,
			},
			{
				name: "empty_lct",
				sk:   rlwe.NewKeyGenerator(params).GenSecretKeyNew(),
				lct:  PlaintextLabeledciphertext{},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := GenLabeledDecryptionShare(ctx, tc.sk, tc.lct)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestAggregateLabeledDecryptionShares verifies share aggregation happy paths and errors.
func TestAggregateLabeledDecryptionShares(t *testing.T) {
	params := testParameters(t)

	t.Run("HappyPath", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
		}{
			{name: "N=1", nParties: 1},
			{name: "N=2", nParties: 2},
			{name: "N=3", nParties: 3},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _ := buildMHETestSetup(t, params, tc.nParties)
				lct, err := EncryptLabeled(ctx, fillSlots(params, 42))
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}
				decShares := make([]LabeledDecryptionShare, tc.nParties)
				for i, sk := range shares {
					decShares[i], err = GenLabeledDecryptionShare(ctx, sk, lct)
					if err != nil {
						t.Fatalf("GenLabeledDecryptionShare[%d]: %v", i, err)
					}
				}
				_, err = AggregateLabeledDecryptionShares(ctx, decShares)
				if err != nil {
					t.Fatalf("AggregateLabeledDecryptionShares: %v", err)
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _ := buildMHETestSetup(t, params, 2)
		cases := []struct {
			name   string
			shares []LabeledDecryptionShare
		}{
			{name: "nil_shares", shares: nil},
			{name: "empty_shares", shares: []LabeledDecryptionShare{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := AggregateLabeledDecryptionShares(ctx, tc.shares)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestDecryptThresholdLabeled verifies the full threshold decryption round-trip and errors.
func TestDecryptThresholdLabeled(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()

	t.Run("RoundTrip", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
			value    uint64
		}{
			{name: "N=1/value=7", nParties: 1, value: 7},
			{name: "N=2/value=7", nParties: 2, value: 7},
			{name: "N=2/value=0", nParties: 2, value: 0},
			{name: "N=2/value=PT-1", nParties: 2, value: pt - 1},
			{name: "N=3/value=42", nParties: 3, value: 42},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _ := buildMHETestSetup(t, params, tc.nParties)
				values := fillSlots(params, tc.value)

				lct, err := EncryptLabeled(ctx, values)
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}

				combined := genThresholdDecryption(t, ctx, shares, lct)

				got, err := DecryptThresholdLabeled(ctx, combined, lct)
				if err != nil {
					t.Fatalf("DecryptThresholdLabeled: %v", err)
				}
				for i, v := range got {
					if v != tc.value {
						t.Errorf("slot %d: got %d, want %d", i, v, tc.value)
					}
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, shares, _ := buildMHETestSetup(t, params, 2)
		validLct, err := EncryptLabeled(ctx, fillSlots(params, 1))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}
		combined := genThresholdDecryption(t, ctx, shares, validLct)

		_, err = DecryptThresholdLabeled(ctx, combined, PlaintextLabeledciphertext{})
		if err == nil {
			t.Fatal("expected error for empty lct, got nil")
		}
	})
}

// TestThresholdDecryptCommutativity verifies that share aggregation order does not affect
// the decryption result: Aggregate([s0,s1]) and Aggregate([s1,s0]) must decrypt identically.
func TestThresholdDecryptCommutativity(t *testing.T) {
	params := testParameters(t)
	ctx, shares, _ := buildMHETestSetup(t, params, 2)
	values := fillSlots(params, 77)

	lct, err := EncryptLabeled(ctx, values)
	if err != nil {
		t.Fatalf("EncryptLabeled: %v", err)
	}

	s0, err := GenLabeledDecryptionShare(ctx, shares[0], lct)
	if err != nil {
		t.Fatalf("GenLabeledDecryptionShare[0]: %v", err)
	}
	s1, err := GenLabeledDecryptionShare(ctx, shares[1], lct)
	if err != nil {
		t.Fatalf("GenLabeledDecryptionShare[1]: %v", err)
	}

	combined01, err := AggregateLabeledDecryptionShares(ctx, []LabeledDecryptionShare{s0, s1})
	if err != nil {
		t.Fatalf("Aggregate [s0,s1]: %v", err)
	}
	combined10, err := AggregateLabeledDecryptionShares(ctx, []LabeledDecryptionShare{s1, s0})
	if err != nil {
		t.Fatalf("Aggregate [s1,s0]: %v", err)
	}

	got01, err := DecryptThresholdLabeled(ctx, combined01, lct)
	if err != nil {
		t.Fatalf("DecryptThresholdLabeled [s0,s1]: %v", err)
	}
	got10, err := DecryptThresholdLabeled(ctx, combined10, lct)
	if err != nil {
		t.Fatalf("DecryptThresholdLabeled [s1,s0]: %v", err)
	}

	for i := range got01 {
		if got01[i] != got10[i] {
			t.Errorf("slot %d: results differ with different aggregate order: got01=%d, got10=%d",
				i, got01[i], got10[i])
		}
		if got01[i] != values[i] {
			t.Errorf("slot %d: got %d, want %d", i, got01[i], values[i])
		}
	}
}

// TestEncryptLabeled verifies EncryptLabeled round-trips, randomness, and the
// collective-key security property (individual sk cannot decrypt).
func TestEncryptLabeled(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()

	t.Run("RoundTrip", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
			value    uint64
		}{
			{name: "N=2/value=7", nParties: 2, value: 7},
			{name: "N=2/value=0", nParties: 2, value: 0},
			{name: "N=2/value=PT-1", nParties: 2, value: pt - 1},
			{name: "N=1/value=42", nParties: 1, value: 42},
			{name: "N=3/value=100", nParties: 3, value: 100},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, _, skIdeal := buildMHETestSetup(t, params, tc.nParties)
				values := fillSlots(params, tc.value)

				lct, err := EncryptLabeled(ctx, values)
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}

				got, err := Decrypt(params, skIdeal, lct)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}

				for i, v := range got {
					if v != tc.value {
						t.Errorf("slot %d: got %d, want %d", i, v, tc.value)
					}
				}
			})
		}
	})

	t.Run("Randomness", func(t *testing.T) {
		// Two calls with the same plaintext must produce different elementsA (independent masks).
		ctx, _, _ := buildMHETestSetup(t, params, 2)
		values := fillSlots(params, 42)

		lct1, err := EncryptLabeled(ctx, values)
		if err != nil {
			t.Fatalf("EncryptLabeled first call: %v", err)
		}
		lct2, err := EncryptLabeled(ctx, values)
		if err != nil {
			t.Fatalf("EncryptLabeled second call: %v", err)
		}

		same := true
		for i := range lct1.elementsA {
			if lct1.elementsA[i] != lct2.elementsA[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("two EncryptLabeled calls with the same input produced identical elementsA; masks must be independently random")
		}
	})

	t.Run("NegativeVerification", func(t *testing.T) {
		// A ciphertext encrypted under the collective pk (sk1+sk2) is not decryptable
		// by sk1 alone. Decrypt(sk1, lct) returns garbled values ≠ original with
		// probability ≈ 1 − 1/PT ≈ 1 − 1/65537. We use value=42 (far from 0) to
		// make an accidental collision negligible.
		ctx, shares, _ := buildMHETestSetup(t, params, 2)
		values := fillSlots(params, 42)

		lct, err := EncryptLabeled(ctx, values)
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}

		wrongDec, err := Decrypt(params, shares[0], lct)
		if err != nil {
			t.Fatalf("Decrypt with individual sk: %v", err)
		}

		// At least slot 0 must differ from the original value.
		if wrongDec[0] == 42 {
			t.Error("Decrypt with individual sk1 returned the correct value; collective public key property violated")
		}
	})
}

// --- Spec 005: Overflow Operations ---

// decryptOverflowOracle runs DecryptOverflow(skIdeal, clct) and fails the test on error.
// skIdeal is assembled only in the test context; production code never assembles it.
func decryptOverflowOracle(t *testing.T, params Parameters, skIdeal *rlwe.SecretKey, clct CiphertextLabeledciphertext) []uint64 {
	t.Helper()
	got, err := DecryptOverflow(params, skIdeal, clct)
	if err != nil {
		t.Fatalf("DecryptOverflow: %v", err)
	}
	return got
}

// TestMultOverflowLabeled verifies MultOverflowLabeled round-trips and error conditions.
func TestMultOverflowLabeled(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()

	t.Run("RoundTrip", func(t *testing.T) {
		cases := []struct {
			name   string
			m1, m2 uint64
			want   uint64
		}{
			{name: "3x4", m1: 3, m2: 4, want: 12},
			{name: "1x0", m1: 1, m2: 0, want: 0},
			{name: "(PT-1)x2", m1: pt - 1, m2: 2, want: (pt - 1) * 2 % pt},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, _, skIdeal, rlk := buildMHESetupWithRLK(t, params, 2)

				lct1, err := EncryptLabeled(ctx, fillSlots(params, tc.m1))
				if err != nil {
					t.Fatalf("EncryptLabeled lct1: %v", err)
				}
				lct2, err := EncryptLabeled(ctx, fillSlots(params, tc.m2))
				if err != nil {
					t.Fatalf("EncryptLabeled lct2: %v", err)
				}

				clct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
				if err != nil {
					t.Fatalf("MultOverflowLabeled: %v", err)
				}

				got := decryptOverflowOracle(t, params, skIdeal, clct)
				for i, v := range got {
					if v != tc.want {
						t.Errorf("slot %d: got %d, want %d", i, v, tc.want)
					}
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _, rlk := buildMHESetupWithRLK(t, params, 2)
		validLct, err := EncryptLabeled(ctx, fillSlots(params, 3))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}
		emptyLct := PlaintextLabeledciphertext{}

		cases := []struct {
			name string
			rlk  *rlwe.RelinearizationKey
			lct1 PlaintextLabeledciphertext
			lct2 PlaintextLabeledciphertext
		}{
			{name: "nil_rlk", rlk: nil, lct1: validLct, lct2: validLct},
			{name: "empty_lct1", rlk: rlk, lct1: emptyLct, lct2: validLct},
			{name: "empty_lct2", rlk: rlk, lct1: validLct, lct2: emptyLct},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := MultOverflowLabeled(ctx, tc.rlk, tc.lct1, tc.lct2)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestSumOverflowLabeled verifies SumOverflowLabeled round-trips and error conditions.
func TestSumOverflowLabeled(t *testing.T) {
	params := testParameters(t)

	t.Run("RoundTrip", func(t *testing.T) {
		// MultOverflow([3],[4]) + SumOverflow([5]) → [3×4+5] = [17]
		ctx, _, skIdeal, rlk := buildMHESetupWithRLK(t, params, 2)

		lct1, err := EncryptLabeled(ctx, fillSlots(params, 3))
		if err != nil {
			t.Fatalf("EncryptLabeled lct1: %v", err)
		}
		lct2, err := EncryptLabeled(ctx, fillSlots(params, 4))
		if err != nil {
			t.Fatalf("EncryptLabeled lct2: %v", err)
		}
		lct3, err := EncryptLabeled(ctx, fillSlots(params, 5))
		if err != nil {
			t.Fatalf("EncryptLabeled lct3: %v", err)
		}

		clct12, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled: %v", err)
		}

		clctSum, err := SumOverflowLabeled(ctx, clct12, lct3)
		if err != nil {
			t.Fatalf("SumOverflowLabeled: %v", err)
		}

		got := decryptOverflowOracle(t, params, skIdeal, clctSum)
		for i, v := range got {
			if v != 17 {
				t.Errorf("slot %d: got %d, want 17", i, v)
			}
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _, rlk := buildMHESetupWithRLK(t, params, 2)
		validLct, err := EncryptLabeled(ctx, fillSlots(params, 5))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}
		lct2, err := EncryptLabeled(ctx, fillSlots(params, 4))
		if err != nil {
			t.Fatalf("EncryptLabeled lct2: %v", err)
		}
		validClct, err := MultOverflowLabeled(ctx, rlk, validLct, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled: %v", err)
		}

		emptyLct := PlaintextLabeledciphertext{}
		emptyClct := CiphertextLabeledciphertext{}

		cases := []struct {
			name string
			clct CiphertextLabeledciphertext
			lct  PlaintextLabeledciphertext
		}{
			{name: "empty_clct", clct: emptyClct, lct: validLct},
			{name: "empty_lct", clct: validClct, lct: emptyLct},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := SumOverflowLabeled(ctx, tc.clct, tc.lct)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestSumOverflowCiphertextLabeled verifies SumOverflowCiphertextLabeled round-trips and errors.
func TestSumOverflowCiphertextLabeled(t *testing.T) {
	params := testParameters(t)

	t.Run("RoundTrip", func(t *testing.T) {
		// MultOverflow([3],[4]) + MultOverflow([2],[5]) → SumOverflowCiphertext → [12+10] = [22]
		ctx, _, skIdeal, rlk := buildMHESetupWithRLK(t, params, 2)

		lct1, err := EncryptLabeled(ctx, fillSlots(params, 3))
		if err != nil {
			t.Fatalf("EncryptLabeled lct1: %v", err)
		}
		lct2, err := EncryptLabeled(ctx, fillSlots(params, 4))
		if err != nil {
			t.Fatalf("EncryptLabeled lct2: %v", err)
		}
		lct3, err := EncryptLabeled(ctx, fillSlots(params, 2))
		if err != nil {
			t.Fatalf("EncryptLabeled lct3: %v", err)
		}
		lct4, err := EncryptLabeled(ctx, fillSlots(params, 5))
		if err != nil {
			t.Fatalf("EncryptLabeled lct4: %v", err)
		}

		clct12, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled(3,4): %v", err)
		}
		clct34, err := MultOverflowLabeled(ctx, rlk, lct3, lct4)
		if err != nil {
			t.Fatalf("MultOverflowLabeled(2,5): %v", err)
		}

		clctSum, err := SumOverflowCiphertextLabeled(ctx, clct12, clct34)
		if err != nil {
			t.Fatalf("SumOverflowCiphertextLabeled: %v", err)
		}

		got := decryptOverflowOracle(t, params, skIdeal, clctSum)
		for i, v := range got {
			if v != 22 {
				t.Errorf("slot %d: got %d, want 22", i, v)
			}
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _, rlk := buildMHESetupWithRLK(t, params, 2)
		lctA, err := EncryptLabeled(ctx, fillSlots(params, 3))
		if err != nil {
			t.Fatalf("EncryptLabeled lctA: %v", err)
		}
		lctB, err := EncryptLabeled(ctx, fillSlots(params, 4))
		if err != nil {
			t.Fatalf("EncryptLabeled lctB: %v", err)
		}
		validClct, err := MultOverflowLabeled(ctx, rlk, lctA, lctB)
		if err != nil {
			t.Fatalf("MultOverflowLabeled: %v", err)
		}
		emptyClct := CiphertextLabeledciphertext{}

		cases := []struct {
			name  string
			clct1 CiphertextLabeledciphertext
			clct2 CiphertextLabeledciphertext
		}{
			{name: "empty_clct1", clct1: emptyClct, clct2: validClct},
			{name: "empty_clct2", clct1: validClct, clct2: emptyClct},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := SumOverflowCiphertextLabeled(ctx, tc.clct1, tc.clct2)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestOverflowOpsN3 verifies MultOverflowLabeled and SumOverflowLabeled with three parties.
func TestOverflowOpsN3(t *testing.T) {
	params := testParameters(t)
	ctx, _, skIdeal, rlk := buildMHESetupWithRLK(t, params, 3)

	lct1, err := EncryptLabeled(ctx, fillSlots(params, 6))
	if err != nil {
		t.Fatalf("EncryptLabeled lct1: %v", err)
	}
	lct2, err := EncryptLabeled(ctx, fillSlots(params, 7))
	if err != nil {
		t.Fatalf("EncryptLabeled lct2: %v", err)
	}
	lct3, err := EncryptLabeled(ctx, fillSlots(params, 2))
	if err != nil {
		t.Fatalf("EncryptLabeled lct3: %v", err)
	}

	// MultOverflow([6],[7]) = [42]
	clct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
	if err != nil {
		t.Fatalf("MultOverflowLabeled N=3: %v", err)
	}
	got := decryptOverflowOracle(t, params, skIdeal, clct)
	for i, v := range got {
		if v != 42 {
			t.Errorf("MultOverflowLabeled N=3: slot %d: got %d, want 42", i, v)
		}
	}

	// SumOverflow([42_clct], [2]) = [44]
	clctSum, err := SumOverflowLabeled(ctx, clct, lct3)
	if err != nil {
		t.Fatalf("SumOverflowLabeled N=3: %v", err)
	}
	got = decryptOverflowOracle(t, params, skIdeal, clctSum)
	for i, v := range got {
		if v != 44 {
			t.Errorf("SumOverflowLabeled N=3: slot %d: got %d, want 44", i, v)
		}
	}
}

// --- Spec 006: Threshold Decryption of Overflow Ciphertexts ---

// genOverflowThresholdDecryption simulates the full N-of-N CKS protocol for a
// CiphertextLabeledciphertext in a single process: each party generates an
// OverflowDecryptionShare, all shares are aggregated, and the combined share is returned.
// Production code runs each party's step in a separate process.
func genOverflowThresholdDecryption(t *testing.T, ctx MHEContext, skShares []*rlwe.SecretKey, clct CiphertextLabeledciphertext) OverflowDecryptionShare {
	t.Helper()
	shares := make([]OverflowDecryptionShare, len(skShares))
	for i, sk := range skShares {
		s, err := GenOverflowDecryptionShare(ctx, sk, clct)
		if err != nil {
			t.Fatalf("GenOverflowDecryptionShare[%d]: %v", i, err)
		}
		shares[i] = s
	}
	combined, err := AggregateOverflowDecryptionShares(ctx, shares)
	if err != nil {
		t.Fatalf("AggregateOverflowDecryptionShares: %v", err)
	}
	return combined
}

// TestGenOverflowDecryptionShare verifies GenOverflowDecryptionShare happy paths and errors.
func TestGenOverflowDecryptionShare(t *testing.T) {
	params := testParameters(t)

	t.Run("HappyPath", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
		}{
			{name: "N=1", nParties: 1},
			{name: "N=2", nParties: 2},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, tc.nParties)
				lct1, err := EncryptLabeled(ctx, fillSlots(params, 3))
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}
				lct2, err := EncryptLabeled(ctx, fillSlots(params, 4))
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}
				clct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
				if err != nil {
					t.Fatalf("MultOverflowLabeled: %v", err)
				}
				_, err = GenOverflowDecryptionShare(ctx, shares[0], clct)
				if err != nil {
					t.Fatalf("GenOverflowDecryptionShare: %v", err)
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _, rlk := buildMHESetupWithRLK(t, params, 2)
		lct1, err := EncryptLabeled(ctx, fillSlots(params, 3))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}
		lct2, err := EncryptLabeled(ctx, fillSlots(params, 4))
		if err != nil {
			t.Fatalf("EncryptLabeled: %v", err)
		}
		validClct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled: %v", err)
		}

		cases := []struct {
			name string
			sk   *rlwe.SecretKey
			clct CiphertextLabeledciphertext
		}{
			{name: "nil_sk", sk: nil, clct: validClct},
			{name: "empty_clct", sk: rlwe.NewKeyGenerator(params).GenSecretKeyNew(), clct: CiphertextLabeledciphertext{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := GenOverflowDecryptionShare(ctx, tc.sk, tc.clct)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestAggregateOverflowDecryptionShares verifies share aggregation happy paths and errors.
func TestAggregateOverflowDecryptionShares(t *testing.T) {
	params := testParameters(t)

	t.Run("HappyPath", func(t *testing.T) {
		cases := []struct {
			name     string
			nParties int
		}{
			{name: "N=2", nParties: 2},
			{name: "N=3", nParties: 3},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, tc.nParties)
				lct1, err := EncryptLabeled(ctx, fillSlots(params, 5))
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}
				lct2, err := EncryptLabeled(ctx, fillSlots(params, 6))
				if err != nil {
					t.Fatalf("EncryptLabeled: %v", err)
				}
				clct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
				if err != nil {
					t.Fatalf("MultOverflowLabeled: %v", err)
				}
				decShares := make([]OverflowDecryptionShare, tc.nParties)
				for i, sk := range shares {
					decShares[i], err = GenOverflowDecryptionShare(ctx, sk, clct)
					if err != nil {
						t.Fatalf("GenOverflowDecryptionShare[%d]: %v", i, err)
					}
				}
				_, err = AggregateOverflowDecryptionShares(ctx, decShares)
				if err != nil {
					t.Fatalf("AggregateOverflowDecryptionShares: %v", err)
				}
			})
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, _, _, _ := buildMHESetupWithRLK(t, params, 2)
		cases := []struct {
			name   string
			shares []OverflowDecryptionShare
		}{
			{name: "nil_shares", shares: nil},
			{name: "empty_shares", shares: []OverflowDecryptionShare{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := AggregateOverflowDecryptionShares(ctx, tc.shares)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			})
		}
	})
}

// TestDecryptThresholdOverflow verifies the full threshold decryption round-trip for
// CiphertextLabeledciphertexts produced by overflow operations.
func TestDecryptThresholdOverflow(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()

	t.Run("MultOnly", func(t *testing.T) {
		cases := []struct {
			name   string
			m1, m2 uint64
			want   uint64
		}{
			{name: "3x4=12", m1: 3, m2: 4, want: 12},
			{name: "1x0=0", m1: 1, m2: 0, want: 0},
			{name: "(PT-1)x2", m1: pt - 1, m2: 2, want: (pt - 1) * 2 % pt},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 2)
				lct1, err := EncryptLabeled(ctx, fillSlots(params, tc.m1))
				if err != nil {
					t.Fatalf("EncryptLabeled lct1: %v", err)
				}
				lct2, err := EncryptLabeled(ctx, fillSlots(params, tc.m2))
				if err != nil {
					t.Fatalf("EncryptLabeled lct2: %v", err)
				}
				clct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
				if err != nil {
					t.Fatalf("MultOverflowLabeled: %v", err)
				}
				combined := genOverflowThresholdDecryption(t, ctx, shares, clct)
				got, err := DecryptThresholdOverflow(ctx, combined, clct)
				if err != nil {
					t.Fatalf("DecryptThresholdOverflow: %v", err)
				}
				for i, v := range got {
					if v != tc.want {
						t.Errorf("slot %d: got %d, want %d", i, v, tc.want)
					}
				}
			})
		}
	})

	t.Run("WithSum", func(t *testing.T) {
		// MultOverflow([3],[4]) + SumOverflow([5]) → [17]
		ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 2)
		lct1, _ := EncryptLabeled(ctx, fillSlots(params, 3))
		lct2, _ := EncryptLabeled(ctx, fillSlots(params, 4))
		lct3, _ := EncryptLabeled(ctx, fillSlots(params, 5))

		clct12, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled: %v", err)
		}
		clctSum, err := SumOverflowLabeled(ctx, clct12, lct3)
		if err != nil {
			t.Fatalf("SumOverflowLabeled: %v", err)
		}
		combined := genOverflowThresholdDecryption(t, ctx, shares, clctSum)
		got, err := DecryptThresholdOverflow(ctx, combined, clctSum)
		if err != nil {
			t.Fatalf("DecryptThresholdOverflow: %v", err)
		}
		for i, v := range got {
			if v != 17 {
				t.Errorf("slot %d: got %d, want 17", i, v)
			}
		}
	})

	t.Run("SumOfMults", func(t *testing.T) {
		// MultOverflow([3],[4]) + MultOverflow([2],[5]) → SumOverflowCiphertext → [22]
		ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 2)
		lct1, _ := EncryptLabeled(ctx, fillSlots(params, 3))
		lct2, _ := EncryptLabeled(ctx, fillSlots(params, 4))
		lct3, _ := EncryptLabeled(ctx, fillSlots(params, 2))
		lct4, _ := EncryptLabeled(ctx, fillSlots(params, 5))

		clct12, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled(3,4): %v", err)
		}
		clct34, err := MultOverflowLabeled(ctx, rlk, lct3, lct4)
		if err != nil {
			t.Fatalf("MultOverflowLabeled(2,5): %v", err)
		}
		clctFinal, err := SumOverflowCiphertextLabeled(ctx, clct12, clct34)
		if err != nil {
			t.Fatalf("SumOverflowCiphertextLabeled: %v", err)
		}
		combined := genOverflowThresholdDecryption(t, ctx, shares, clctFinal)
		got, err := DecryptThresholdOverflow(ctx, combined, clctFinal)
		if err != nil {
			t.Fatalf("DecryptThresholdOverflow: %v", err)
		}
		for i, v := range got {
			if v != 22 {
				t.Errorf("slot %d: got %d, want 22", i, v)
			}
		}
	})

	t.Run("N3", func(t *testing.T) {
		// Three parties: MultOverflow([6],[7]) = [42]
		ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 3)
		lct1, _ := EncryptLabeled(ctx, fillSlots(params, 6))
		lct2, _ := EncryptLabeled(ctx, fillSlots(params, 7))

		clct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled N=3: %v", err)
		}
		combined := genOverflowThresholdDecryption(t, ctx, shares, clct)
		got, err := DecryptThresholdOverflow(ctx, combined, clct)
		if err != nil {
			t.Fatalf("DecryptThresholdOverflow N=3: %v", err)
		}
		for i, v := range got {
			if v != 42 {
				t.Errorf("slot %d: got %d, want 42", i, v)
			}
		}
	})

	t.Run("Consistency", func(t *testing.T) {
		// DecryptThresholdOverflow and DecryptOverflow(skIdeal) must agree.
		ctx, shares, skIdeal, rlk := buildMHESetupWithRLK(t, params, 2)
		lct1, _ := EncryptLabeled(ctx, fillSlots(params, 9))
		lct2, _ := EncryptLabeled(ctx, fillSlots(params, 7))

		clct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled: %v", err)
		}
		want, err := DecryptOverflow(params, skIdeal, clct)
		if err != nil {
			t.Fatalf("DecryptOverflow oracle: %v", err)
		}
		combined := genOverflowThresholdDecryption(t, ctx, shares, clct)
		got, err := DecryptThresholdOverflow(ctx, combined, clct)
		if err != nil {
			t.Fatalf("DecryptThresholdOverflow: %v", err)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("slot %d: threshold=%d, oracle=%d", i, got[i], want[i])
			}
		}
	})

	t.Run("Errors", func(t *testing.T) {
		ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 2)
		lct1, _ := EncryptLabeled(ctx, fillSlots(params, 1))
		lct2, _ := EncryptLabeled(ctx, fillSlots(params, 2))
		validClct, err := MultOverflowLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultOverflowLabeled: %v", err)
		}
		combined := genOverflowThresholdDecryption(t, ctx, shares, validClct)

		_, err = DecryptThresholdOverflow(ctx, combined, CiphertextLabeledciphertext{})
		if err == nil {
			t.Fatal("expected error for empty clct, got nil")
		}
	})
}
