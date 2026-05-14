package labeling

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// --- Spec 003: Threshold Decryption helpers ---

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

// mhe002CRSSeed is the fixed CRS seed shared by all simulated parties in spec 002 tests.
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
