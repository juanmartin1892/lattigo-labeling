package labeling

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

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
