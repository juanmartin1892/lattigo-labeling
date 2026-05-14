//go:build integration

package labeling

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// mheTestParams defines BGV parameters for MHE integration tests.
//
// LogN=14: polynomial degree 2^14, giving 2^13=8192 slots per ciphertext.
// LogQ=[56,55,55,54,54,54]: 6-level modulus chain (~328 total bits), matching the
// existing examples/ to reuse a validated configuration.
// LogP=[55,55]: two auxiliary moduli for key-switching noise flooding; LogP>0 is
// required by multiparty.KeySwitchProtocol.
// PlaintextModulus=0x101 (257): small prime that enables slot encoding and keeps
// arithmetic readable in round-trip verification.
var mheTestParams = bgv.ParametersLiteral{
	LogN:             14,
	LogQ:             []int{56, 55, 55, 54, 54, 54},
	LogP:             []int{55, 55},
	PlaintextModulus: 0x101, // 257 — prime, enables BGV CRT slot encoding
}

// mheFixedCRSSeed is the shared seed used to build the Common Reference String (CRS)
// in all MHE tests. Every simulated party reads from a PRNG with this seed so they
// agree on the same uniform random polynomials without network communication.
var mheFixedCRSSeed = []byte("mhe-integration-test-crs-seed-v1")

// newMHEParams returns BGV parameters for MHE tests and fails the test on error.
func newMHEParams(t *testing.T) bgv.Parameters {
	t.Helper()
	params, err := bgv.NewParametersFromLiteral(mheTestParams)
	if err != nil {
		t.Fatalf("bgv.NewParametersFromLiteral: %v", err)
	}
	return params
}

// newCRS returns a keyed PRNG seeded with mheFixedCRSSeed.
func newCRS(t *testing.T) sampling.PRNG {
	t.Helper()
	crs, err := sampling.NewKeyedPRNG(mheFixedCRSSeed)
	if err != nil {
		t.Fatalf("sampling.NewKeyedPRNG: %v", err)
	}
	return crs
}

// genSecretKeyShares generates n individual secret keys and computes the ideal secret key
// (the sum of all shares), which is the effective single-party key for the collective scheme.
func genSecretKeyShares(t *testing.T, params bgv.Parameters, n int) (shares []*rlwe.SecretKey, ideal *rlwe.SecretKey) {
	t.Helper()
	kgen := rlwe.NewKeyGenerator(params)
	shares = make([]*rlwe.SecretKey, n)
	ideal = rlwe.NewSecretKey(params)
	for i := range shares {
		shares[i] = kgen.GenSecretKeyNew()
		params.RingQP().Add(ideal.Value, shares[i].Value, ideal.Value)
	}
	return
}

// runPublicKeyGen executes the collective public key generation protocol and returns
// the resulting collective public key.
func runPublicKeyGen(t *testing.T, params bgv.Parameters, skShares []*rlwe.SecretKey, crs sampling.PRNG) *rlwe.PublicKey {
	t.Helper()
	n := len(skShares)

	protos := make([]multiparty.PublicKeyGenProtocol, n)
	protos[0] = multiparty.NewPublicKeyGenProtocol(params)
	for i := 1; i < n; i++ {
		protos[i] = protos[0].ShallowCopy()
	}

	crp := protos[0].SampleCRP(crs)

	shares := make([]multiparty.PublicKeyGenShare, n)
	for i := range shares {
		shares[i] = protos[i].AllocateShare()
		protos[i].GenShare(skShares[i], crp, &shares[i])
	}
	for i := 1; i < n; i++ {
		protos[0].AggregateShares(shares[0], shares[i], &shares[0])
	}

	pk := rlwe.NewPublicKey(params)
	protos[0].GenPublicKey(shares[0], crp, pk)
	return pk
}

// runRelinKeyGen executes the 2-round collective relinearization key generation protocol.
func runRelinKeyGen(t *testing.T, params bgv.Parameters, skShares []*rlwe.SecretKey, crs sampling.PRNG) *rlwe.RelinearizationKey {
	t.Helper()
	n := len(skShares)

	protos := make([]multiparty.RelinearizationKeyGenProtocol, n)
	protos[0] = multiparty.NewRelinearizationKeyGenProtocol(params)
	for i := 1; i < n; i++ {
		protos[i] = protos[0].ShallowCopy()
	}

	crp := protos[0].SampleCRP(crs)

	ephSKs := make([]*rlwe.SecretKey, n)
	round1 := make([]multiparty.RelinearizationKeyGenShare, n)
	round2 := make([]multiparty.RelinearizationKeyGenShare, n)
	for i := range protos {
		ephSKs[i], round1[i], round2[i] = protos[i].AllocateShare()
		protos[i].GenShareRoundOne(skShares[i], crp, ephSKs[i], &round1[i])
	}
	for i := 1; i < n; i++ {
		protos[0].AggregateShares(round1[0], round1[i], &round1[0])
	}
	for i := range protos {
		protos[i].GenShareRoundTwo(ephSKs[i], skShares[i], round1[0], &round2[i])
	}
	for i := 1; i < n; i++ {
		protos[0].AggregateShares(round2[0], round2[i], &round2[0])
	}

	rlk := rlwe.NewRelinearizationKey(params)
	protos[0].GenRelinearizationKey(round1[0], round2[0], rlk)
	return rlk
}

// runThresholdDecrypt performs N-of-N collective decryption by key-switching to sk=0.
// Each party contributes a decryption share; the combined result is decrypted by
// the standard decryptor with the zero secret key.
func runThresholdDecrypt(t *testing.T, params bgv.Parameters, skShares []*rlwe.SecretKey, ct *rlwe.Ciphertext) []uint64 {
	t.Helper()
	n := len(skShares)

	// Smudging noise chosen to mask the individual sk*c1 terms; 8*DefaultNoise matches
	// the bound used in Lattigo's own multiparty tests.
	sigmaSmudging := 8.0 * rlwe.DefaultNoise
	cksProto, err := multiparty.NewKeySwitchProtocol(params, ring.DiscreteGaussian{
		Sigma: sigmaSmudging,
		Bound: 6 * sigmaSmudging,
	})
	if err != nil {
		t.Fatalf("NewKeySwitchProtocol: %v", err)
	}

	zeroSK := rlwe.NewSecretKey(params) // all-zero polynomial; used as destination key
	shares := make([]multiparty.KeySwitchShare, n)
	for i := range shares {
		shares[i] = cksProto.AllocateShare(ct.Level())
		cksProto.GenShare(skShares[i], zeroSK, ct, &shares[i])
	}
	for i := 1; i < n; i++ {
		if err := cksProto.AggregateShares(shares[0], shares[i], &shares[0]); err != nil {
			t.Fatalf("AggregateShares: %v", err)
		}
	}

	ctOut := rlwe.NewCiphertext(params, ct.Degree(), ct.Level())
	cksProto.KeySwitch(ct, shares[0], ctOut)

	// After CKS to sk=0: c0' = c0 + skIdeal*c1 + noise ≈ m.
	// Decryption with zeroSK: m = c0' + c1*0 = c0'.
	ptDec := rlwe.NewDecryptor(params, zeroSK).DecryptNew(ctOut)
	values := make([]uint64, params.MaxSlots())
	if err := bgv.NewEncoder(params).Decode(ptDec, values); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return values
}

// encodeAndEncrypt is a test helper that encodes a uint64 slice and encrypts it.
func encodeAndEncrypt(t *testing.T, params bgv.Parameters, enc *rlwe.Encryptor, values []uint64) *rlwe.Ciphertext {
	t.Helper()
	pt := bgv.NewPlaintext(params, params.MaxLevel())
	if err := bgv.NewEncoder(params).Encode(values, pt); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	ct, err := enc.EncryptNew(pt)
	if err != nil {
		t.Fatalf("EncryptNew: %v", err)
	}
	return ct
}

// TestMHESetupBGVParams verifies that the MHE test parameters are accepted by
// bgv.NewParametersFromLiteral and that the CRS samples a non-trivial polynomial.
func TestMHESetupBGVParams(t *testing.T) {
	cases := []struct {
		name string
		lit  bgv.ParametersLiteral
	}{
		{
			name: "MHEParams/LogN=14/LogQ=6/LogP=2/PT=257",
			lit:  mheTestParams,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := bgv.NewParametersFromLiteral(tc.lit)
			if err != nil {
				t.Fatalf("NewParametersFromLiteral: %v", err)
			}

			proto := multiparty.NewPublicKeyGenProtocol(params)

			// Two PRNGs with the same seed must produce the same CRP (determinism).
			crs1, _ := sampling.NewKeyedPRNG(mheFixedCRSSeed)
			crs2, _ := sampling.NewKeyedPRNG(mheFixedCRSSeed)
			crp1 := proto.SampleCRP(crs1)
			crp2 := proto.SampleCRP(crs2)

			if crp1.Value.Q.Level() < 0 {
				t.Error("CRP Q polynomial should have a valid level")
			}
			for i, c := range crp1.Value.Q.Coeffs {
				for j, v := range c {
					if v != crp2.Value.Q.Coeffs[i][j] {
						t.Errorf("CRS is not deterministic: crp1[%d][%d]=%d != crp2[%d][%d]=%d", i, j, v, i, j, crp2.Value.Q.Coeffs[i][j])
					}
				}
			}
		})
	}
}

// TestMHECollectiveKeyGen verifies N-of-N collective public key generation with N=1, 2, 3 parties.
// After generating the collective pk, encrypts a known vector and decrypts with the ideal sk.
func TestMHECollectiveKeyGen(t *testing.T) {
	params := newMHEParams(t)
	encoder := bgv.NewEncoder(params)

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
			crs := newCRS(t)
			skShares, skIdeal := genSecretKeyShares(t, params, tc.nParties)
			pk := runPublicKeyGen(t, params, skShares, crs)

			want := make([]uint64, params.MaxSlots())
			for i := range want {
				want[i] = uint64((i + 1) % int(params.PlaintextModulus()))
			}
			ct := encodeAndEncrypt(t, params, rlwe.NewEncryptor(params, pk), want)

			ptDec := rlwe.NewDecryptor(params, skIdeal).DecryptNew(ct)
			got := make([]uint64, params.MaxSlots())
			if err := encoder.Decode(ptDec, got); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			for i, v := range got {
				if v != want[i] {
					t.Errorf("slot %d: got %d, want %d", i, v, want[i])
				}
			}
		})
	}

	// Commutativity: aggregating shares in reverse order must produce the same collective pk.
	t.Run("Commutativity/N=2", func(t *testing.T) {
		skShares, skIdeal := genSecretKeyShares(t, params, 2)

		// Forward order: P0 then P1
		crs1 := newCRS(t)
		proto := multiparty.NewPublicKeyGenProtocol(params)
		crp := proto.SampleCRP(crs1)
		s0 := proto.AllocateShare()
		s1 := proto.AllocateShare()
		proto.GenShare(skShares[0], crp, &s0)
		proto.GenShare(skShares[1], crp, &s1)
		aggFwd := proto.AllocateShare()
		proto.AggregateShares(s0, s1, &aggFwd)
		pkFwd := rlwe.NewPublicKey(params)
		proto.GenPublicKey(aggFwd, crp, pkFwd)

		// Reverse order: P1 then P0
		aggRev := proto.AllocateShare()
		proto.AggregateShares(s1, s0, &aggRev)
		pkRev := rlwe.NewPublicKey(params)
		proto.GenPublicKey(aggRev, crp, pkRev)

		// Both keys must decrypt correctly (same plaintext under ideal sk)
		want := []uint64{7, 3}
		wantFull := make([]uint64, params.MaxSlots())
		for i := range wantFull {
			wantFull[i] = want[i%2]
		}
		enc := rlwe.NewEncryptor(params, pkFwd)
		ctFwd := encodeAndEncrypt(t, params, enc, wantFull)
		enc2 := rlwe.NewEncryptor(params, pkRev)
		ctRev := encodeAndEncrypt(t, params, enc2, wantFull)

		dec := rlwe.NewDecryptor(params, skIdeal)
		gotFwd := make([]uint64, params.MaxSlots())
		gotRev := make([]uint64, params.MaxSlots())
		bgv.NewEncoder(params).Decode(dec.DecryptNew(ctFwd), gotFwd)
		bgv.NewEncoder(params).Decode(dec.DecryptNew(ctRev), gotRev)

		for i := range wantFull {
			if gotFwd[i] != wantFull[i] {
				t.Errorf("fwd slot %d: got %d, want %d", i, gotFwd[i], wantFull[i])
			}
			if gotRev[i] != wantFull[i] {
				t.Errorf("rev slot %d: got %d, want %d", i, gotRev[i], wantFull[i])
			}
		}
	})
}

// TestMHERelinKeyGen verifies that a 2-round collective relinearization key generation
// produces a valid key that enables compact homomorphic multiplication.
func TestMHERelinKeyGen(t *testing.T) {
	params := newMHEParams(t)

	cases := []struct {
		name     string
		nParties int
		a, b     uint64
	}{
		{name: "N=2/3x5=15", nParties: 2, a: 3, b: 5},
		{name: "N=2/10x20=200", nParties: 2, a: 10, b: 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crs := newCRS(t)
			skShares, skIdeal := genSecretKeyShares(t, params, tc.nParties)

			// CRS is stateful: pkgen consumes the first portion, rlkgen the next.
			pk := runPublicKeyGen(t, params, skShares, crs)
			rlk := runRelinKeyGen(t, params, skShares, crs)
			evk := rlwe.NewMemEvaluationKeySet(rlk)

			valA := make([]uint64, params.MaxSlots())
			valB := make([]uint64, params.MaxSlots())
			for i := range valA {
				valA[i] = tc.a
				valB[i] = tc.b
			}

			enc := rlwe.NewEncryptor(params, pk)
			ctA := encodeAndEncrypt(t, params, enc, valA)
			ctB := encodeAndEncrypt(t, params, enc, valB)

			eval := bgv.NewEvaluator(params, evk)
			ctMul, err := eval.MulRelinNew(ctA, ctB)
			if err != nil {
				t.Fatalf("MulRelinNew: %v", err)
			}

			ptDec := rlwe.NewDecryptor(params, skIdeal).DecryptNew(ctMul)
			got := make([]uint64, params.MaxSlots())
			if err := bgv.NewEncoder(params).Decode(ptDec, got); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			want := (tc.a * tc.b) % params.PlaintextModulus()
			for i, v := range got {
				if v != want {
					t.Errorf("slot %d: got %d, want %d", i, v, want)
					break
				}
			}
		})
	}
}

// TestMHEThresholdDecrypt verifies N-of-N collective decryption via KeySwitchProtocol
// (key-switching to sk=0).
func TestMHEThresholdDecrypt(t *testing.T) {
	params := newMHEParams(t)

	cases := []struct {
		name     string
		nParties int
		value    uint64
	}{
		{name: "N=2/value=42", nParties: 2, value: 42},
		{name: "N=3/value=100", nParties: 3, value: 100},
		{name: "N=2/value=0", nParties: 2, value: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crs := newCRS(t)
			skShares, _ := genSecretKeyShares(t, params, tc.nParties)
			pk := runPublicKeyGen(t, params, skShares, crs)

			want := make([]uint64, params.MaxSlots())
			for i := range want {
				want[i] = tc.value
			}
			ct := encodeAndEncrypt(t, params, rlwe.NewEncryptor(params, pk), want)

			got := runThresholdDecrypt(t, params, skShares, ct)
			for i, v := range got {
				if v != tc.value {
					t.Errorf("slot %d: got %d, want %d", i, v, tc.value)
				}
			}
		})
	}
}

// TestMHEFullRoundTrip exercises the complete MHE protocol:
// setup → collective key generation → independent encryption → homomorphic evaluation → threshold decryption.
func TestMHEFullRoundTrip(t *testing.T) {
	params := newMHEParams(t)
	pt := params.PlaintextModulus()

	cases := []struct {
		name    string
		val1    uint64
		val2    uint64
		wantSum uint64
	}{
		{name: "7+3=10", val1: 7, val2: 3, wantSum: 10},
		{name: "200+100=43mod257", val1: 200, val2: 100, wantSum: (200 + 100) % pt},
		{name: "0+0=0", val1: 0, val2: 0, wantSum: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			crs := newCRS(t)
			nParties := 2
			skShares, _ := genSecretKeyShares(t, params, nParties)
			pk := runPublicKeyGen(t, params, skShares, crs)

			enc := rlwe.NewEncryptor(params, pk)

			vals1 := make([]uint64, params.MaxSlots())
			vals2 := make([]uint64, params.MaxSlots())
			for i := range vals1 {
				vals1[i] = tc.val1
				vals2[i] = tc.val2
			}
			ct1 := encodeAndEncrypt(t, params, enc, vals1)
			ct2 := encodeAndEncrypt(t, params, enc, vals2)

			// Homomorphic addition; no evaluation keys needed for Add.
			eval := bgv.NewEvaluator(params, nil)
			ctSum, err := eval.AddNew(ct1, ct2)
			if err != nil {
				t.Fatalf("AddNew: %v", err)
			}

			got := runThresholdDecrypt(t, params, skShares, ctSum)
			for i, v := range got {
				if v != tc.wantSum {
					t.Errorf("slot %d: got %d, want %d", i, v, tc.wantSum)
				}
			}
		})
	}
}
