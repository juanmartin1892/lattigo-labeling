package labeling

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

const (
	testLogN             = 10
	testPlaintextModulus = 65537
)

var (
	testLogQ = []int{50, 50, 50}
	testLogP = []int{50}
)

type testKeySet struct {
	sk  *rlwe.SecretKey
	pk  rlwe.EncryptionKey
	rlk *rlwe.RelinearizationKey
	evk *rlwe.MemEvaluationKeySet
}

func testParameters(t *testing.T) Parameters {
	t.Helper()

	params, err := NewParametersFromLiteral(testLogN, testLogQ, testLogP, testPlaintextModulus)
	if err != nil {
		t.Fatalf("failed to create parameters: %v", err)
	}

	return params
}

func testKeys(t *testing.T, params Parameters) testKeySet {
	t.Helper()

	sk, pk := GenerateKeyPair(params)
	rlk := GenerateRelinearizationKey(params, sk)
	evk := GenerateMemEvaluationKeySet(rlk)

	return testKeySet{sk: sk, pk: pk, rlk: rlk, evk: evk}
}

func testValues(params Parameters) []uint64 {
	values := make([]uint64, params.MaxSlots())
	modulus := int(params.PlaintextModulus())
	for i := range values {
		values[i] = uint64((i*3 + 1) % modulus)
	}

	return values
}

func addVectors(modulus uint64, a, b []uint64) []uint64 {
	out := make([]uint64, len(a))
	for i := range a {
		out[i] = (a[i] + b[i]) % modulus
	}
	return out
}

func mulVectors(modulus uint64, a, b []uint64) []uint64 {
	out := make([]uint64, len(a))
	for i := range a {
		out[i] = (a[i] * b[i]) % modulus
	}
	return out
}

func rotateExpected(params Parameters, values []uint64, k int) []uint64 {
	slots := params.MaxSlots()
	halfSlots := slots / 2
	rotated := make([]uint64, slots)

	for i := 0; i < halfSlots; i++ {
		sourceIndex := (i + k) % halfSlots
		rotated[i] = values[sourceIndex]
	}

	for i := halfSlots; i < slots; i++ {
		sourceIndex := halfSlots + ((i - halfSlots + k) % halfSlots)
		rotated[i] = values[sourceIndex]
	}

	return rotated
}

func assertEqualVectors(t *testing.T, got, want []uint64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("length mismatch: got %d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("value mismatch at %d: got %d want %d", i, got[i], want[i])
		}
	}
}

func TestNewParametersFromLiteral(t *testing.T) {
	testCases := []struct {
		name    string
		logN    int
		logQ    []int
		logP    []int
		modulus uint64
		wantErr bool
	}{
		{
			name:    "valid",
			logN:    testLogN,
			logQ:    testLogQ,
			logP:    testLogP,
			modulus: testPlaintextModulus,
			wantErr: false,
		},
		{
			name:    "invalid-logN",
			logN:    1,
			logQ:    testLogQ,
			logP:    testLogP,
			modulus: testPlaintextModulus,
			wantErr: true,
		},
		{
			name:    "invalid-modulus",
			logN:    testLogN,
			logQ:    testLogQ,
			logP:    testLogP,
			modulus: 0,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParametersFromLiteral(tc.logN, tc.logQ, tc.logP, tc.modulus)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if params.MaxSlots() == 0 {
				t.Fatalf("expected non-zero slots")
			}
		})
	}
}

func TestGenerateKeyPair(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "keys-created"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			sk, pk := GenerateKeyPair(params)
			if sk == nil {
				t.Fatalf("expected secret key")
			}
			if pk == nil {
				t.Fatalf("expected public key")
			}
		})
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "round-trip"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			values := testValues(params)

			labeledCiphertext, err := Encrypt(params, keys.pk, values)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			got, err := Decrypt(params, keys.sk, labeledCiphertext)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			assertEqualVectors(t, got, values)
		})
	}
}

func TestSum(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "sum"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			valuesA := testValues(params)
			valuesB := addVectors(params.PlaintextModulus(), valuesA, valuesA)

			labeledA, err := Encrypt(params, keys.pk, valuesA)
			if err != nil {
				t.Fatalf("encrypt A failed: %v", err)
			}
			labeledB, err := Encrypt(params, keys.pk, valuesB)
			if err != nil {
				t.Fatalf("encrypt B failed: %v", err)
			}

			sumCiphertext, err := Sum(params.Parameters, labeledA, labeledB)
			if err != nil {
				t.Fatalf("sum failed: %v", err)
			}

			got, err := Decrypt(params, keys.sk, sumCiphertext)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			want := addVectors(params.PlaintextModulus(), valuesA, valuesB)
			assertEqualVectors(t, got, want)
		})
	}
}

func TestMult(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "mult"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			valuesA := testValues(params)
			valuesB := addVectors(params.PlaintextModulus(), valuesA, valuesA)

			labeledA, err := Encrypt(params, keys.pk, valuesA)
			if err != nil {
				t.Fatalf("encrypt A failed: %v", err)
			}
			labeledB, err := Encrypt(params, keys.pk, valuesB)
			if err != nil {
				t.Fatalf("encrypt B failed: %v", err)
			}

			productCiphertext, err := Mult(params, labeledA, labeledB, keys.pk, keys.evk)
			if err != nil {
				t.Fatalf("mult failed: %v", err)
			}

			got, err := Decrypt(params, keys.sk, productCiphertext)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			want := mulVectors(params.PlaintextModulus(), valuesA, valuesB)
			assertEqualVectors(t, got, want)
		})
	}
}

func TestMultOverflowAndDecrypt(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "mult-overflow"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			valuesA := testValues(params)
			valuesB := addVectors(params.PlaintextModulus(), valuesA, valuesA)

			labeledA, err := Encrypt(params, keys.pk, valuesA)
			if err != nil {
				t.Fatalf("encrypt A failed: %v", err)
			}
			labeledB, err := Encrypt(params, keys.pk, valuesB)
			if err != nil {
				t.Fatalf("encrypt B failed: %v", err)
			}

			overflowCiphertext, err := MultOverflow(params, labeledA, labeledB, keys.pk, keys.evk)
			if err != nil {
				t.Fatalf("mult overflow failed: %v", err)
			}

			got, err := DecryptOverflow(params, keys.sk, overflowCiphertext)
			if err != nil {
				t.Fatalf("decrypt overflow failed: %v", err)
			}

			want := mulVectors(params.PlaintextModulus(), valuesA, valuesB)
			assertEqualVectors(t, got, want)
		})
	}
}

func TestSumOverflow(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "sum-overflow"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			valuesA := testValues(params)
			valuesB := addVectors(params.PlaintextModulus(), valuesA, valuesA)

			labeledA, err := Encrypt(params, keys.pk, valuesA)
			if err != nil {
				t.Fatalf("encrypt A failed: %v", err)
			}
			labeledB, err := Encrypt(params, keys.pk, valuesB)
			if err != nil {
				t.Fatalf("encrypt B failed: %v", err)
			}

			overflowCiphertext, err := MultOverflow(params, labeledA, labeledB, keys.pk, keys.evk)
			if err != nil {
				t.Fatalf("mult overflow failed: %v", err)
			}

			overflowSum, err := SumOverflow(params, overflowCiphertext, labeledA)
			if err != nil {
				t.Fatalf("sum overflow failed: %v", err)
			}

			got, err := DecryptOverflow(params, keys.sk, overflowSum)
			if err != nil {
				t.Fatalf("decrypt overflow failed: %v", err)
			}

			want := addVectors(params.PlaintextModulus(), mulVectors(params.PlaintextModulus(), valuesA, valuesB), valuesA)
			assertEqualVectors(t, got, want)
		})
	}
}

func TestSumOverflowCiphertext(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "sum-overflow-ciphertext"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			valuesA := testValues(params)
			valuesB := addVectors(params.PlaintextModulus(), valuesA, valuesA)
			valuesC := addVectors(params.PlaintextModulus(), valuesB, valuesA)

			labeledA, err := Encrypt(params, keys.pk, valuesA)
			if err != nil {
				t.Fatalf("encrypt A failed: %v", err)
			}
			labeledB, err := Encrypt(params, keys.pk, valuesB)
			if err != nil {
				t.Fatalf("encrypt B failed: %v", err)
			}
			labeledC, err := Encrypt(params, keys.pk, valuesC)
			if err != nil {
				t.Fatalf("encrypt C failed: %v", err)
			}

			overflowA, err := MultOverflow(params, labeledA, labeledB, keys.pk, keys.evk)
			if err != nil {
				t.Fatalf("mult overflow A failed: %v", err)
			}
			overflowB, err := MultOverflow(params, labeledB, labeledC, keys.pk, keys.evk)
			if err != nil {
				t.Fatalf("mult overflow B failed: %v", err)
			}

			overflowSum, err := SumOverflowCiphertext(params, overflowA, overflowB)
			if err != nil {
				t.Fatalf("sum overflow ciphertext failed: %v", err)
			}

			got, err := DecryptOverflow(params, keys.sk, overflowSum)
			if err != nil {
				t.Fatalf("decrypt overflow failed: %v", err)
			}

			want := addVectors(params.PlaintextModulus(),
				mulVectors(params.PlaintextModulus(), valuesA, valuesB),
				mulVectors(params.PlaintextModulus(), valuesB, valuesC),
			)
			assertEqualVectors(t, got, want)
		})
	}
}

func TestRotateColumns(t *testing.T) {
	testCases := []struct {
		name string
		k    int
	}{
		{name: "rotate-1", k: 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			values := testValues(params)

			labeled, err := Encrypt(params, keys.pk, values)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			galEls := []uint64{params.GaloisElementForColRotation(tc.k)}
			galKeys := GenerateGaloisKeys(params, keys.sk, galEls)
			evk := GenerateMemEvaluationKeySetWithGalois(keys.rlk, galKeys...)

			rotated, err := RotateColumns(params, labeled, tc.k, evk)
			if err != nil {
				t.Fatalf("rotate columns failed: %v", err)
			}

			got, err := Decrypt(params, keys.sk, rotated)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			want := rotateExpected(params, values, tc.k)
			assertEqualVectors(t, got, want)
		})
	}
}

func TestRotateColumnsOverflow(t *testing.T) {
	testCases := []struct {
		name string
		k    int
	}{
		{name: "rotate-overflow-1", k: 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keys := testKeys(t, params)
			valuesA := testValues(params)
			valuesB := addVectors(params.PlaintextModulus(), valuesA, valuesA)

			labeledA, err := Encrypt(params, keys.pk, valuesA)
			if err != nil {
				t.Fatalf("encrypt A failed: %v", err)
			}
			labeledB, err := Encrypt(params, keys.pk, valuesB)
			if err != nil {
				t.Fatalf("encrypt B failed: %v", err)
			}

			overflowCiphertext, err := MultOverflow(params, labeledA, labeledB, keys.pk, keys.evk)
			if err != nil {
				t.Fatalf("mult overflow failed: %v", err)
			}

			galEls := []uint64{params.GaloisElementForColRotation(tc.k)}
			galKeys := GenerateGaloisKeys(params, keys.sk, galEls)
			evk := GenerateMemEvaluationKeySetWithGalois(keys.rlk, galKeys...)

			rotated, err := RotateColumnsOverflow(params, overflowCiphertext, tc.k, evk)
			if err != nil {
				t.Fatalf("rotate columns overflow failed: %v", err)
			}

			got, err := DecryptOverflow(params, keys.sk, rotated)
			if err != nil {
				t.Fatalf("decrypt overflow failed: %v", err)
			}

			product := mulVectors(params.PlaintextModulus(), valuesA, valuesB)
			want := rotateExpected(params, product, tc.k)
			assertEqualVectors(t, got, want)
		})
	}
}

func TestApplyEvaluationKey(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "apply-evaluation-key"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keysA := testKeys(t, params)
			keysB := testKeys(t, params)

			values := testValues(params)
			labeled, err := Encrypt(params, keysA.pk, values)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			evalKey := GenerateEvaluationKey(params, keysA.sk, keysB.sk)
			switched, err := ApplyEvaluationKey(params, *evalKey, labeled)
			if err != nil {
				t.Fatalf("apply evaluation key failed: %v", err)
			}

			got, err := Decrypt(params, keysB.sk, *switched)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			assertEqualVectors(t, got, values)
		})
	}
}

func TestApplyEvaluationKeyOverflow(t *testing.T) {
	testCases := []struct {
		name string
	}{
		{name: "apply-evaluation-key-overflow"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := testParameters(t)
			keysA := testKeys(t, params)
			keysB := testKeys(t, params)

			valuesA := testValues(params)
			valuesB := addVectors(params.PlaintextModulus(), valuesA, valuesA)

			labeledA, err := Encrypt(params, keysA.pk, valuesA)
			if err != nil {
				t.Fatalf("encrypt A failed: %v", err)
			}
			labeledB, err := Encrypt(params, keysA.pk, valuesB)
			if err != nil {
				t.Fatalf("encrypt B failed: %v", err)
			}

			overflowCiphertext, err := MultOverflow(params, labeledA, labeledB, keysA.pk, keysA.evk)
			if err != nil {
				t.Fatalf("mult overflow failed: %v", err)
			}

			evalKey := GenerateEvaluationKey(params, keysA.sk, keysB.sk)
			switched, err := ApplyEvaluationKeyOverflow(params, *evalKey, overflowCiphertext)
			if err != nil {
				t.Fatalf("apply evaluation key overflow failed: %v", err)
			}

			got, err := DecryptOverflow(params, keysB.sk, *switched)
			if err != nil {
				t.Fatalf("decrypt overflow failed: %v", err)
			}

			want := mulVectors(params.PlaintextModulus(), valuesA, valuesB)
			assertEqualVectors(t, got, want)
		})
	}
}

// encryptAtMaxLevel encodes values at MaxLevel and encrypts under sk, returning a raw
// BGV ciphertext for the modulus-switch tests.
func encryptAtMaxLevel(t *testing.T, params Parameters, sk *rlwe.SecretKey, values []uint64) *rlwe.Ciphertext {
	t.Helper()
	bgvParams := params.Parameters
	plaintext := bgv.NewPlaintext(bgvParams, bgvParams.MaxLevel())
	if err := bgv.NewEncoder(bgvParams).Encode(values, plaintext); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	ciphertext, err := rlwe.NewEncryptor(bgvParams, sk).EncryptNew(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	return ciphertext
}

// decodeWith decrypts ciphertext under sk and returns the slot vector.
func decodeWith(t *testing.T, params Parameters, sk *rlwe.SecretKey, ciphertext *rlwe.Ciphertext) []uint64 {
	t.Helper()
	bgvParams := params.Parameters
	plaintext := rlwe.NewDecryptor(bgvParams, sk).DecryptNew(ciphertext)
	decoded := make([]uint64, bgvParams.MaxSlots())
	if err := bgv.NewEncoder(bgvParams).Decode(plaintext, decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	return decoded
}

func TestRescaleToLevel(t *testing.T) {
	params := testParameters(t)
	maxLevel := params.MaxLevel()

	testCases := []struct {
		name        string
		targetLevel int
		wantLevel   int
		wantErr     bool
	}{
		{name: "rescale_to_1", targetLevel: 1, wantLevel: 1},
		{name: "rescale_to_0", targetLevel: 0, wantLevel: 0},
		{name: "target_equals_max_is_copy", targetLevel: maxLevel, wantLevel: maxLevel},
		{name: "target_above_max_is_copy", targetLevel: maxLevel + 5, wantLevel: maxLevel},
		{name: "negative_target_errors", targetLevel: -1, wantErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sk := rlwe.NewKeyGenerator(params.Parameters).GenSecretKeyNew()
			values := testValues(params)
			ciphertext := encryptAtMaxLevel(t, params, sk, values)

			got, err := RescaleToLevel(params, ciphertext, tc.targetLevel)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for targetLevel %d, got nil", tc.targetLevel)
				}
				return
			}
			if err != nil {
				t.Fatalf("RescaleToLevel failed: %v", err)
			}
			if got.Level() != tc.wantLevel {
				t.Fatalf("level mismatch: got %d want %d", got.Level(), tc.wantLevel)
			}
			// Input must not be mutated: RescaleToLevel returns a deep copy.
			if ciphertext.Level() != maxLevel {
				t.Fatalf("input ciphertext level mutated: got %d want %d", ciphertext.Level(), maxLevel)
			}
			// The plaintext value must survive the modulus switch.
			assertEqualVectors(t, decodeWith(t, params, sk, got), values)
		})
	}
}

// TestEncryptWithMaskBound verifies that EncryptWithMaskBound produces a correct
// round-trip and that no wrap-around occurs when maskBound ≤ min(values) (spec 014).
func TestEncryptWithMaskBound(t *testing.T) {
	params := testParameters(t)

	cases := []struct {
		name      string
		maskBound uint64
		values    func() []uint64
	}{
		{
			name:      "maskBound=1 values=[1..1000]",
			maskBound: 1,
			values: func() []uint64 {
				v := make([]uint64, params.MaxSlots())
				for i := range v {
					v[i] = uint64(1 + i%1000)
				}
				return v
			},
		},
		{
			name:      "maskBound=100 values=[100..1000]",
			maskBound: 100,
			values: func() []uint64 {
				v := make([]uint64, params.MaxSlots())
				for i := range v {
					v[i] = uint64(100 + i%901)
				}
				return v
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := testKeys(t, params)
			values := tc.values()

			lct, err := EncryptWithMaskBound(params, keys.pk, values, tc.maskBound)
			if err != nil {
				t.Fatalf("EncryptWithMaskBound: %v", err)
			}

			// Round-trip: Decrypt must recover values exactly.
			got, err := Decrypt(params, keys.sk, lct)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			assertEqualVectors(t, got, values)

			// Verify no wrap-around: with maskBound ≤ min(values), b_i < v_i always,
			// so a_i = v_i - b_i ≥ 0 and canonical(a_i) ≥ 0.
			pt := params.PlaintextModulus()
			for i, a := range lct.elementsA {
				if a > pt/2 {
					t.Errorf("slot %d: a=%d has negative canonical rep (wrap-around); v=%d maskBound=%d",
						i, a, values[i], tc.maskBound)
				}
			}
		})
	}
}
