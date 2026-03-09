package labeling

import (
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
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
