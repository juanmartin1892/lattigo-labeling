// Copyright 2025 Juan Martín Pérez
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package labeling

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// Definimos tipos específicos sin interface
type PlaintextElements []uint64
type CiphertextElement rlwe.Ciphertext

// Labeledciphertext genérico que puede usar cualquier tipo para elementsA
type Labeledciphertext[T any] struct {
	elementsA T
	elementsB [][]rlwe.Ciphertext
}

// BetaCount returns the total number of β ciphertexts stored in this labeled
// ciphertext. After MultOverflow + L rotate-and-sum steps the count grows as
// 2^(L+1); use this to observe the β explosion when using SumOverflowCiphertextLabeled.
func (lct Labeledciphertext[T]) BetaCount() int {
	n := 0
	for _, row := range lct.elementsB {
		n += len(row)
	}
	return n
}

// AlphaLevel returns the BGV level of the α (elementsA) ciphertext in clct, or
// -1 if there is no α component. Used by benchmarks to compute CKS share sizes.
func AlphaLevel(clct CiphertextLabeledciphertext) int {
	if clct.elementsA == nil {
		return -1
	}
	return (*rlwe.Ciphertext)(clct.elementsA).Level()
}

// RescaleToLevel reduces a BGV ciphertext to targetLevel by successive modulus
// switching (Rescale), dividing the noise by each dropped prime while preserving the
// plaintext's most-significant bits. The ciphertext Scale is updated by each Rescale so
// that a subsequent Decode recovers the correct value.
//
// If the ciphertext is already at or below targetLevel it is returned as a deep copy
// without modification (the level is never increased). This requires the BGV
// (non scale-invariant) evaluator; with the parameters used in this project Rescale is
// active. It returns an error if targetLevel is negative or if a Rescale step fails.
//
// RescaleToLevel exists to compare, on equal footing, the threshold-decryption
// communication of the standard BGV path against the CF labeling path, which operates
// natively at level=1. See spec 012.
func RescaleToLevel(parameters Parameters, ciphertext *rlwe.Ciphertext, targetLevel int) (*rlwe.Ciphertext, error) {
	if targetLevel < 0 {
		return nil, fmt.Errorf("RescaleToLevel: targetLevel %d must be non-negative", targetLevel)
	}
	if ciphertext.Level() <= targetLevel {
		return ciphertext.CopyNew(), nil
	}
	evaluator := bgv.NewEvaluator(parameters.Parameters, nil)
	current := ciphertext.CopyNew()
	for current.Level() > targetLevel {
		next := rlwe.NewCiphertext(parameters.Parameters, current.Degree(), current.Level()-1)
		if err := evaluator.Rescale(current, next); err != nil {
			return nil, fmt.Errorf("RescaleToLevel: rescale from level %d: %w", current.Level(), err)
		}
		current = next
	}
	return current, nil
}

// Aliases de tipo para mayor claridad
type PlaintextLabeledciphertext = Labeledciphertext[PlaintextElements]
type CiphertextLabeledciphertext = Labeledciphertext[*CiphertextElement]

// Servicio para manejar operaciones con Labeledciphertext
type Parameters struct {
	bgv.Parameters
}

// NewParametersFromLiteral creates a new set of BGV parameters for labeling operations
// from literal values.
//
// Parameters:
//   - logN: base-2 logarithm of the polynomial degree (number of slots = 2^(logN-1))
//   - LogQ: moduli for the operation chain (in base-2 logarithm)
//   - LogP: auxiliary moduli for key-switching (in base-2 logarithm)
//   - PlaintextModulus: modulus of the message space
//
// Returns the configured parameters and an error if the configuration is invalid.
func NewParametersFromLiteral(logN int, LogQ []int, LogP []int, PlaintextModulus uint64) (Parameters, error) {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             logN,
		LogQ:             LogQ,
		LogP:             LogP,
		PlaintextModulus: PlaintextModulus,
	})

	if err != nil {
		return Parameters{}, err
	}

	return Parameters{params}, nil
}

// GenerateKeyPair generates a key pair (secret and public) for the BGV scheme.
//
// Returns:
//   - sk: secret key for decryption
//   - pk: public key for encryption
func GenerateKeyPair(params Parameters) (*rlwe.SecretKey, rlwe.EncryptionKey) {
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	return sk, pk
}

// GenerateRelinearizationKey generates a relinearization key necessary to reduce
// the size of ciphertexts after homomorphic multiplications.
//
// Relinearization converts higher-degree ciphertexts back to degree 1, allowing
// multiple consecutive multiplications to be performed.
func GenerateRelinearizationKey(params Parameters, sk *rlwe.SecretKey) *rlwe.RelinearizationKey {
	kgen := rlwe.NewKeyGenerator(params)
	return kgen.GenRelinearizationKeyNew(sk)
}

// GenerateMemEvaluationKeySet creates an in-memory evaluation key set containing
// only the relinearization key.
//
// This is used for basic homomorphic operations that don't require Galois keys
// (rotations) or evaluation keys (key switching between parties).
func GenerateMemEvaluationKeySet(rlk *rlwe.RelinearizationKey) *rlwe.MemEvaluationKeySet {
	return rlwe.NewMemEvaluationKeySet(rlk)
}

// GenerateGaloisKeys generates Galois keys for the specified Galois elements.
//
// Galois keys enable column rotation operations on ciphertexts. The galEls parameter
// should contain the Galois elements corresponding to the desired rotation steps.
//
// For column rotation by k positions, use params.GaloisElement(k).
func GenerateGaloisKeys(params Parameters, sk *rlwe.SecretKey, galEls []uint64) []*rlwe.GaloisKey {
	kgen := rlwe.NewKeyGenerator(params)
	galKeys := make([]*rlwe.GaloisKey, len(galEls))
	for i, galEl := range galEls {
		galKeys[i] = kgen.GenGaloisKeyNew(galEl, sk)
	}
	return galKeys
}

// GenerateMemEvaluationKeySetWithGalois creates an in-memory evaluation key set
// containing both relinearization and Galois keys.
//
// This enables homomorphic operations including multiplication, rotation, and
// key switching.
func GenerateMemEvaluationKeySetWithGalois(rlk *rlwe.RelinearizationKey, galKeys ...*rlwe.GaloisKey) *rlwe.MemEvaluationKeySet {
	return rlwe.NewMemEvaluationKeySet(rlk, galKeys...)
}

// GenerateEvaluationKey generates an evaluation key for switching from secret key
// skA to secret key skB.
//
// This allows transferring ownership of a ciphertext encrypted under skA to be
// decryptable by skB, useful in multiparty computation scenarios.
func GenerateEvaluationKey(params Parameters, skA *rlwe.SecretKey, skB *rlwe.SecretKey) *rlwe.EvaluationKey {
	kgen := rlwe.NewKeyGenerator(params)

	return kgen.GenEvaluationKeyNew(skA, skB)
}

// Encrypt encrypts a vector of values using the labeling scheme with plaintext
// elements A.
//
// The algorithm implements:
//   - Generates random masks b for each slot
//   - Computes a ← (m - b) mod PlaintextModulus
//   - Encrypts β ← Enc(b)
//
// Returns a PlaintextLabeledciphertext where elementsA contains the plaintext
// values a and elementsB contains the ciphertext β.
func Encrypt(params Parameters, key rlwe.EncryptionKey, value []uint64) (PlaintextLabeledciphertext, error) {
	// Instanciamos el generador de numeros aleatorios
	prng, err := sampling.NewPRNG()
	if err != nil {
		return PlaintextLabeledciphertext{}, err
	}

	var labeledciphertext PlaintextLabeledciphertext
	var masks []uint64

	// Inicializamos elementsA como un slice vacío
	labeledciphertext.elementsA = make(PlaintextElements, 0, params.MaxSlots())

	for i := range params.MaxSlots() {
		// Generamos una mascara aleatoria para cada elemento del vector
		mask := ring.RandUniform(prng, uint64(math.Sqrt(float64(params.PlaintextModulus()))), uint64(1<<bits.Len64(uint64(math.Sqrt(float64(params.PlaintextModulus()))))-1))

		// Asignamos el valor cifrado a la lista de elementos A como a ← (m − b) ∈ M
		diff := (value[i] - mask + params.PlaintextModulus()) % params.PlaintextModulus()
		labeledciphertext.elementsA = append(labeledciphertext.elementsA, diff)

		// Añadimos la mascara a la lista de mascaras
		masks = append(masks, mask)
	}

	// Creamos el texto plano para las mascaras
	maskPlaninText := bgv.NewPlaintext(params.Parameters, params.MaxLevel())
	if err := bgv.NewEncoder(params.Parameters).Encode(masks, maskPlaninText); err != nil {
		return labeledciphertext, err
	}

	// Ciframos las mascaras
	// β ← Enc(m)
	ciphertextMask, err := rlwe.NewEncryptor(params, key).EncryptNew(maskPlaninText)
	if err != nil {
		return labeledciphertext, err
	}

	labeledciphertext.elementsB = make([][]rlwe.Ciphertext, 1)
	labeledciphertext.elementsB[0] = make([]rlwe.Ciphertext, 1)
	labeledciphertext.elementsB[0][0] = *ciphertextMask

	return labeledciphertext, nil
}

// Decrypt decrypts a PlaintextLabeledciphertext to recover the original plaintext values.
//
// The algorithm implements:
//   - Decrypts the mask: b ← Dec(β)
//   - Recovers the message: m ← (a + b) mod PlaintextModulus
//
// Returns the decrypted vector of values.
func Decrypt(params Parameters, key *rlwe.SecretKey, labeledciphertext PlaintextLabeledciphertext) ([]uint64, error) {
	// Operación normal con PlaintextElements
	// m ← a + Dec(d)(sk, β)
	maskResult := make([]uint64, params.MaxSlots())
	if err := bgv.NewEncoder(params.Parameters).Decode(rlwe.NewDecryptor(params, key).DecryptNew(&labeledciphertext.elementsB[0][0]), maskResult); err != nil {
		return nil, err
	}

	// Ahora podemos obtener el valor original
	value := make([]uint64, 0, len(labeledciphertext.elementsA))
	for i, elementA := range labeledciphertext.elementsA {
		sum := (elementA + maskResult[i] + params.PlaintextModulus()) % params.PlaintextModulus()
		value = append(value, sum)
	}

	return value, nil
}

// DecryptOverflow decrypts a CiphertextLabeledciphertext with multiple B components
// resulting from overflow operations.
//
// The algorithm implements:
//   - Decrypts α: Dec(α)
//   - For each component i in B: computes ∏ⱼ Dec(βᵢⱼ)
//   - Returns: m = Dec(α) + ∑ᵢ ∏ⱼ Dec(βᵢⱼ) mod PlaintextModulus
//
// This is used to decrypt results from MultOverflow and subsequent overflow operations.
func DecryptOverflow(params Parameters, key *rlwe.SecretKey, labeledciphertext CiphertextLabeledciphertext) ([]uint64, error) {
	// Para overflow: m1m2 = Dec(α) + ∑ Dec(β1)·Dec(β2)
	// α contiene Enc(pk, m1m2 - b1b2)
	// β = [β1, β2] contiene los ciphertexts originales

	// Desciframos α
	plainAlpha := make([]uint64, params.MaxSlots())
	if err := bgv.NewEncoder(params.Parameters).Decode(rlwe.NewDecryptor(params, key).DecryptNew((*rlwe.Ciphertext)(labeledciphertext.elementsA)), plainAlpha); err != nil {
		return nil, err
	}

	sumBetas := make([]uint64, params.MaxSlots())
	for i := range labeledciphertext.elementsB {
		multBetas := make([]uint64, params.MaxSlots())
		// inicializamos el vector multBetas a 1s
		for j := range multBetas {
			multBetas[j] = 1
		}

		for j := range labeledciphertext.elementsB[i] {
			// Desciframos cada βj
			plainBeta := make([]uint64, params.MaxSlots())
			if err := bgv.NewEncoder(params.Parameters).Decode(rlwe.NewDecryptor(params, key).DecryptNew(&labeledciphertext.elementsB[i][j]), plainBeta); err != nil {
				return nil, err
			}
			// Acumulamos el producto de los βj
			for k := range params.MaxSlots() {
				multBetas[k] = (multBetas[k] * plainBeta[k]) % params.PlaintextModulus()
			}
		}
		// Sumamos el resultado de los βj al resultado final
		for k := range params.MaxSlots() {
			sumBetas[k] = (sumBetas[k] + multBetas[k]) % params.PlaintextModulus()
		}
	}

	// Ahora sumamos α y la suma de los βj
	value := make([]uint64, params.MaxSlots())
	for i := range params.MaxSlots() {
		// m1m2 = α + ∑ βj
		value[i] = (plainAlpha[i] + sumBetas[i] + params.PlaintextModulus()) % params.PlaintextModulus()
	}

	return value, nil
}

// Sum adds two PlaintextLabeledciphertext homomorphically.
//
// The algorithm implements:
//   - a ← (a₁ + a₂) mod PlaintextModulus
//   - β ← β₁ + β₂ (homomorphic addition)
//
// Returns the sum as a PlaintextLabeledciphertext.
func Sum(params bgv.Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error) {
	var labeledciphertextSum PlaintextLabeledciphertext

	// Sumar los elementos A de ambos textos cifrados - sin conversiones de tipo!
	labeledciphertextSum.elementsA = make(PlaintextElements, 0, len(labeledciphertext1.elementsA))
	for i := range len(labeledciphertext1.elementsA) {
		sum := (labeledciphertext1.elementsA[i] + labeledciphertext2.elementsA[i]) % params.PlaintextModulus()
		labeledciphertextSum.elementsA = append(labeledciphertextSum.elementsA, sum)
	}

	// Inicializar elementsB
	// Pre-allocate β at degree=1, level=1. Using degree>1 here would cause bgv.Evaluator.Add
	// to keep the output at the higher degree (via InitOutputBinaryOp's max-degree rule),
	// breaking subsequent RotateColumns calls which require degree==1.
	labeledciphertextSum.elementsB = make([][]rlwe.Ciphertext, 1)
	labeledciphertextSum.elementsB[0] = make([]rlwe.Ciphertext, 1)
	labeledciphertextSum.elementsB[0][0] = *rlwe.NewCiphertext(params, 1, 1)

	evaluator := bgv.NewEvaluator(params, nil)
	err := evaluator.Add(&labeledciphertext1.elementsB[0][0], &labeledciphertext2.elementsB[0][0], &labeledciphertextSum.elementsB[0][0])
	if err != nil {
		return labeledciphertextSum, err
	}

	return labeledciphertextSum, nil
}

// Mult multiplies two PlaintextLabeledciphertext homomorphically.
//
// The algorithm implements:
//   - Generates random r
//   - Computes a ← (a₁ × a₂ - r) mod PlaintextModulus
//   - Computes β ← (β₁ × β₂) + a₁β₂ + a₂β₁ + Enc(r)
//
// The result is relinearized using the evaluation key set to keep the ciphertext
// at degree 1. Returns a PlaintextLabeledciphertext.
func Mult(params Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext, key rlwe.EncryptionKey, evk *rlwe.MemEvaluationKeySet) (PlaintextLabeledciphertext, error) {
	// Empezamos calculando la componente A
	// a ← (a1 × a2 − r) ∈ M

	// Generamos un nuevo vector de elementos aleatorios
	// r ← M
	prng, err := sampling.NewPRNG()
	if err != nil {
		return PlaintextLabeledciphertext{}, err
	}

	randomVector := make([]uint64, params.MaxSlots())
	for i := range params.MaxSlots() {
		// Generamos una mascara aleatoria para cada elemento del vector
		rand := ring.RandUniform(prng, uint64(math.Sqrt(float64(params.PlaintextModulus()))), uint64(1<<bits.Len64(uint64(math.Sqrt(float64(params.PlaintextModulus()))))-1))
		randomVector[i] = rand
	}

	var labeledciphertextProduct PlaintextLabeledciphertext

	// Multiplicamos los elementos A de ambos textos cifrados y restamos el resultado con el vector aleatorio
	// a = a1 × a2 − r
	labeledciphertextProduct.elementsA = make(PlaintextElements, 0, len(labeledciphertext1.elementsA))
	for i := range len(labeledciphertext1.elementsA) {
		product := (labeledciphertext1.elementsA[i]*labeledciphertext2.elementsA[i] - randomVector[i] + params.PlaintextModulus()) % params.PlaintextModulus()
		labeledciphertextProduct.elementsA = append(labeledciphertextProduct.elementsA, product)
	}

	// Realizamos ahora el siguiente proceso:
	// (β1 X β2) + a1β2 + a2β1 + Enc(d)(pk, r)
	labeledciphertextProduct.elementsB = make([][]rlwe.Ciphertext, 1)
	labeledciphertextProduct.elementsB[0] = make([]rlwe.Ciphertext, 1)
	labeledciphertextProduct.elementsB[0][0] = *rlwe.NewCiphertext(params, params.MaxLevel(), 1)

	// Primero multiplicamos los textos cifrados
	evaluator := bgv.NewEvaluator(params.Parameters, evk)
	err = evaluator.MulRelin(&labeledciphertext1.elementsB[0][0], &labeledciphertext2.elementsB[0][0], &labeledciphertextProduct.elementsB[0][0])
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Ahora calculamos a1β2
	labeledciphertext1elementsB := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext1.elementsB[0][0], []uint64(labeledciphertext2.elementsA), &labeledciphertext1elementsB)
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Sumamos a1β2 al resultado
	// (β1 X β2) + a1β2
	err = evaluator.Add(&labeledciphertextProduct.elementsB[0][0], &labeledciphertext1elementsB, &labeledciphertextProduct.elementsB[0][0])
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Ahora calculamos a2β1
	labeledciphertext2elementsB := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext2.elementsB[0][0], []uint64(labeledciphertext1.elementsA), &labeledciphertext2elementsB)
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Sumamos a2β1 al resultado
	// (β1 X β2) + a1β2 + a2β1
	err = evaluator.Add(&labeledciphertextProduct.elementsB[0][0], &labeledciphertext2elementsB, &labeledciphertextProduct.elementsB[0][0])
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Ciframos el vector aleatorio
	randomVectorPlaninText := bgv.NewPlaintext(params.Parameters, params.MaxLevel())
	if err := bgv.NewEncoder(params.Parameters).Encode(randomVector, randomVectorPlaninText); err != nil {
		return labeledciphertextProduct, err
	}

	// Ciframos el texto plano del vector aleatorio
	ciphertextRandomVector, err := rlwe.NewEncryptor(params, key).EncryptNew(randomVectorPlaninText)
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Sumamos el texto cifrado del vector aleatorio al resultado final
	// (β1 X β2) + a1β2 + a2β1 + Enc(pk, r)
	err = evaluator.Add(&labeledciphertextProduct.elementsB[0][0], ciphertextRandomVector, &labeledciphertextProduct.elementsB[0][0])
	if err != nil {
		return labeledciphertextProduct, err
	}

	return labeledciphertextProduct, nil
}

// MultOverflow multiplies two PlaintextLabeledciphertext and returns a
// CiphertextLabeledciphertext to support deeper multiplicative depth.
//
// The algorithm implements:
//   - Computes α ← Enc(a₁·a₂) + a₁β₂ + a₂β₁
//   - Sets β ← [β₁, β₂]
//
// The overflow representation allows subsequent multiplications beyond the noise
// budget of standard multiplication. Returns a CiphertextLabeledciphertext.
func MultOverflow(params Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext, key rlwe.EncryptionKey, evk *rlwe.MemEvaluationKeySet) (CiphertextLabeledciphertext, error) {
	// MultOverflow implementa: Enc(pk, a1·a2) + a1β2 + a2β1
	// El resultado se almacena en elementA

	// Calculamos el producto de los elementos A: a1 · a2 - sin conversiones de tipo!
	productVector := make([]uint64, len(labeledciphertext1.elementsA))
	for i := range len(labeledciphertext1.elementsA) {
		productVector[i] = (labeledciphertext1.elementsA[i] * labeledciphertext2.elementsA[i]) % params.PlaintextModulus()
	}

	// Ciframos el vector producto para elementsA
	productPlaintext := bgv.NewPlaintext(params.Parameters, params.MaxLevel())
	if err := bgv.NewEncoder(params.Parameters).Encode(productVector, productPlaintext); err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	productCiphertext, err := rlwe.NewEncryptor(params.Parameters, key).EncryptNew(productPlaintext)
	if err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	evaluator := bgv.NewEvaluator(params.Parameters, evk)

	// Calculamos a1β2 - sin conversiones de tipo!
	a1beta2 := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext2.elementsB[0][0], []uint64(labeledciphertext1.elementsA), &a1beta2)
	if err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	// Calculamos a2β1 - sin conversiones de tipo!
	a2beta1 := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext1.elementsB[0][0], []uint64(labeledciphertext2.elementsA), &a2beta1)
	if err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	// Calculamos α = Enc(pk, a1·a2) + a1β2 + a2β1

	// Primero asegurémonos de que todos tengan el mismo level
	minLevel := utils.Min(utils.Min(productCiphertext.Level(), a1beta2.Level()), a2beta1.Level())

	// Crear alpha con el nivel mínimo y degree 1
	alpha := *rlwe.NewCiphertext(params, minLevel, 1)

	// Ajustar levels
	if productCiphertext.Level() > minLevel {
		productCiphertext.Resize(productCiphertext.Degree(), minLevel)
	}

	err = evaluator.Add(productCiphertext, &a1beta2, &alpha)
	if err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	err = evaluator.Add(&alpha, &a2beta1, &alpha)
	if err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	var labeledciphertextProduct CiphertextLabeledciphertext

	// Establecemos elementsA como α para overflow
	labeledciphertextProduct.elementsA = (*CiphertextElement)(&alpha)

	// Para elementsB, almacenamos [β1, β2]
	labeledciphertextProduct.elementsB = make([][]rlwe.Ciphertext, 1)
	labeledciphertextProduct.elementsB[0] = make([]rlwe.Ciphertext, 2)
	labeledciphertextProduct.elementsB[0][0] = labeledciphertext1.elementsB[0][0] // β1
	labeledciphertextProduct.elementsB[0][1] = labeledciphertext2.elementsB[0][0] // β2

	return labeledciphertextProduct, nil
}

// SumOverflow adds a CiphertextLabeledciphertext and a PlaintextLabeledciphertext.
//
// The algorithm implements:
//   - Computes α ← α₁ + a₂
//   - Appends β₂ to the list of B components
//
// This allows mixing overflow and non-overflow ciphertexts. Returns a
// CiphertextLabeledciphertext.
func SumOverflow(params Parameters, labeledciphertext1 CiphertextLabeledciphertext, labeledciphertext2 PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error) {
	var labeledciphertextSum CiphertextLabeledciphertext

	evaluator := bgv.NewEvaluator(params.Parameters, nil)

	// Convert CiphertextElement to *rlwe.Ciphertext
	ct1 := (*rlwe.Ciphertext)(labeledciphertext1.elementsA)

	// Create output ciphertext
	result := rlwe.NewCiphertext(params, params.MaxLevel(), 1)

	// Realizamos suma con plaintext - sin conversiones de tipo!
	err := evaluator.Add(ct1, []uint64(labeledciphertext2.elementsA), result)
	if err != nil {
		return labeledciphertextSum, err
	}

	// Set the result as elementsA
	labeledciphertextSum.elementsA = (*CiphertextElement)(result)

	// Para elementsB, concatenamos los elementos B de ambos textos cifrados
	// β ← [β1, β2]
	labeledciphertextSum.elementsB = append(labeledciphertextSum.elementsB, labeledciphertext1.elementsB...)
	labeledciphertextSum.elementsB = append(labeledciphertextSum.elementsB, labeledciphertext2.elementsB...)

	return labeledciphertextSum, nil
}

// SumOverflowCiphertext adds two CiphertextLabeledciphertext homomorphically.
//
// The algorithm implements:
//   - Computes α ← α₁ + α₂
//   - Concatenates β components: β ← [β₁, β₂]
//
// Returns the sum as a CiphertextLabeledciphertext.
func SumOverflowCiphertext(params Parameters, labeledciphertext1, labeledciphertext2 CiphertextLabeledciphertext) (CiphertextLabeledciphertext, error) {
	var labeledciphertextSum CiphertextLabeledciphertext

	evaluator := bgv.NewEvaluator(params.Parameters, nil)

	// Convert CiphertextElements to *rlwe.Ciphertext
	ct1 := (*rlwe.Ciphertext)(labeledciphertext1.elementsA)
	ct2 := (*rlwe.Ciphertext)(labeledciphertext2.elementsA)

	// Allocate degree=1 explicitly: Lattigo's InitOutputBinaryOp takes the max degree
	// of op0, op1, and opOut, so pre-allocating at degree>1 would corrupt the output.
	result := rlwe.NewCiphertext(params, 1, params.MaxLevel())

	// Perform addition
	err := evaluator.Add(ct1, ct2, result)
	if err != nil {
		return labeledciphertextSum, err
	}

	// Set the result as elementsA
	labeledciphertextSum.elementsA = (*CiphertextElement)(result)

	// Para elementsB, concatenamos los elementos B de ambos textos cifrados
	// β ← [β1, β2]
	labeledciphertextSum.elementsB = append(labeledciphertextSum.elementsB, labeledciphertext1.elementsB...)
	labeledciphertextSum.elementsB = append(labeledciphertextSum.elementsB, labeledciphertext2.elementsB...)

	return labeledciphertextSum, nil
}

// RotateColumns rotates the columns of a PlaintextLabeledciphertext by k positions.
//
// The algorithm implements:
//   - Rotates plaintext elements: a ← rotate(a, k)
//   - Rotates ciphertext: β ← Automorphism(β, k)
//
// Note: BGV rotates the two halves of the vector independently. The first half
// (slots 0 to N/2-1) and second half (slots N/2 to N-1) rotate separately.
//
// Requires Galois keys for the rotation element k in the evaluation key set.
func RotateColumns(params Parameters, labeledciphertext PlaintextLabeledciphertext, k int, evk *rlwe.MemEvaluationKeySet) (PlaintextLabeledciphertext, error) {
	var rotatedCiphertext PlaintextLabeledciphertext

	// RotateColumns en BGV funciona con dos mitades independientes
	// Cada mitad rota circularmente dentro de sí misma
	slots := params.MaxSlots()
	halfSlots := slots / 2
	rotatedCiphertext.elementsA = make(PlaintextElements, slots)

	// Rotar la primera mitad (0 a halfSlots-1)
	for i := 0; i < halfSlots; i++ {
		sourceIndex := (i + k) % halfSlots
		rotatedCiphertext.elementsA[i] = labeledciphertext.elementsA[sourceIndex]
	}

	// Rotar la segunda mitad (halfSlots a slots-1)
	for i := halfSlots; i < slots; i++ {
		sourceIndex := halfSlots + ((i - halfSlots + k) % halfSlots)
		rotatedCiphertext.elementsA[i] = labeledciphertext.elementsA[sourceIndex]
	}

	// Allocate fresh ring.Poly memory for each β component and rotate from the
	// original into the fresh allocation. A shallow struct copy followed by in-place
	// rotation would alias the underlying ring.Poly data and corrupt the source.
	rotatedCiphertext.elementsB = make([][]rlwe.Ciphertext, len(labeledciphertext.elementsB))
	for i := range labeledciphertext.elementsB {
		rotatedCiphertext.elementsB[i] = make([]rlwe.Ciphertext, len(labeledciphertext.elementsB[i]))
		for j := range labeledciphertext.elementsB[i] {
			src := &labeledciphertext.elementsB[i][j]
			rotatedCiphertext.elementsB[i][j] = *rlwe.NewCiphertext(params.Parameters, src.Degree(), src.Level())
		}
	}

	evaluator := bgv.NewEvaluator(params.Parameters, evk)
	err := evaluator.RotateColumns(
		&labeledciphertext.elementsB[0][0],
		k,
		&rotatedCiphertext.elementsB[0][0],
	)
	if err != nil {
		return rotatedCiphertext, err
	}

	return rotatedCiphertext, nil
}

// RotateColumnsOverflow rotates the columns of a CiphertextLabeledciphertext by
// k positions.
//
// The algorithm implements:
//   - Rotates α: α ← Automorphism(α, k)
//   - Rotates all β components: βᵢⱼ ← Automorphism(βᵢⱼ, k)
//
// Requires Galois keys for the rotation element k in the evaluation key set.
// Returns a rotated CiphertextLabeledciphertext.
func RotateColumnsOverflow(params Parameters, labeledciphertext CiphertextLabeledciphertext, k int, evk *rlwe.MemEvaluationKeySet) (CiphertextLabeledciphertext, error) {
	var rotatedCiphertext CiphertextLabeledciphertext

	evaluator := bgv.NewEvaluator(params.Parameters, evk)

	// Normalizar y rotar elementoA
	ctA, err := evaluator.AddNew((*rlwe.Ciphertext)(labeledciphertext.elementsA), []uint64{0})
	if err != nil {
		return rotatedCiphertext, err
	}

	rotatedA := rlwe.NewCiphertext(params.Parameters, ctA.Level(), 1)
	err = evaluator.RotateColumns(ctA, k, rotatedA)
	if err != nil {
		return rotatedCiphertext, err
	}

	rotatedCiphertext.elementsA = (*CiphertextElement)(rotatedA)

	// Rotar cada uno de los elementos B
	rotatedCiphertext.elementsB = make([][]rlwe.Ciphertext, len(labeledciphertext.elementsB))
	for i := range labeledciphertext.elementsB {
		rotatedCiphertext.elementsB[i] = make([]rlwe.Ciphertext, len(labeledciphertext.elementsB[i]))
		for j := range labeledciphertext.elementsB[i] {
			sourceCt := &labeledciphertext.elementsB[i][j]

			// Normalizar el ciphertext - crea una copia del ciphertext asegurando degree 1
			normalizedCt := rlwe.NewCiphertext(params.Parameters, sourceCt.Level(), 1)
			err := evaluator.Add(sourceCt, []uint64{0}, normalizedCt)
			if err != nil {
				return rotatedCiphertext, err
			}

			// Crear nuevo ciphertext para el resultado y rotar
			rotatedCiphertext.elementsB[i][j] = *rlwe.NewCiphertext(params.Parameters, normalizedCt.Level(), 1)
			err = evaluator.RotateColumns(normalizedCt, k, &rotatedCiphertext.elementsB[i][j])
			if err != nil {
				return rotatedCiphertext, err
			}
		}
	}

	return rotatedCiphertext, nil
}

// ApplyEvaluationKey applies an evaluation key to switch the secret key associated
// with a PlaintextLabeledciphertext.
//
// The algorithm applies the key switching operation to the β component, effectively
// re-encrypting it under a different secret key.
//
// This is used in multiparty computation to transfer ciphertext ownership between
// parties. Returns a new PlaintextLabeledciphertext encrypted under the target key.
func ApplyEvaluationKey(params Parameters, evalKey rlwe.EvaluationKey, labeledciphertext PlaintextLabeledciphertext) (*PlaintextLabeledciphertext, error) {

	evaluator := bgv.NewEvaluator(params.Parameters, nil)

	ctOut, err := evaluator.ApplyEvaluationKeyNew(&labeledciphertext.elementsB[0][0], &evalKey)
	if err != nil {
		return nil, err
	}

	labeledciphertext.elementsB[0][0] = *ctOut

	return &labeledciphertext, nil
}

// ApplyEvaluationKeyOverflow applies an evaluation key to switch the secret key
// associated with a CiphertextLabeledciphertext.
//
// The algorithm applies the key switching operation to:
//   - α component
//   - All βᵢⱼ components in the overflow structure
//
// Returns a new CiphertextLabeledciphertext encrypted under the target key.
func ApplyEvaluationKeyOverflow(params Parameters, evalKey rlwe.EvaluationKey, labeledciphertext CiphertextLabeledciphertext) (*CiphertextLabeledciphertext, error) {

	// Aplicar la clave de evaluación sobre elementsA
	evaluator := bgv.NewEvaluator(params.Parameters, nil)

	ctIn := (*rlwe.Ciphertext)(labeledciphertext.elementsA)

	ctOut, err := evaluator.ApplyEvaluationKeyNew(ctIn, &evalKey)
	if err != nil {
		return nil, err
	}

	labeledciphertext.elementsA = (*CiphertextElement)(ctOut)

	// Aplicar la clave de evaluación sobre cada elemento de elementsB
	for i := range labeledciphertext.elementsB {
		for j := range labeledciphertext.elementsB[i] {
			ctInB := &labeledciphertext.elementsB[i][j]
			ctOutB, err := evaluator.ApplyEvaluationKeyNew(ctInB, &evalKey)
			if err != nil {
				return nil, err
			}
			labeledciphertext.elementsB[i][j] = *ctOutB
		}
	}

	return &labeledciphertext, nil
}
