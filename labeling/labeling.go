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
	"math"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// Definimos tipos específicos sin interface
type PlaintextElements []uint64
type CiphertextElement rlwe.Ciphertext

// Labeledciphertext genérico que puede usar cualquier tipo para elementsA
type Labeledciphertext[T any] struct {
	elementsA T
	elementB  [][]rlwe.Ciphertext
}

// Aliases de tipo para mayor claridad
type PlaintextLabeledciphertext = Labeledciphertext[PlaintextElements]
type CiphertextLabeledciphertext = Labeledciphertext[*CiphertextElement]

// Servicio para manejar operaciones con Labeledciphertext
type Parameters struct {
	bgv.Parameters
}

// Constructor del servicio
func NewParametersFromLiteral(logN int, LogQ []int, LogP []int, PlaintextModulus uint64) (Parameters, error) {
	params, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: 0x3ee0001,
	})

	if err != nil {
		return Parameters{}, err
	}

	return Parameters{params}, nil
}

func GenerateKeyPair(params Parameters) (*rlwe.SecretKey, rlwe.EncryptionKey) {
	kgen := rlwe.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPairNew()
	return sk, pk
}

func GenerateRelinearizationKey(params Parameters, sk *rlwe.SecretKey) *rlwe.RelinearizationKey {
	kgen := rlwe.NewKeyGenerator(params)
	return kgen.GenRelinearizationKeyNew(sk)
}

func GenerateMemEvaluationKeySet(rlk *rlwe.RelinearizationKey) *rlwe.MemEvaluationKeySet {
	return rlwe.NewMemEvaluationKeySet(rlk)
}

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

	labeledciphertext.elementB = make([][]rlwe.Ciphertext, 1)
	labeledciphertext.elementB[0] = make([]rlwe.Ciphertext, 1)
	labeledciphertext.elementB[0][0] = *ciphertextMask

	return labeledciphertext, nil
}

// Decrypt para PlaintextLabeledciphertext
func Decrypt(params *bgv.Parameters, key *rlwe.SecretKey, labeledciphertext PlaintextLabeledciphertext) ([]uint64, error) {
	// Operación normal con PlaintextElements
	// m ← a + Dec(d)(sk, β)
	maskResult := make([]uint64, params.MaxSlots())
	if err := bgv.NewEncoder(*params).Decode(rlwe.NewDecryptor(params, key).DecryptNew(&labeledciphertext.elementB[0][0]), maskResult); err != nil {
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

// DecryptOverflow para CiphertextLabeledciphertext
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
	for i := range labeledciphertext.elementB {
		multBetas := make([]uint64, params.MaxSlots())
		// inicializamos el vector multBetas a 1s
		for j := range multBetas {
			multBetas[j] = 1
		}

		for j := range labeledciphertext.elementB[i] {
			// Desciframos cada βj
			plainBeta := make([]uint64, params.MaxSlots())
			if err := bgv.NewEncoder(params.Parameters).Decode(rlwe.NewDecryptor(params, key).DecryptNew(&labeledciphertext.elementB[i][j]), plainBeta); err != nil {
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

// Sum para PlaintextLabeledciphertext
func Sum(params bgv.Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error) {
	var labeledciphertextSum PlaintextLabeledciphertext

	// Sumar los elementos A de ambos textos cifrados - sin conversiones de tipo!
	labeledciphertextSum.elementsA = make(PlaintextElements, 0, len(labeledciphertext1.elementsA))
	for i := range len(labeledciphertext1.elementsA) {
		sum := (labeledciphertext1.elementsA[i] + labeledciphertext2.elementsA[i]) % params.PlaintextModulus()
		labeledciphertextSum.elementsA = append(labeledciphertextSum.elementsA, sum)
	}

	// Inicializar elementB
	labeledciphertextSum.elementB = make([][]rlwe.Ciphertext, 1)
	labeledciphertextSum.elementB[0] = make([]rlwe.Ciphertext, 1)
	labeledciphertextSum.elementB[0][0] = *rlwe.NewCiphertext(params, params.MaxLevel(), 1)

	evaluator := bgv.NewEvaluator(params, nil)
	err := evaluator.Add(&labeledciphertext1.elementB[0][0], &labeledciphertext2.elementB[0][0], &labeledciphertextSum.elementB[0][0])
	if err != nil {
		return labeledciphertextSum, err
	}

	return labeledciphertextSum, nil
}

// Mult para PlaintextLabeledciphertext
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
	labeledciphertextProduct.elementB = make([][]rlwe.Ciphertext, 1)
	labeledciphertextProduct.elementB[0] = make([]rlwe.Ciphertext, 1)
	labeledciphertextProduct.elementB[0][0] = *rlwe.NewCiphertext(params, params.MaxLevel(), 1)

	// Primero multiplicamos los textos cifrados
	evaluator := bgv.NewEvaluator(params.Parameters, evk)
	err = evaluator.MulRelin(&labeledciphertext1.elementB[0][0], &labeledciphertext2.elementB[0][0], &labeledciphertextProduct.elementB[0][0])
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Ahora calculamos a1β2
	labeledciphertext1ElementB := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext1.elementB[0][0], []uint64(labeledciphertext2.elementsA), &labeledciphertext1ElementB)
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Sumamos a1β2 al resultado
	// (β1 X β2) + a1β2
	err = evaluator.Add(&labeledciphertextProduct.elementB[0][0], &labeledciphertext1ElementB, &labeledciphertextProduct.elementB[0][0])
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Ahora calculamos a2β1
	labeledciphertext2ElementB := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext2.elementB[0][0], []uint64(labeledciphertext1.elementsA), &labeledciphertext2ElementB)
	if err != nil {
		return labeledciphertextProduct, err
	}

	// Sumamos a2β1 al resultado
	// (β1 X β2) + a1β2 + a2β1
	err = evaluator.Add(&labeledciphertextProduct.elementB[0][0], &labeledciphertext2ElementB, &labeledciphertextProduct.elementB[0][0])
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
	err = evaluator.Add(&labeledciphertextProduct.elementB[0][0], ciphertextRandomVector, &labeledciphertextProduct.elementB[0][0])
	if err != nil {
		return labeledciphertextProduct, err
	}

	return labeledciphertextProduct, nil
}

// MultOverflow para operaciones PlaintextLabeledciphertext
func MultOverflow(params Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext, key rlwe.EncryptionKey) (CiphertextLabeledciphertext, error) {
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

	evaluator := bgv.NewEvaluator(params.Parameters, nil)

	// Calculamos a1β2 - sin conversiones de tipo!
	a1beta2 := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext2.elementB[0][0], []uint64(labeledciphertext1.elementsA), &a1beta2)
	if err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	// Calculamos a2β1 - sin conversiones de tipo!
	a2beta1 := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
	err = evaluator.Mul(&labeledciphertext1.elementB[0][0], []uint64(labeledciphertext2.elementsA), &a2beta1)
	if err != nil {
		return CiphertextLabeledciphertext{}, err
	}

	// Calculamos α = Enc(pk, a1·a2) + a1β2 + a2β1
	alpha := *rlwe.NewCiphertext(params, params.MaxLevel(), 1)
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

	// Para elementB, almacenamos [β1, β2]
	labeledciphertextProduct.elementB = make([][]rlwe.Ciphertext, 1)
	labeledciphertextProduct.elementB[0] = make([]rlwe.Ciphertext, 2)
	labeledciphertextProduct.elementB[0][0] = labeledciphertext1.elementB[0][0] // β1
	labeledciphertextProduct.elementB[0][1] = labeledciphertext2.elementB[0][0] // β2

	return labeledciphertextProduct, nil
}

// SumOverflow para operaciones mixtas entre CiphertextLabeledciphertext y PlaintextLabeledciphertext
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

	// Para elementB, concatenamos los elementos B de ambos textos cifrados
	// β ← [β1, β2]
	labeledciphertextSum.elementB = append(labeledciphertextSum.elementB, labeledciphertext1.elementB...)
	labeledciphertextSum.elementB = append(labeledciphertextSum.elementB, labeledciphertext2.elementB...)

	return labeledciphertextSum, nil
}

// SumOverflowCiphertext para operaciones entre CiphertextLabeledciphertext
func SumOverflowCiphertext(params Parameters, labeledciphertext1, labeledciphertext2 CiphertextLabeledciphertext) (CiphertextLabeledciphertext, error) {
	var labeledciphertextSum CiphertextLabeledciphertext

	evaluator := bgv.NewEvaluator(params.Parameters, nil)

	// Convert CiphertextElements to *rlwe.Ciphertext
	ct1 := (*rlwe.Ciphertext)(labeledciphertext1.elementsA)
	ct2 := (*rlwe.Ciphertext)(labeledciphertext2.elementsA)

	// Create output ciphertext
	result := rlwe.NewCiphertext(params, params.MaxLevel(), 1)

	// Perform addition
	err := evaluator.Add(ct1, ct2, result)
	if err != nil {
		return labeledciphertextSum, err
	}

	// Set the result as elementsA
	labeledciphertextSum.elementsA = (*CiphertextElement)(result)

	// Para elementB, concatenamos los elementos B de ambos textos cifrados
	// β ← [β1, β2]
	labeledciphertextSum.elementB = append(labeledciphertextSum.elementB, labeledciphertext1.elementB...)
	labeledciphertextSum.elementB = append(labeledciphertextSum.elementB, labeledciphertext2.elementB...)

	return labeledciphertextSum, nil
}
