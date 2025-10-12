//Copyright 2025 Juan Martín Pérez
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package main

import (
	"log"
	"math"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"

	"main.go/labeling"
)

func main() {

	// Definimos los parámetros del esquema
	var logN int = 14
	var LogQ []int = []int{56, 55, 55, 54, 54, 54}
	var LogP []int = []int{55, 55}
	var PlaintextModulus uint64 = 0x3ee0001

	// Instanciamos el servicio de cifrado con los parámetros definidos
	params, err := labeling.NewParametersFromLiteral(logN, LogQ, LogP, PlaintextModulus)
	if err != nil {
		log.Fatalf("Error al crear el servicio de cifrado: %v", err)
	}

	// Generamos las claves de cifrado
	Sk, Pk := labeling.GenerateKeyPair(params)

	// Generamos la clave de relinealización
	rlk := labeling.GenerateRelinearizationKey(params, Sk)
	evk := labeling.GenerateMemEvaluationKeySet(rlk)

	// Calculamos los limites de los parámetros
	maxvalue := uint64(math.Sqrt(float64(params.PlaintextModulus()))) // max values = floor(sqrt(plaintext modulus))
	mask := uint64(1<<bits.Len64(maxvalue) - 1)                       // binary mask upper-bound for the uniform sampling

	// Instanciamos el generador de numeros aleatorios
	prng, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}

	// Generamos un vector de valores aleatorios uniformes
	valuesVector1 := make([]uint64, params.MaxSlots())
	for i := range params.MaxSlots() {
		// Generamos un valor aleatorio uniforme
		rand := ring.RandUniform(prng, maxvalue, mask)
		valuesVector1[i] = rand // Asignamos el valor aleatorio al primer elemento del vector
	}

	// Geramos un segundo vector de valores aleatorios uniformes
	valuesVector2 := make([]uint64, params.MaxSlots())
	for i := range params.MaxSlots() {
		// Generamos un valor aleatorio uniforme
		rand := ring.RandUniform(prng, maxvalue, mask)
		valuesVector2[i] = rand // Asignamos el valor aleatorio al segundo elemento del vector
	}

	// Ahora ciframos el valor aleatorio
	labeledciphertext1, err := labeling.Encrypt(params, Pk, valuesVector1)
	if err != nil {
		log.Fatalf("Error al cifrar el valor: %v", err)
	}

	// Ciframos el segundo vector de valores aleatorios
	labeledciphertext2, err := labeling.Encrypt(params, Pk, valuesVector2)
	if err != nil {
		log.Fatalf("Error al cifrar el segundo valor: %v", err)
	}

	// Multiplicamos los dos textos cifrados
	labeledciphertextMult, err := labeling.Mult(params, labeledciphertext1, labeledciphertext2, Pk, evk)
	if err != nil {
		log.Fatalf("Error al multiplicar los textos cifrados: %v", err)
	}

	// Multiplicamos de nuevo el primer texto cifrado por el resultado de la multiplicación
	labeledciphertex2Mult, err := labeling.MultOverflow(params, labeledciphertext1, labeledciphertextMult, Pk)
	if err != nil {
		log.Fatalf("Error al multiplicar los textos cifrados: %v", err)
	}

	// Sumamos el resultado de la multiplicación con el primer texto cifrado
	labeledciphertex2MultAndSum, err := labeling.SumOverflow(params, labeledciphertex2Mult, labeledciphertext1)
	if err != nil {
		log.Fatalf("Error al sumar los textos cifrados: %v", err)
	}

	// Desciframos el valor cifrado
	value, err := labeling.DecryptOverflow(params, Sk, labeledciphertex2MultAndSum)
	if err != nil {
		log.Fatalf("Error al descifrar el valor: %v", err)
	}

	// Comprobamos que el valor descifrado es igual al valor original
	for i := range params.MaxSlots() {
		expectedValue := (((valuesVector1[i] * valuesVector2[i]) * valuesVector1[i]) + valuesVector1[i]) % params.PlaintextModulus()
		if value[i] != expectedValue {
			log.Fatalf("El valor descifrado %d no coincide con el valor esperado %d", value[i], expectedValue)
		} else {
			log.Printf("El valor descifrado %d coincide con el valor esperado %d", value[i], expectedValue)
		}
	}

	log.Println("Todos los valores descifrados coinciden con los valores originales.")
}
