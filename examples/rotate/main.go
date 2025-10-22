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

	// Generamos las claves de Galois para RotateColumns
	galEls := []uint64{
		params.GaloisElementForColRotation(10),
		params.GaloisElementForRowRotation(),
	}
	galKeys := labeling.GenerateGaloisKeys(params, Sk, galEls)

	// Creamos el conjunto de claves de evaluación con las claves de Galois
	evk := labeling.GenerateMemEvaluationKeySetWithGalois(rlk, galKeys...)

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

	// Ahora ciframos el valor aleatorio
	labeledciphertext1, err := labeling.Encrypt(params, Pk, valuesVector1)
	if err != nil {
		log.Fatalf("Error al cifrar el valor: %v", err)
	}

	labeledciphertextRot, err := labeling.RotateColumns(params, labeledciphertext1, 10, evk)
	if err != nil {
		log.Fatalf("Error al rotar las columnas: %v", err)
	}

	result, err := labeling.Decrypt(params, Sk, labeledciphertextRot)
	if err != nil {
		log.Fatalf("Error al descifrar el valor: %v", err)
	}

	// Verificación: valores esperados manualmente
	// Con RotateColumns(k=2), los valores se desplazan 2 posiciones a la izquierda
	// BGV usa dos mitades independientes que rotan por separado
	k := 10
	halfSlots := int(params.MaxSlots()) / 2
	for i := range params.MaxSlots() {
		var expectedValue uint64
		if i < halfSlots {
			// Primera mitad: rota dentro de [0, halfSlots)
			expectedValue = valuesVector1[(i+k)%halfSlots]
		} else {
			// Segunda mitad: rota dentro de [halfSlots, MaxSlots)
			expectedValue = valuesVector1[halfSlots+((i-halfSlots+k)%halfSlots)]
		}

		if result[i] != expectedValue {
			log.Fatalf("El valor descifrado %d no coincide con el valor esperado %d en el índice %d", result[i], expectedValue, i)
		}
	}

	log.Println("Todos los valores rotados coinciden con los valores esperados.")
}
