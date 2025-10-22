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
	SkA, Pk := labeling.GenerateKeyPair(params)

	//Generamos las claves de cifrado del segundo usuario
	SkB, _ := labeling.GenerateKeyPair(params)

	// Generamos la clave de relinealización
	evk := labeling.GenerateEvaluationKey(params, SkA, SkB)

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

	labeledciphertextEval, err := labeling.ApplyEvaluationKey(params, *evk, labeledciphertext1)
	if err != nil {
		log.Fatalf("Error al evaluar el cifrado: %v", err)
	}

	// Desencriptamos el valor cifrado evaluado
	decryptedValues, err := labeling.Decrypt(params, SkB, *labeledciphertextEval)
	if err != nil {
		log.Fatalf("Error al descifrar el valor: %v", err)
	}

	// Mostramos los resultados
	log.Println("Valores originales: ", valuesVector1[:10])
	log.Println("Valores desencriptados tras aplicar la clave de evaluacion: ", decryptedValues[:10])

	// Ahora vamos a probar la evaluación de una multiplicación con overflow

	// Generamos un segundo par de claves
	SkC, _ := labeling.GenerateKeyPair(params)

	// Generamos la clave de relinealización
	rlk := labeling.GenerateRelinearizationKey(params, SkA)
	evkSet := labeling.GenerateMemEvaluationKeySet(rlk)

	// Generamos la clave de relinealización
	evkC := labeling.GenerateEvaluationKey(params, SkA, SkC)

	// Generamos un vector de valores aleatorios uniformes
	valuesVector2 := make([]uint64, params.MaxSlots())
	for i := range params.MaxSlots() {
		// Generamos un valor aleatorio uniforme
		rand := ring.RandUniform(prng, maxvalue, mask)
		valuesVector2[i] = rand // Asignamos el valor aleatorio al primer elemento del vector
	}

	// Ciframos el vector de valores aleatorios
	labeledciphertext2, err := labeling.Encrypt(params, Pk, valuesVector2)
	if err != nil {
		log.Fatalf("Error al cifrar el segundo valor: %v", err)
	}

	// Necesitamos usar un nuevo cifrado de valuesVector1 porque
	// labeledciphertext1 ya fue procesado con ApplyEvaluationKey
	labeledciphertext1Fresh, err := labeling.Encrypt(params, Pk, valuesVector1)
	if err != nil {
		log.Fatalf("Error al cifrar el primer valor fresco: %v", err)
	}

	// Multiplicamos los dos textos cifrados con la función de overflow
	labeledciphertextMult, err := labeling.MultOverflow(params, labeledciphertext1Fresh, labeledciphertext2, Pk, evkSet)
	if err != nil {
		log.Fatalf("Error al multiplicar los textos cifrados: %v", err)
	}

	// Aplicamos la clave de evaluacion al resultado de la multiplicación
	labeledciphertextMultEval, err := labeling.ApplyEvaluationKeyOverflow(params, *evkC, labeledciphertextMult)
	if err != nil {
		log.Fatalf("Error al evaluar la multiplicacion: %v", err)
	}

	// Desencriptamos el valor cifrado evaluado
	decryptedValuesMult, err := labeling.DecryptOverflow(params, SkC, *labeledciphertextMultEval)
	if err != nil {
		log.Fatalf("Error al descifrar el valor: %v", err)
	}

	// Comprobamos que el valor descifrado es igual al valor original
	for i := range params.MaxSlots() {
		expectedValue := (valuesVector1[i] * valuesVector2[i]) % params.PlaintextModulus()
		if decryptedValuesMult[i] != expectedValue {
			log.Fatalf("Error en la multiplicacion en la posicion %d: valor descifrado %d, valor esperado %d", i, decryptedValuesMult[i], expectedValue)
		}
	}

	log.Println("Valores originales para la multiplicacion: ", valuesVector1[:10])
	log.Println("Valores originales para la multiplicacion: ", valuesVector2[:10])
	log.Println("Valores desencriptados tras aplicar la clave de evaluacion a la multiplicacion: ", decryptedValuesMult[:10])

}
