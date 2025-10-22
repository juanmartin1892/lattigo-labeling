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

	// Generamos un segundo vector de valores aleatorios uniformes
	valuesVector2 := make([]uint64, params.MaxSlots())
	for i := range params.MaxSlots() {
		// Generamos un valor aleatorio uniforme
		rand := ring.RandUniform(prng, maxvalue, mask)
		valuesVector2[i] = rand // Asignamos el valor aleatorio al primer elemento del vector
	}

	// Ciframos los dos vectores de valores aleatorios
	labeledciphertext1, err := labeling.Encrypt(params, Pk, valuesVector1)
	if err != nil {
		log.Fatalf("Error al cifrar el valor: %v", err)
	}

	labeledciphertext2, err := labeling.Encrypt(params, Pk, valuesVector2)
	if err != nil {
		log.Fatalf("Error al cifrar el segundo valor: %v", err)
	}

	// Multiplicamos los dos textos cifrados con la función de overflow
	labeledciphertextMult, err := labeling.MultOverflow(params, labeledciphertext1, labeledciphertext2, Pk, evk)
	if err != nil {
		log.Fatalf("Error al multiplicar los textos cifrados: %v", err)
	}

	// Rotamos las columnas del texto cifrado resultante
	labeledciphertextRot, err := labeling.RotateColumnsOverflow(params, labeledciphertextMult, 10, evk)
	if err != nil {
		log.Fatalf("Error al rotar las columnas: %v", err)
	}

	// Desciframos el resultado final
	result, err := labeling.DecryptOverflow(params, Sk, labeledciphertextRot)
	if err != nil {
		log.Fatalf("Error al descifrar el valor: %v", err)
	}

	// Verificamos el resultado esperado
	// En BGV, RotateColumns rota hacia la izquierda
	expected := make([]uint64, params.MaxSlots())
	slots := int(params.MaxSlots())
	halfSlots := slots / 2

	// Calculamos primero el vector producto
	product := make([]uint64, slots)
	for i := range slots {
		product[i] = (valuesVector1[i] * valuesVector2[i]) % params.PlaintextModulus()
	}

	// Aplicamos la rotación de columnas: cada mitad rota independientemente
	// RotateColumns(k) rota hacia la izquierda, por lo que el elemento en posición i
	// viene de la posición (i+k)
	for i := 0; i < halfSlots; i++ {
		// Primera mitad: rota circularmente dentro de [0, halfSlots)
		sourceIndex := (i + 10) % halfSlots
		expected[i] = product[sourceIndex]
	}

	for i := halfSlots; i < slots; i++ {
		// Segunda mitad: rota circularmente dentro de [halfSlots, slots)
		sourceIndex := halfSlots + ((i - halfSlots + 10) % halfSlots)
		expected[i] = product[sourceIndex]
	}

	for i := range params.MaxSlots() {
		if result[i] != expected[i] {
			log.Fatalf("Error en el resultado en el índice %d: esperado %d, obtenido %d", i, expected[i], result[i])
		}
	}

	log.Println("Rotación con overflow completada correctamente y verificada.")
}
