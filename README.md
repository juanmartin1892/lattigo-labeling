# Labeling en Cifrado Homomórfico con Lattigo

Implementación de la técnica de labeling aplicada a esquemas de cifrado homomórfico utilizando la librería [Lattigo](https://github.com/tuneinsight/lattigo) en Go.

## Descripción

Este proyecto implementa operaciones de cifrado homomórfico con la técnica de **labeling**, permitiendo realizar operaciones aritméticas más complejas sobre datos cifrados sin que el crecimiento del ruido impida su ejecución. La implementación se basa en el esquema BGV (Brakerski-Gentry-Vaikuntanathan) y extiende las capacidades computacionales del cifrado homomórfico estándar.

Esta implementación está basada en el paper **"Labeling Homomorphic Encryption: Computing on Encrypted Data with Less Noise"** de Catalano y Fiore (2015), disponible en [https://eprint.iacr.org/2014/813.pdf](https://eprint.iacr.org/2014/813.pdf).

### ¿Qué es Labeling?

La técnica de labeling permite ejecutar operaciones homomórficas más complejas controlando el crecimiento del ruido inherente a estas operaciones. Por ejemplo mientras que un esquema homomórfico estándar podría permitir multiplicaciones hasta un cierto nivel (x³), la técnica de labeling permite realizar multiplicaciones adicionales. Esto posibilita operaciones como x³ × x³ = x⁶, llegando efectivamente a un nivel superior de profundidad multiplicativa.

El labeling mantiene información adicional (etiquetas) en los textos cifrados que permite gestionar el presupuesto de ruido de forma más eficiente, ampliando las capacidades computacionales sin comprometer la seguridad.

## Características

**Operaciones básicas con labeling:**
- Suma de textos cifrados
- Multiplicación de textos cifrados con control de ruido mejorado
- Rotación de columnas en textos cifrados
- Aplicación de claves de evaluación para cambio de claves

**Operaciones avanzadas (overflow):**
- Multiplicación con overflow para operaciones de mayor profundidad
- Suma con overflow (mixta y entre ciphertexts)
- Rotación de columnas con overflow
- Aplicación de claves de evaluación con overflow
- Soporte para expresiones polinómicas complejas

**Dos tipos de labeled ciphertexts:**
- `PlaintextLabeledciphertext`: Elementos A en texto plano (operaciones básicas)
- `CiphertextLabeledciphertext`: Elementos A cifrados (operaciones con overflow y mayor profundidad)

## Requisitos

- Go 1.25.1 o superior
- Lattigo v6.1.1

## Instalación

```bash
# Clonar el repositorio
git clone <url-del-repositorio>
cd <directorio-del-proyecto>

# Instalar dependencias
go mod download
```

## Uso

### Ejemplo básico

```go
package main

import (
    "log"
    "<ruta-del-proyecto>/labeling"
)

func main() {
    // Crear parámetros del esquema
    params, err := labeling.NewParametersFromLiteral(14,
        []int{56, 55, 55, 54, 54, 54},
        []int{55, 55},
        0x3ee0001)
    if err != nil {
        log.Fatal(err)
    }

    // Generar claves
    sk, pk := labeling.GenerateKeyPair(params)
    rlk := labeling.GenerateRelinearizationKey(params, sk)
    evk := labeling.GenerateMemEvaluationKeySet(rlk)

    // Cifrar valores
    values1 := []uint64{10, 20, 30, 40}
    values2 := []uint64{5, 10, 15, 20}

    ct1, _ := labeling.Encrypt(params, pk, values1)
    ct2, _ := labeling.Encrypt(params, pk, values2)

    // Sumar textos cifrados
    ctSum, _ := labeling.Sum(params.Parameters, ct1, ct2)

    // Multiplicar textos cifrados
    ctMult, _ := labeling.Mult(params, ct1, ct2, pk, evk)

    // Descifrar resultado
    result, _ := labeling.Decrypt(&params.Parameters, sk, ctSum)
    log.Printf("Resultado: %v", result)
}
```

### Ejemplos incluidos

El proyecto incluye varios ejemplos que demuestran diferentes aspectos de la implementación:

#### Ejemplo básico de suma y multiplicación con overflow
```bash
cd examples/sum-mult-overflow
go run main.go
```
Realiza la operación `((v1 * v2) * v1) + v1` sobre vectores aleatorios, demostrando multiplicaciones múltiples y suma con overflow.

#### Ejemplo de claves de evaluación
```bash
cd examples/evaluationKeys
go run main.go
```
Demuestra el uso de claves de evaluación para cambiar la clave secreta asociada a un texto cifrado, tanto para operaciones básicas como con overflow.

#### Ejemplo de rotación básica
```bash
cd examples/rotate
go run main.go
```
Muestra cómo realizar rotaciones de columnas en textos cifrados PlaintextLabeledciphertext usando claves de Galois.

#### Ejemplo de rotación con overflow
```bash
cd examples/rotate-overflow
go run main.go
```
Demuestra rotaciones de columnas en textos cifrados CiphertextLabeledciphertext resultantes de multiplicaciones con overflow.

## Estructura del Proyecto

```
.
├── labeling/
│   └── labeling.go          # Implementación principal de la librería
├── examples/
│   ├── evaluationKeys/
│   │   └── main.go          # Ejemplo de claves de evaluación
│   ├── rotate/
│   │   └── main.go          # Ejemplo de rotación básica
│   ├── rotate-overflow/
│   │   └── main.go          # Ejemplo de rotación con overflow
│   └── sum-mult-overflow/
│       └── main.go          # Ejemplo de suma y multiplicación con overflow
├── go.mod                   # Dependencias del proyecto
└── README.md                # Este archivo
```

## API Principal

### Tipos

- `PlaintextLabeledciphertext`: Texto cifrado con elementos A en texto plano
- `CiphertextLabeledciphertext`: Texto cifrado con elementos A cifrados

### Funciones

#### Configuración
- `NewParametersFromLiteral()`: Crea parámetros del esquema
- `GenerateKeyPair()`: Genera par de claves (pública/privada)
- `GenerateRelinearizationKey()`: Genera clave de relinealización
- `GenerateMemEvaluationKeySet()`: Crea conjunto de claves de evaluación
- `GenerateGaloisKeys()`: Genera claves de Galois para operaciones de rotación
- `GenerateMemEvaluationKeySetWithGalois()`: Crea conjunto de claves con claves de Galois
- `GenerateEvaluationKey()`: Genera clave de evaluación entre dos claves secretas

#### Operaciones básicas
- `Encrypt()`: Cifra un vector de valores
- `Decrypt()`: Descifra un PlaintextLabeledciphertext
- `Sum()`: Suma dos PlaintextLabeledciphertext
- `Mult()`: Multiplica dos PlaintextLabeledciphertext

#### Operaciones avanzadas
- `RotateColumns()`: Rotación de columnas en PlaintextLabeledciphertext
- `RotateColumnsOverflow()`: Rotación de columnas en CiphertextLabeledciphertext
- `ApplyEvaluationKey()`: Aplica clave de evaluación a PlaintextLabeledciphertext
- `ApplyEvaluationKeyOverflow()`: Aplica clave de evaluación a CiphertextLabeledciphertext

#### Operaciones con overflow
- `MultOverflow()`: Multiplicación que devuelve CiphertextLabeledciphertext
- `SumOverflow()`: Suma mixta (Ciphertext + Plaintext)
- `SumOverflowCiphertext()`: Suma entre CiphertextLabeledciphertext
- `DecryptOverflow()`: Descifra un CiphertextLabeledciphertext

## Ventajas del Labeling

**Extensión de la profundidad computacional:**
Sin labeling, el presupuesto de ruido limita las operaciones a un nivel multiplicativo reducido (ej. x³). Con labeling, es posible realizar multiplicaciones adicionales sobre los resultados intermedios, permitiendo alcanzar niveles superiores (ej. x³ × x³ = x⁶).

**Mejor gestión del ruido:**
La técnica mantiene componentes adicionales en la estructura del ciphertext que permiten controlar y redistribuir el ruido de forma más eficiente.

**Aplicaciones prácticas:**
Permite evaluar polinomios de mayor grado y realizar computaciones más complejas sobre datos cifrados sin necesidad de bootstrapping prematuro.

## Limitaciones

- Aunque labeling extiende la profundidad multiplicativa, el número total de operaciones sigue limitado por el presupuesto de ruido global
- Las operaciones con overflow requieren más recursos computacionales y almacenamiento

## Contexto Académico

Este proyecto forma parte del **Trabajo Fin de Máster** del Máster Interuniversitario en Ciberseguridad (Universidad de Vigo/Universidad de A Coruña), curso 2025/2026.

**Tema**: Estudio e implementación de la técnica de labeling en esquemas de cifrado homomórfico multipartito con la librería Lattigo

**Autor**: Juan Martín Pérez
**Tutores**: Alberto Pedrouzo Ulloa, Fernando Pérez González
**Departamento**: Teoría do Sinal e Comunicacións

## Referencias

- Damgård, I., Pastro, V., Smart, N., & Zakarias, S. (2014). **Multiparty Computation from Somewhat Homomorphic Encryption**. IACR Cryptology ePrint Archive, 2014/813. [https://eprint.iacr.org/2014/813.pdf](https://eprint.iacr.org/2014/813.pdf)
- [Lattigo Documentation](https://github.com/tuneinsight/lattigo)

## Licencia

```
Copyright 2025 Juan Martín Pérez

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

**Nota**: Este proyecto está en desarrollo como parte de un TFM y puede contener funcionalidades experimentales.
