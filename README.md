# Labeling en Cifrado Homomórfico Multipartito con Lattigo

Implementación de la técnica de labeling de Catalano-Fiore (CF) sobre el esquema BGV en modo multipartido (MHE), usando la librería [Lattigo v6.1.1](https://github.com/tuneinsight/lattigo) en Go. El proyecto incluye un framework de benchmark que compara el protocolo CF contra el esquema estándar en cuatro casos de uso, con el objetivo de identificar escenarios donde CF aporta una ventaja real.

Este trabajo forma parte del **Trabajo Fin de Máster** del Máster Interuniversitario en Ciberseguridad (Universidade de Vigo / Universidade da Coruña), curso 2025/2026.

**Paper base**: Catalano, D., & Fiore, D. (2015). *Labeling Homomorphic Encryption: Computing on Encrypted Data with Less Noise*. [https://eprint.iacr.org/2014/813.pdf](https://eprint.iacr.org/2014/813.pdf)

## ¿Qué es CF Labeling?

En el esquema estándar, cifrar `v` produce `CT = Enc(v)`. La construcción CF divide el valor en dos componentes: `β = Enc(b)` (máscara aleatoria cifrada) y `a = v − b` (residuo público). Esta estructura permite al servidor evaluar ciertas operaciones usando la parte pública `a` sin acceder a `v`, reduciendo el ruido que consumen las operaciones homomórficas.

## Protocolo CF-Scalar

El resultado más relevante del proyecto es el protocolo **CF-scalar** para el cálculo de `Σvᵢ²` (suma de cuadrados, componente central de la varianza). Usando una única máscara broadcast `bⱼ` por bloque en lugar de una máscara por slot, la evaluación se reduce a:

```
α = 2·S·β + n·βSq
```

donde `S = Σ(vᵢ − bⱼ)` y `S2 = Σ(vᵢ − bⱼ)²` son escalares que el cliente calcula en claro. El servidor solo ejecuta dos multiplicaciones escalar×ciphertext, sin rotaciones ni claves de evaluación.

**Resultado experimental** (20 repeticiones × 3 tamaños de DB × 3 perfiles de parámetros):

| Métrica | std | label\_cf\_scalar |
|---|---|---|
| Corrección en parámetros mínimos (S3/min) | ❌ 0/20 | ✅ 20/20 |
| Evaluación — 1M registros | 16.0 s | 0.45 s (×35) |
| Comunicación threshold — 1M registros | 4.0 MB | 4.0 MB |
| Claves de evaluación requeridas | rlk + 13 Galois | ninguna |

## Casos de Uso Implementados

| UC | Circuito | Variantes |
|---|---|---|
| UC1 — Suma | `Σvᵢ` (profundidad 0) | std, label |
| UC2 — Producto escalar | `Σ(xᵢ·yᵢ)` (profundidad 1) | std, std\_modsw, label, label\_max |
| UC3 — Varianza completa | `Σvᵢ²` + `Σvᵢ` (profundidad 1) | std, std\_modsw, label, label\_max |
| UC4 — Varianza compacta | `Σvᵢ²` con compactación de β y CF-scalar | std, label\_compact, label\_compact\_max, label\_compact\_mb, label\_cf\_scalar |

Los benchmarks usan tres tamaños de base de datos (DB1=512, DB2=32.768, DB3=1.000.000 registros) y tres perfiles de parámetros criptográficos (`full`, `tight`, `min`), con 20 repeticiones cada configuración. Los resultados se exportan a CSV en `results/`.

## Estructura del Proyecto

```
.
├── labeling/
│   ├── labeling.go          # Operaciones CF: Encrypt, Sum, Mult, MultOverflow, etc.
│   ├── mhe_labeling.go      # Capa MHE: contexto multipartido, descifrado threshold, CF-scalar
│   └── *_test.go            # Tests table-driven para todas las operaciones
├── benchmarks/
│   ├── internal/harness/    # Infraestructura: timing, memoria, CSV
│   ├── uc1_sum/             # UC1: suma distribuida
│   ├── uc2_dotproduct/      # UC2: producto escalar
│   ├── uc3_variance/        # UC3: varianza
│   └── uc4_variance_compact/# UC4: varianza con CF-scalar
├── examples/                # Ejemplos de uso: suma, multiplicación, rotación, overflow
├── specs/features/          # Especificaciones de cada feature (001–015)
├── results/                 # CSVs de resultados de benchmark
├── go.mod
└── go.sum
```

## Requisitos

- Go 1.25.1 o superior
- Lattigo v6.1.1

## Instalación

```bash
git clone https://github.com/juanmartin1892/lattigo-labeling
cd lattigo-labeling
go mod download
```

## Uso

### Ejecutar benchmarks

```bash
# UC4 con todas las variantes (std, label_compact, label_cf_scalar, ...)
go run ./benchmarks/uc4_variance_compact/

# UC2, UC3 análogamente
go run ./benchmarks/uc2_dotproduct/
go run ./benchmarks/uc3_variance/
```

Los resultados se escriben en `results/`.

### Ejemplos básicos

```bash
go run ./examples/sum-mult-overflow/   # (v1*v2)*v1 + v1 con labeling
go run ./examples/rotate/              # rotación de columnas
go run ./examples/evaluationKeys/      # cambio de clave de evaluación
```

### Uso de la librería — cifrado CF monopartido

```go
params, _ := labeling.NewParametersFromLiteral(14, []int{56,55,55,54}, []int{55,55}, 0x3ee0001)
sk, pk := labeling.GenerateKeyPair(params)
rlk := labeling.GenerateRelinearizationKey(params, sk)
evk := labeling.GenerateMemEvaluationKeySet(rlk)

ct1, _ := labeling.Encrypt(params, pk, []uint64{10, 20, 30})
ct2, _ := labeling.Encrypt(params, pk, []uint64{5, 10, 15})

ctMult, _ := labeling.Mult(params, ct1, ct2, pk, evk)
result, _ := labeling.Decrypt(params, sk, ctMult)
```

### Uso de la librería — protocolo CF-scalar multipartido

```go
ctx, _ := labeling.NewMHEContext(params, skShares, crs)

// Cifrado (cliente por bloque)
beta, betaSq, S, S2, _, _ := labeling.EncryptCFScalar(ctx, blockValues, maskBound)

// Evaluación (servidor, sin claves)
alpha, _ := labeling.CFScalarAlpha(ctx, beta, betaSq, S, uint64(params.N()/2))

// Descifrado threshold (una sola ronda)
share, _ := labeling.GenCiphertextDecryptionShare(ctx, sk, alpha)
// ... agregar shares ...
slots, _ := labeling.DecryptThresholdCiphertext(ctx, combined, alpha)
sumSq := slots[0] + S2  // Σvᵢ²
```

## API Principal

### `labeling/labeling.go` — operaciones CF monopartido

| Función | Descripción |
|---|---|
| `NewParametersFromLiteral` | Crea parámetros BGV |
| `GenerateKeyPair` | Par de claves pública/privada |
| `GenerateRelinearizationKey` | Clave de relinearización |
| `GenerateGaloisKeys` | Claves de Galois para rotaciones |
| `Encrypt` / `EncryptWithMaskBound` | Cifrado CF con máscara aleatoria |
| `Decrypt` / `DecryptOverflow` | Descifrado single-party |
| `Sum` / `SumKeepLevel` | Suma CF (level=1 / nivel preservado) |
| `Mult` / `MultKeepLevel` | Multiplicación CF con relin |
| `MultOverflow` / `MultOverflowKeepLevel` | Multiplicación CF sin relin → `CiphertextLabeledciphertext` |
| `SumOverflow` / `SumOverflowCiphertext` | Suma con overflow |
| `RotateColumns` / `RotateColumnsOverflow` | Rotación de columnas |
| `RescaleToLevel` | ModSwitch a nivel objetivo |

### `labeling/mhe_labeling.go` — protocolo MHE multipartido

| Función | Descripción |
|---|---|
| `NewMHEContext` | Contexto multipartido con shares de SK y CRS |
| `EncryptLabeled` / `EncryptLabeledWithMaskBound` | Cifrado CF con clave colectiva |
| `EncryptCFScalar` | Cifrado CF-scalar (β, βSq, S, S2 por bloque) |
| `CFScalarAlpha` | Evaluación `α = 2·S·β + n·βSq` sin claves |
| `AggregateRawAlphas` | Suma CT+CT de todos los bloques |
| `GenCiphertextDecryptionShare` | Share CKS sobre un ciphertext raw |
| `DecryptThresholdCiphertext` | Descifrado threshold con share combinado |
| `GenLabeledDecryptionShare` | Share CKS para `PlaintextLabeledciphertext` |
| `AggregateLabeledDecryptionShares` | Combinación de shares |
| `DecryptThresholdLabeled` | Descifrado threshold labeled |
| `MultLabeled` / `MultLabeledKeepLevel` | Multiplicación CF MHE |
| `MultOverflowLabeledFree` | Multiplicación overflow sin rlk |
| `GenCompactSelfProductShare` | Share compacto para auto-producto UC4 |
| `DecryptThresholdCompact` | Descifrado compacto UC4 (1 ronda) |
| `GenCollectiveRelinKey` | Generación colectiva de rlk |

## Hallazgos Principales

**UC2/UC3 (profundidad 1 con relin):** A igual nivel de descifrado, CF no aporta ninguna ventaja sobre el estándar. La comunicación threshold es idéntica, y CF es entre un 16% y 62% más lento con mayor uso de memoria. En el perfil de parámetros ajustado (`tight`/level=1), CF falla en corrección donde std acierta, porque el ruido de la máscara supera el presupuesto.

**UC4 con CF-scalar:** Es el único escenario donde CF supera al estándar. Con parámetros mínimos de seguridad (LogQ=[35,35]), el estándar falla en corrección el 100% de las veces y CF-scalar acierta el 100%, con comunicación threshold constante e igual a std y sin necesidad de claves de evaluación. El coste es un cifrado ~2× más lento y una reducción del modelo de privacidad (el servidor aprende agregados por bloque en lugar de nada).

## Contexto Académico

**Máster**: Máster Interuniversitario en Ciberseguridad  
**Universidades**: Universidade de Vigo / Universidade da Coruña  
**Curso**: 2025/2026  
**Autor**: Juan Martín Pérez  
**Tutores**: Alberto Pedrouzo Ulloa, Fernando Pérez González  
**Departamento**: Teoría do Sinal e Comunicacións

## Licencia

Copyright 2025 Juan Martín Pérez. Licencia Apache 2.0 — ver [LICENSE](LICENSE).
