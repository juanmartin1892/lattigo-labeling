# Benchmark Harness + UC1: Sumatorio

**ID:** 008  
**Estado:** Done  
**Fecha:** 2026-05-28  
**Autor:** juanmartin

---

## Objetivo

Implementar la infraestructura común de benchmark (`benchmarks/internal/harness`) y el primer caso de uso (`benchmarks/uc1_sum/main.go`) que compara la variante **sin labeling** (MHE estándar Lattigo) contra la variante **con labeling** (construcción CF) al calcular un sumatorio sobre datos distribuidos entre dos partes, para tres tamaños de base de datos.

---

## Contexto

El plan de benchmarking (`vault/proyectos/tfm-uvigo/benchmark-diseno.md`) requiere ejecutar, para cada caso de uso, dos variantes en paralelo —sin labeling y con labeling— para cuantificar el overhead de la construcción CF. UC1 es el caso de profundidad 0: no hay multiplicación CT×CT, así que labeling **no aporta ninguna ventaja criptográfica**. Cualquier diferencia de tiempo es overhead puro de infraestructura.

**Protocolo de UC1**: cada parte calcula su suma local en claro (`s_j = Σᵢ xᵢⱼ`) y cifra el escalar resultante. El evaluador suma los dos ciphertexts y el resultado se descifra en threshold. Este diseño:
- Es consistente con el protocolo de varianza (UC3) donde las partes también cifran sumas locales.
- Evita la necesidad de claves de Galois para rotaciones, manteniendo el foco en el overhead de CF.
- Permite comparar directamente las dos variantes con exactamente el mismo grafo de operaciones homomórficas (1 HAdd + 1 descifrado).

El efecto del tamaño de la BD se observa en el tiempo de cómputo previo al cifrado (`s_j` requiere sumar N/2 valores en claro) y en la verificación, no en el circuito homomórfico en sí.

**Relación con otras specs:**
- Usa spec 002 (`NewMHEContext`, `EncryptLabeled`) y spec 003 (`GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`, `DecryptThresholdLabeled`)
- La infraestructura del harness será reutilizada por specs 009 (UC2) y 010 (UC3)

**Archivos a crear:**
```
benchmarks/
├── internal/
│   └── harness/
│       ├── harness.go
│       └── harness_test.go
└── uc1_sum/
    └── main.go
```

---

## Interfaz Pública

### `benchmarks/internal/harness`

```go
// Dataset holds synthetic integer values for one experiment and the expected
// sum modulo plaintextModulus, precomputed for validation.
type Dataset struct {
    Values          []uint64
    N               int
    ExpectedSum     uint64
    PlaintextModulus uint64
}

// GenerateDataset creates a deterministic dataset of n values in [1, 1000]
// using the given seed. Two calls with the same arguments always return the
// same Dataset. ExpectedSum is computed with modular arithmetic to match BGV.
func GenerateDataset(n int, seed int64, plaintextModulus uint64) Dataset

// PhaseResult holds timing and net heap allocation for one benchmark phase.
type PhaseResult struct {
    Name    string
    Elapsed time.Duration
    HeapB   int64 // net bytes allocated (HeapAlloc after minus before); can be negative
}

// Run executes fn, measures elapsed time and net heap allocation, and returns
// a PhaseResult labeled name. Calls runtime.GC() before measurement to reduce
// noise from prior allocations.
func Run(name string, fn func()) PhaseResult

// BenchmarkRun holds all metrics for one complete experiment run.
type BenchmarkRun struct {
    UseCase   string        // "UC1", "UC2a", "UC2b", "UC3"
    Variant   string        // "std", "label", "label-compact"
    DBLabel   string        // "DB1", "DB2", "DB3"
    N         int
    RunID     int           // 1-based repetition index
    Phases    []PhaseResult
    CommBytes int64         // total bytes exchanged in threshold decryption (simulated)
    Rounds    int           // number of threshold decryption rounds
    Correct   bool
}

// TotalMs returns the sum of all phase durations in milliseconds.
func (r BenchmarkRun) TotalMs() float64

// AppendCSV appends runs to the CSV at path, writing the header row if the
// file does not exist. Creates parent directories with os.MkdirAll if needed.
func AppendCSV(path string, runs []BenchmarkRun) error
```

### `benchmarks/uc1_sum/main.go`

Ejecutable sin API exportada. Acepta flags opcionales:

```
-out   string  ruta del CSV de salida       (default: "results/uc1_sum.csv")
-reps  int     repeticiones por variante    (default: 10)
```

---

## Comportamiento Esperado

### `GenerateDataset`

| `n` | `seed` | Resultado |
|---|---|---|
| 512 | 42 | 512 valores en [1,1000], `ExpectedSum` determinista |
| 100000 | 42 | igual para DB2 |
| 1000000 | 42 | igual para DB3 |
| 512 | 42 | segunda llamada idéntica → mismo `Dataset` |
| 512 | 99 | distinta semilla → distintos valores, distinto `ExpectedSum` |

### `Run`

| Operación | Comportamiento |
|---|---|
| `Run("encrypt", fn)` | ejecuta `fn`, devuelve `PhaseResult{Name:"encrypt", Elapsed:..., HeapB:...}` |
| fn que no aloca | `HeapB` cercano a 0 (tras GC previo) |

### `AppendCSV`

| Estado previo | Comportamiento |
|---|---|
| Archivo no existe | crea directorio + archivo con fila de cabecera + filas de datos |
| Archivo existe con cabecera | añade solo filas de datos (no repite cabecera) |
| Directorio no existe | `os.MkdirAll` antes de crear el archivo |

### UC1: operaciones por variante

Las dos partes tienen `N/2` valores cada una. Cada una calcula su suma local en claro y cifra el escalar resultante.

**Variante `std` (MHE sin labeling):**
```
Fase "setup":   NewMHEContext para obtener pk colectiva
Fase "precomp": s₁ = Σᵢ valores_parte1   (en claro)
                s₂ = Σᵢ valores_parte2   (en claro)
Fase "encrypt": bgv.Encryptor(pk).Encrypt(s₁) → ct₁
                bgv.Encryptor(pk).Encrypt(s₂) → ct₂
Fase "eval":    bgv.Evaluator.Add(ct₁, ct₂) → ct_sum
Fase "decrypt": share₁ = mhe share de ct_sum desde sk₁
                share₂ = mhe share de ct_sum desde sk₂
                combinar shares → S en claro
```

**Variante `label` (MHE con labeling CF):**
```
Fase "setup":   NewMHEContext
Fase "precomp": s₁ = Σᵢ valores_parte1   (en claro)
                s₂ = Σᵢ valores_parte2   (en claro)
Fase "encrypt": EncryptLabeled(ctx, []uint64{s₁}) → lct₁
                EncryptLabeled(ctx, []uint64{s₂}) → lct₂
Fase "eval":    SumLabeled(ctx, lct₁, lct₂) → lct_sum
Fase "decrypt": GenLabeledDecryptionShare(ctx, sk₁, lct_sum) → share₁
                GenLabeledDecryptionShare(ctx, sk₂, lct_sum) → share₂
                AggregateLabeledDecryptionShares(ctx, [share₁, share₂]) → combined
                DecryptThresholdLabeled(ctx, combined, lct_sum) → []uint64
```

### Verificación

Ambas variantes deben producir `result[0] == dataset.ExpectedSum`. Si difieren, `BenchmarkRun.Correct = false`.

### CSV de salida

Cabecera:
```
use_case,variant,db_label,n,run_id,phase,elapsed_ms,heap_b,comm_bytes,rounds,correct
```

Una fila por fase por run. Los campos `comm_bytes`, `rounds` y `correct` son significativos únicamente en la fila de la fase `"decrypt"`; en el resto toman el valor `0`/`false`.

Ejemplo de bloque para un run:
```
UC1,std,DB1,512,1,setup,12.3,204800,0,0,false
UC1,std,DB1,512,1,precomp,0.1,0,0,0,false
UC1,std,DB1,512,1,encrypt,2.4,51200,0,0,false
UC1,std,DB1,512,1,eval,0.3,1024,0,0,false
UC1,std,DB1,512,1,decrypt,5.1,8192,1680,1,true
```

---

## Casos Edge

- [ ] `N` impar: parte 1 toma `⌈N/2⌉`, parte 2 toma `⌊N/2⌋`; la suma sigue siendo correcta
- [ ] `ExpectedSum` desborda `uint64` antes del módulo: `GenerateDataset` usa aritmética modular acumulativa
- [ ] CSV ya existe con cabecera: `AppendCSV` no duplica la cabecera
- [ ] Directorio padre del CSV no existe: `AppendCSV` lo crea con `os.MkdirAll`
- [ ] `Run` con función que panicea: el panic se propaga sin silenciarse

---

## Dependencias

- Spec #002: `NewMHEContext`, `EncryptLabeled`
- Spec #003: `GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`, `DecryptThresholdLabeled`
- Spec #004: `SumLabeled`
- Paquetes Lattigo: `bgv`, `mhe`, `rlwe`, `utils/sampling`
- Stdlib: `encoding/csv`, `flag`, `math/rand/v2`, `os`, `runtime`, `strconv`, `time`

---

## Criterios de Aceptación

- [x] `go build ./benchmarks/...` exitoso
- [x] `go vet ./benchmarks/...` sin warnings
- [x] `go test ./benchmarks/internal/harness/` pasa con tests table-driven para `GenerateDataset` y `AppendCSV`
- [x] `go run ./benchmarks/uc1_sum/ -reps 1` completa sin errores y produce CSV
- [x] El CSV contiene exactamente `2 variantes × 3 DB sizes × 1 rep × 5 fases` = 30 filas
- [x] `correct=true` en todas las filas de fase `"decrypt"` para ambas variantes
- [x] `GenerateDataset` es determinista: mismos argumentos → mismo `Dataset`
- [x] El harness es el único punto de medición de tiempo y memoria; `uc1_sum/main.go` no llama a `time.Now()` ni `runtime.ReadMemStats()` directamente

---

## Notas de Implementación

### Parámetros criptográficos

```go
// Mismos para ambas variantes. logN=14 da 8192 slots, suficiente para empaquetar
// valores SIMD si fuera necesario en specs futuras.
const (
    logN             = 14
    plaintextModulus = uint64(0x3ee0001)
)
// LogQ = []int{56, 55, 55, 54}  (profundidad 1, suficiente para UC2 y UC3)
// LogP = []int{55, 55}
```

### Simulación de bytes de comunicación

Para la variante `std`, los shares de descifrado de Lattigo son `ring.Poly`. Serializar para medir:

```go
raw, _ := share.MarshalBinary()
commBytes += int64(len(raw))
```

Para la variante `label`, serializar el campo `BShare` de `LabeledDecryptionShare` de la misma forma.

### Estructura del main de UC1

```go
func main() {
    // 1. Parse flags (-out, -reps)
    // 2. Definir DB sizes: []struct{ label string; n int }
    //    {{"DB1", 512}, {"DB2", 100_000}, {"DB3", 1_000_000}}
    // 3. Para cada DB × variante × rep:
    //    a. GenerateDataset(n, 42, plaintextModulus)
    //    b. run := runVariant(variant, dataset, repID)  → BenchmarkRun
    // 4. AppendCSV(outPath, allRuns)
    // 5. Imprimir tabla resumen por pantalla (variante, DB, total_ms, correct)
}
```

### Separación de fases en `runVariant`

Cada llamada a `harness.Run(name, fn)` delimita una fase. El setup (generación de claves y contexto MHE) se mide como fase `"setup"` separada del cifrado para poder distinguir el coste de arranque del coste por operación.

### Lo que NO implementa esta spec

- UC2 (producto escalar): spec 009
- UC3 (varianza): spec 010
- Scripts de análisis estadístico (Python/pandas)
- Gráficos de resultados
- Benchmark con más de 2 partes
- Generación colectiva de claves de Galois (no necesaria en UC1)
