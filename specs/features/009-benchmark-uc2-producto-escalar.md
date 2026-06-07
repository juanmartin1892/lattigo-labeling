# Benchmark UC2: Producto Escalar con Análisis de Frontera de Ruido

**ID:** 009  
**Estado:** Done  
**Fecha:** 2026-06-07  
**Autor:** juanmartin

---

## Objetivo

Implementar el segundo caso de uso (`benchmarks/uc2_dotproduct/main.go`) que compara la variante **sin labeling** (MHE estándar) contra la variante **con labeling** (construcción CF) al calcular el **producto escalar** entre dos vectores distribuidos entre dos partes.

UC2 implica profundidad multiplicativa 1 (un HMul por bloque SIMD + rotate-and-sum sin coste de profundidad), lo que activa el término de ruido de relinearización en std pero no en label. Esto permite un **análisis de frontera de ruido**: variar LogQ hasta que `correct=false`, cuantificando el margen de seguridad diferencial entre variantes.

UC2 es además el bloque constructivo directo de UC3 (varianza), donde la suma de cuadrados es un auto-producto escalar.

---

## Contexto

### Protocolo de UC2

Dado el dataset total de N valores con semilla fija, la parte 1 recibe los primeros M=N/2 valores y la parte 2 recibe los últimos M=N/2 valores. El producto escalar es:

```
<v₁, v₂> = Σᵢ₌₀^{M-1} v₁[i] × v₂[i]  mod t
```

### Estrategia multi-bloque para los tres tamaños de DB

BGV con logN=14 y t=0x3ee0001 tiene `MaxSlots = 16384` (t≡1 mod 2N). Las rotaciones de columna operan dentro de cada mitad de forma independiente, por lo que el tamaño de bloque efectivo es:

```
blockSize = MaxSlots / 2 = 8192
```

Para vectores de M > blockSize, los valores se dividen en K=⌈M/blockSize⌉ bloques. El último bloque se rellena con ceros hasta blockSize. Cada bloque genera un partial inner product en slot 0 mediante rotate-and-sum; los parciales se suman al final.

| DB  | N (total) | M (por parte) | K bloques | Último bloque |
|-----|-----------|---------------|-----------|---------------|
| DB1 | 512       | 256           | 1         | 256 valores (relleno hasta 8192) |
| DB2 | 100 000   | 50 000        | 7         | 848 valores  (relleno hasta 8192) |
| DB3 | 1 000 000 | 500 000       | 62        | 288 valores  (relleno hasta 8192) |

### Árbol de rotate-and-sum por bloque

Después de la multiplicación elemento a elemento en las ranuras 0..blockSize−1:

```
for step := blockSize/2; step >= 1; step /= 2:
    ct_rot = Rotate(ct_prod_block, step)
    ct_prod_block = ct_prod_block + ct_rot
// ct_prod_block[0] = suma de todos los productos del bloque mod t
```

Log₂(8192) = 13 pasos → 13 Galois keys, **iguales para todos los DB y todos los bloques**. El padding de ceros garantiza que las rotaciones no introduzcan valores espurios.

### Acumulación entre bloques

```
ct_total = ct_prod_block_0
for b := 1; b < K; b++:
    ct_total = HAdd(ct_total, ct_prod_block_b)
// ct_total[0] = <v₁, v₂> mod t
```

Para la variante label, `SumLabeled` cumple el mismo papel (suma homómorfica de labeled ciphertexts).

### Argumento de ruido: std vs label

**Variante std** — MulRelin sobre ciphertext de nivel MaxLevel, smudging sobre módulo completo:

```
HMul(ctBlock₁, ctBlock₂) → MulRelin → nivel MaxLevel−1
CKS-to-zero: smudging ∝ Q_{MaxLevel−1}  (grande)
```

Ruido total: `B_fresh² + B_relin + n × B_smudge(∝ Q_alto)`

**Variante label** — β vive en level=1 (observado empíricamente en UC1):

```
MultLabeled → β_result en level=1
RotateColumns + SumLabeled → acumulación sin coste de profundidad
DecryptThresholdLabeled: smudging ∝ q₀  (primer primo del tower, ≪ Q_alto)
```

Ruido total efectivo: `B_fresh² + B_relin(level=1) + n × B_smudge(∝ q₀)`

| Fuente de ruido              | std       | label          |
|------------------------------|-----------|----------------|
| Ruido de cifrado fresco       | ✓         | ✓              |
| Ruido de HMul / CT×CT en β   | ✓         | ✓ (solo en β)  |
| Ruido de smudging threshold   | ✓ (∝ Q)   | ✓ (∝ q₀ ≪ Q)   |

Consecuencia: label puede descifrar con LogQ más pequeño → parámetros RLWE más ajustados → mejor seguridad.

### Tres perfiles de parámetros

| Perfil     | LogQ                       | correct_std | correct_label | Interpretación                        |
|------------|----------------------------|-------------|---------------|---------------------------------------|
| S1 "full"  | [56, 55, 55, 54] (actual)  | ✓           | ✓             | Baseline; ambos correctos con margen  |
| S2 "tight" | reducido (calibrar empír.) | ✗           | ✓             | Std falla; label resiste por menor q₀ |
| S3 "min"   | muy reducido (calibrar)    | ✗           | ✗             | Límite absoluto para label            |

Los valores exactos se determinan empíricamente durante la implementación (ver Notas).

### Relación con otras specs

- Reutiliza `benchmarks/internal/harness` (spec #008), extendiendo `BenchmarkRun` con `ParamProfile`
- Usa spec #002 (`NewMHEContext`, `EncryptLabeled`), spec #003 (threshold decrypt labeling)
- Usa spec #004 (`MultLabeled`, `GenCollectiveRelinKey`, `RotateColumns`, `SumLabeled`)
- La infraestructura de param sweep será reutilizada por spec 010 (UC3)

---

## Interfaz Pública

### Extensión de `benchmarks/internal/harness`

```go
// BenchmarkRun holds all metrics for one complete experiment run.
type BenchmarkRun struct {
    UseCase      string
    Variant      string
    DBLabel      string
    N            int      // total dataset size = 2 × vector size per party
    RunID        int
    Phases       []PhaseResult
    CommBytes    int64
    Rounds       int
    Correct      bool
    ParamProfile string   // "full", "tight", "min" — "" for benchmarks without param sweep
}
```

CSV: columna `param_profile` al final de cada fila (backward compatible; UC1 escribe `""`).

Cabecera actualizada:
```
use_case,variant,db_label,n,run_id,phase,elapsed_ms,heap_b,comm_bytes,rounds,correct,param_profile
```

### `benchmarks/uc2_dotproduct/main.go`

Ejecutable sin API exportada. Flags:

```
-out   string  ruta del CSV de salida   (default: "results/uc2_dotproduct.csv")
-reps  int     repeticiones por celda   (default: 20)
```

---

## Comportamiento Esperado

### Extensión de BenchmarkRun / AppendCSV

| Escenario | Comportamiento |
|-----------|----------------|
| `ParamProfile = ""` | columna vacía en CSV; UC1 tests existentes no se ven afectados |
| `ParamProfile = "full"` | columna contiene `"full"` |
| Runs mixtos (con y sin perfil) en mismo CSV | cabecera una sola vez; campo vacío donde no aplica |

### UC2: operaciones por variante

Las dos partes tienen M=N/2 valores cada una. El evaluador calcula `<v₁,v₂> mod t`.

**Variante `std`:**
```
Fase "setup":   NewMHEContext → pk colectiva
                GenCollectiveRelinKey → rlk (2 rondas)
                GenCollectiveGaloisKeys para {4096,2048,...,1} → 13 galKeys (1 ronda c/u)
                evk = MemEvaluationKeySet(rlk, galKeys...)

Fase "precomp": ds = GenerateDataset(N, 42, t)
                v₁ = ds.Values[0..M-1], v₂ = ds.Values[M..N-1]
                expected = (Σᵢ v₁[i]×v₂[i]) mod t

Fase "encrypt": Para cada bloque b en 0..K-1:
                  buf₁, buf₂ = bloques de blockSize ranuras (ceros en ranuras sin dato)
                  ct₁[b] = bgv.Encryptor(pk).Encrypt(buf₁)
                  ct₂[b] = bgv.Encryptor(pk).Encrypt(buf₂)

Fase "eval":    ct_total = nil
                Para cada bloque b:
                  ctProd = bgv.Evaluator(evk).MulRelinNew(ct₁[b], ct₂[b])
                  Para step = 4096; step >= 1; step /= 2:
                    ctRot = Evaluator.RotateColumnsNew(ctProd, step)
                    ctProd = Evaluator.AddNew(ctProd, ctRot)
                  // ctProd[0] = suma parcial del bloque
                  if ct_total == nil { ct_total = ctProd }
                  else { ct_total = Evaluator.AddNew(ct_total, ctProd) }

Fase "decrypt": CKS-to-zero threshold (smudging) → decoded[0] == expected
```

**Variante `label`:**
```
Fase "setup":   (idéntico a std)

Fase "precomp": (idéntico a std)

Fase "encrypt": Para cada bloque b:
                  lct₁[b] = EncryptLabeled(ctx, buf₁)
                  lct₂[b] = EncryptLabeled(ctx, buf₂)

Fase "eval":    lct_total = nil
                Para cada bloque b:
                  lctProd = MultLabeled(ctx, rlk, lct₁[b], lct₂[b])
                  Para step = 4096; step >= 1; step /= 2:
                    lctRot = RotateColumns(params, lctProd, step, evk)
                    lctProd = SumLabeled(ctx, lctProd, lctRot)
                  // lctProd[0] = suma parcial del bloque
                  if lct_total == nil { lct_total = lctProd }
                  else { lct_total = SumLabeled(ctx, lct_total, lctProd) }

Fase "decrypt": GenLabeledDecryptionShare × 2 → AggregateLabeledDecryptionShares
                → DecryptThresholdLabeled → result[0] == expected
```

### Verificación del resultado esperado

```go
ds := harness.GenerateDataset(db.n, 42, plaintextModulus)
M := db.n / 2
// v₁ = ds.Values[0..M-1], v₂ = ds.Values[M..N-1]
// Cada valor ≤ 1000; producto ≤ 10^6 < t (≈66M) → sin reducción por producto.
// Suma máxima: 500 000 × 10^6 = 5×10^11 < 2^40 < 2^64 → sin desbordamiento uint64.
var innerProd uint64
for i := 0; i < M; i++ {
    innerProd += ds.Values[i] * ds.Values[M+i]
}
expected := innerProd % plaintextModulus
```

### Matriz de experimentos

```
3 perfiles × 2 variantes × 3 DBs × 20 reps × 5 fases = 1800 filas en CSV
```

### Ejemplo de bloque CSV (DB2, 7 bloques por variante)

```
UC2,std,DB2,100000,1,setup,180.5,4096000,0,0,false,full
UC2,std,DB2,100000,1,precomp,1.2,800000,0,0,false,full
UC2,std,DB2,100000,1,encrypt,18.3,2867200,0,0,false,full
UC2,std,DB2,100000,1,eval,24.7,3145728,0,0,false,full
UC2,std,DB2,100000,1,decrypt,6.5,16384,6720,1,true,full
```

---

## Casos Edge

- [ ] S2/S3: si Lattigo rechaza los parámetros al crear el esquema, loguear warning y omitir ese perfil sin abortar
- [ ] `correct=false` en S2 (std) y en S3 (ambos) es el resultado esperado, no un fallo del benchmark
- [ ] Último bloque con menos de blockSize valores: se rellena con ceros; los ceros contribuyen 0 al producto → suma correcta sin sesgo
- [ ] `N` impar: parte 1 toma `⌈N/2⌉`, parte 2 toma `⌊N/2⌋`; expected se calcula con el split real
- [ ] `ParamProfile = ""` no rompe tests existentes de UC1 (campo vacío en CSV)
- [ ] Las 13 Galois keys se generan una sola vez por perfil de parámetros y se reutilizan para todos los DBs y todos los bloques

---

## Dependencias

- Spec #008: harness (`BenchmarkRun`, `AppendCSV`, `GenerateDataset`, `Run`)
- Spec #002: `NewMHEContext`, `EncryptLabeled`
- Spec #003: `GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`, `DecryptThresholdLabeled`
- Spec #004: `MultLabeled`, `GenCollectiveRelinKey`, `RotateColumns`, `SumLabeled`
- Lattigo: `bgv`, `multiparty.GaloisKeyGenProtocol`, `multiparty.KeySwitchProtocol`, `rlwe`, `ring`
- Stdlib: `flag`, `fmt`, `log`, `math/rand/v2`

---

## Criterios de Aceptación

- [x] `go build ./benchmarks/...` exitoso
- [x] `go vet ./benchmarks/...` sin warnings
- [x] `go test ./benchmarks/internal/harness/` pasa; test nuevo para `ParamProfile` en `AppendCSV`; UC1 tests no rotos
- [x] `go run ./benchmarks/uc2_dotproduct/ -reps 1` completa sin errores y produce CSV
- [x] CSV contiene `3 perfiles × 2 variantes × 3 DBs × 1 rep × 5 fases` = 90 filas para `-reps 1`
- [x] S1 [56,55,55,54]/[55,55]: `correct=true` para ambas variantes en los tres DBs
- [x] S2 [38,37,50,50]/[50,50]: `correct=false` para label, `correct=true` para std (β a level=1 con claves colectivas tiene presupuesto insuficiente)
- [x] S3 [35,35]/[35,35]: `correct=false` para ambas variantes (Q demasiado pequeño para la multiplicación BGV)
- [x] Misma semilla → mismo resultado en múltiples ejecuciones
- [x] `go test -race ./benchmarks/...` sin data races

---

## Notas de Implementación

### Parámetros criptográficos

```go
const (
    logN             = 14
    plaintextModulus = uint64(0x3ee0001)
    blockSize        = 8192 // MaxSlots/2; rotaciones de columna dentro de una mitad SIMD
    nParties         = 2
    datasetSeed      = int64(42)
    nRotSteps        = 13   // log₂(8192)
)

// S1 — baseline, mismos que UC1
var logQFull = []int{56, 55, 55, 54}
var logPFull = []int{55, 55}

// S2 y S3 — valores a determinar empíricamente con -reps 20 sobre DB1 (más rápido):
//   Paso 1 — empezar en logQ=[40,40,40], logP=[40,40] (~120 bits logQ)
//   Paso 2 — std: correct=false mayoritario y label: correct=true → S2
//   Paso 3 — reducir a [30,30,30] → label también falla → S3
//   Paso 4 — búsqueda binaria bit a bit para fronteras exactas
// Restricción Lattigo: primo mínimo ≈ 30 bits; logQ+logP ≤ 438 bits (HE Standard 2019, logN=14, λ=128)
var logQTight = []int{...} // completar tras calibración
var logPTight = []int{...}
var logQMin   = []int{...}
var logPMin   = []int{...}
```

### Generación colectiva de claves de Galois

`multiparty.GaloisKeyGenProtocol` es un protocolo de **1 ronda** (sin ephemeral key, más simple que relin). Se necesita una GaloisKey por elemento de rotación:

```go
// rotationGaloisEls devuelve los 13 galois elements para el árbol de rotate-and-sum.
func rotationGaloisEls(params labeling.Parameters) []uint64 {
    galEls := make([]uint64, nRotSteps)
    for i, step := 0, blockSize/2; step >= 1; i, step = i+1, step/2 {
        galEls[i] = params.GaloisElementForColRotation(step)
    }
    return galEls
}

// genCollectiveGaloisKeys ejecuta el protocolo multiparty de 1 ronda.
func genCollectiveGaloisKeys(
    bgvParams bgv.Parameters,
    skShares []*rlwe.SecretKey,
    crs multiparty.CRS,
    galEls []uint64,
) ([]*rlwe.GaloisKey, error) {
    proto := multiparty.NewGaloisKeyGenProtocol(bgvParams)
    galKeys := make([]*rlwe.GaloisKey, len(galEls))
    for j, galEl := range galEls {
        crp := proto.SampleCRP(crs)
        agg := proto.AllocateShare()
        for _, sk := range skShares {
            share := proto.AllocateShare()
            if err := proto.GenShare(sk, galEl, crp, &share); err != nil {
                return nil, err
            }
            if err := proto.AggregateShares(agg, share, &agg); err != nil {
                return nil, err
            }
        }
        galKeys[j] = rlwe.NewGaloisKey(bgvParams)
        if err := proto.GenGaloisKey(agg, crp, galKeys[j]); err != nil {
            return nil, err
        }
    }
    return galKeys, nil
}
```

Esta función se implementa localmente en `uc2_dotproduct/main.go`.

### Particionado en bloques

```go
// blocks divide values en K bloques de blockSize, rellenando el último con ceros.
// Devuelve una slice de slices del tamaño de MaxSlots (para SIMD completo).
func blocks(values []uint64, maxSlots int) [][]uint64 {
    half := maxSlots / 2
    K := (len(values) + half - 1) / half
    result := make([][]uint64, K)
    for b := range result {
        buf := make([]uint64, maxSlots) // ceros por defecto
        start := b * half
        end := min(start+half, len(values))
        copy(buf[:end-start], values[start:end])
        result[b] = buf
    }
    return result
}
```

### Nota de rendimiento para DB3

DB3 con K=62 bloques ejecutará 62 `HMul`/`MultLabeled` + 62×13=806 rotaciones por run. Para `-reps 20` y S1/S2/S3, el tiempo total puede ser elevado. Estrategia recomendada:

1. Calibrar S2/S3 usando **solo DB1** (1 bloque, rápido).
2. Ejecutar el benchmark completo (DB1/DB2/DB3 × S1/S2/S3) una vez confirmados los umbrales.
3. Los perfiles S2/S3 pueden limitarse a DB1 en la publicación si DB2/DB3 tarda demasiado.

### Estructura del main

```go
type paramProfile struct {
    name string  // "full", "tight", "min"
    logQ []int
    logP []int
}

func main() {
    // 1. Parse flags (-out, -reps)
    // 2. Para cada perfil:
    //    a. NewParametersFromLiteral — si error, log warning y skip
    //    b. genCollectiveGaloisKeys (mismas keys para todos los DBs)
    // 3. Para cada perfil × DB × variante × rep:
    //    c. GenerateDataset(N, 42, t) → ds; calcular expected
    //    d. runVariant(...) → BenchmarkRun
    // 4. AppendCSV(outPath, allRuns)
    // 5. Imprimir tabla resumen (perfil, variante, DB, correct_rate%, total_ms)
}
```

### Lo que NO implementa esta spec

- UC3 (varianza): spec 010 — UC2 es su bloque constructivo
- Sub-variante UC2b (auto-producto con vector único; relevante para UC3)
- Análisis con σ_smudge variable (extensión futura)
- Scripts Python de análisis estadístico
- Más de 2 partes
