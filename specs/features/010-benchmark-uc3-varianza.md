# Benchmark UC3: Varianza con Análisis de Frontera de Ruido

**ID:** 010  
**Estado:** Done  
**Fecha:** 2026-06-07  
**Autor:** juanmartin

---

## Objetivo

Implementar el tercer caso de uso (`benchmarks/uc3_variance/main.go`) que compara la variante **sin labeling** (MHE estándar) contra la variante **con labeling** (construcción CF) al calcular la **varianza** de un dataset distribuido entre dos partes.

UC3 combina profundidad 1 (suma de cuadrados) y profundidad 0 (suma) sobre los mismos datos cifrados, demostrando el uso de la misma clave colectiva para computar dos circuitos diferentes en una sola sesión. El análisis de frontera de ruido reutiliza los perfiles S1/S2/S3 calibrados en spec 009.

---

## Contexto

### Fórmula de varianza

```
Var(x) = (Σxᵢ²)/N  −  (Σxᵢ/N)²
       = (N × Σxᵢ²  −  (Σxᵢ)²) / N²
```

Se calculan homomórficamente las dos componentes por separado:

```
sum_sq  = Σᵢ₌₀^{N−1} xᵢ²   (profundidad 1: auto-producto + rotate-and-sum)
sum     = Σᵢ₌₀^{N−1} xᵢ     (profundidad 0: suma + rotate-and-sum)
```

La varianza final se calcula en claro por el agregador tras el descifrado threshold:

```
var_unnorm = (N × sum_sq  −  sum²) mod t
```

El verificador comprueba que `decoded_sum_sq == expected_sum_sq` y `decoded_sum == expected_sum`. La `Correct` del BenchmarkRun es `true` únicamente si ambos son correctos.

### Protocolo distribuido

El dataset de N valores se divide entre dos partes: la parte 1 tiene los primeros M=N/2 valores y la parte 2 tiene los últimos M valores. Cada parte cifra su vector UNA SOLA VEZ; ese mismo ciphertext se usa para el cálculo de `sum_sq` (auto-producto) y de `sum` (solo rotaciones y sumas).

```
sum_sq = (Σᵢ v₁[i]²) + (Σᵢ v₂[i]²)   → evaluador auto-multiplica cada bloque
sum    = (Σᵢ v₁[i])  + (Σᵢ v₂[i])    → evaluador rota y suma cada bloque
```

### Estrategia multi-bloque

Idéntica a spec 009 (blockSize = MaxSlots/2 = 8192, 13 Galois keys). Cada parte divide sus M valores en K=⌈M/8192⌉ bloques rellenos de ceros.

| DB  | N (total) | M (por parte) | K bloques |
|-----|-----------|---------------|-----------|
| DB1 | 512       | 256           | 1         |
| DB2 | 100 000   | 50 000        | 7         |
| DB3 | 1 000 000 | 500 000       | 62        |

### Perfiles de parámetros (calibrados en spec 009)

| Perfil     | LogQ                        | LogP      | correct_std | correct_label |
|------------|-----------------------------|-----------|-------------|---------------|
| S1 "full"  | [56, 55, 55, 54]            | [55, 55]  | ✓           | ✓             |
| S2 "tight" | [38, 37, 50, 50]            | [50, 50]  | ✓           | ✗             |
| S3 "min"   | [35, 35]                    | [35, 35]  | ✗           | ✗             |

Los umbrales son los mismos que UC2 porque ambos computan una profundidad-1 HMul con las mismas claves colectivas. Ver `analisis-ruido-cf-labeling.md` para la explicación del hallazgo.

### Ventaja de comunicación en UC3

UC3 descifra **dos** cantidades (sum_sq y sum). En label, ambas tienen β a level=1, por lo que los shares son pequeños:

| Variante | CommBytes por run (aprox.) |
|----------|---------------------------|
| std      | ~4 MB (sum_sq a MaxLevel + sum a MaxLevel) |
| label    | ~2 MB (sum_sq a level=1 + sum a level=1)   |

Este beneficio ~2× es el doble del observado en UC1 y UC2 (donde solo se descifra una cantidad).

### Relación con otras specs

- Reutiliza harness (spec #008) con `ParamProfile` ya implementado en spec #009
- Usa spec #002, #003, #004 (igual que UC2)
- Replica la infraestructura de genCollectiveGaloisKeys de spec 009 (copy-paste al nuevo ejecutable)

---

## Interfaz Pública

### `benchmarks/uc3_variance/main.go`

Ejecutable sin API exportada. Flags:

```
-out   string  ruta del CSV de salida   (default: "results/uc3_variance.csv")
-reps  int     repeticiones por celda   (default: 20)
```

---

## Comportamiento Esperado

### UC3: operaciones por variante

Ambas partes tienen M=N/2 valores. El evaluador calcula `sum_sq` y `sum`.

**Variante `std`:**
```
Fase "setup":   NewMHEContext → pk colectiva
                GenCollectiveRelinKey → rlk (2 rondas)
                GenCollectiveGaloisKeys para {4096,...,1} → 13 galKeys
                evk = MemEvaluationKeySet(rlk, galKeys...)

Fase "precomp": v₁ = ds.Values[0..M-1], v₂ = ds.Values[M..N-1]
                expected_sum = (Σvⱼ[i]) mod t
                expected_sum_sq = (Σvⱼ[i]²) mod t

Fase "encrypt": Para cada bloque b:
                  ct₁[b] = Encrypt(bloque b de v₁)   ← un solo conjunto de cts por parte
                  ct₂[b] = Encrypt(bloque b de v₂)

Fase "eval":    // sum_sq: auto-producto por bloque → accumulate
                ct_sq_p1, ct_sq_p2 = nil
                Para cada bloque b:
                  ctSq1 = MulRelinNew(ct₁[b], ct₁[b])   ← auto-producto parte 1
                  Para step = 4096; step >= 1; step /= 2:
                    ctSq1 += RotateColumns(ctSq1, step)
                  ct_sq_p1 = ct_sq_p1 == nil ? ctSq1 : Add(ct_sq_p1, ctSq1)

                  ctSq2 = MulRelinNew(ct₂[b], ct₂[b])   ← auto-producto parte 2
                  [mismo rotate-and-sum]
                  ct_sq_p2 = ct_sq_p2 == nil ? ctSq2 : Add(ct_sq_p2, ctSq2)
                ct_sum_sq = Add(ct_sq_p1, ct_sq_p2)

                // sum: rotate-and-sum sin multiplicación
                ct_s_p1, ct_s_p2 = nil
                Para cada bloque b:
                  ctS1 = ct₁[b]
                  Para step = 4096; step >= 1; step /= 2:
                    ctS1 = Add(ctS1, RotateColumns(ctS1, step))   ← suma slot 0
                  ct_s_p1 = ct_s_p1 == nil ? ctS1 : Add(ct_s_p1, ctS1)
                  [idem para ct₂[b] → ct_s_p2]
                ct_sum = Add(ct_s_p1, ct_s_p2)

Fase "decrypt": CKS-to-zero para ct_sum_sq → decoded_sum_sq
                CKS-to-zero para ct_sum → decoded_sum
                commBytes = shares(ct_sum_sq) + shares(ct_sum)
                correct = (decoded_sum_sq == expected_sum_sq) && (decoded_sum == expected_sum)
```

**Variante `label`:**
```
Fase "setup":   (idéntico a std)

Fase "precomp": (idéntico a std)

Fase "encrypt": Para cada bloque b:
                  lct₁[b] = EncryptLabeled(ctx, bloque b de v₁)
                  lct₂[b] = EncryptLabeled(ctx, bloque b de v₂)

Fase "eval":    // sum_sq: auto-producto MultLabeled
                lct_sq = nil
                Para cada bloque b:
                  lctSq1 = MultLabeled(ctx, rlk, lct₁[b], lct₁[b])
                  Para step = 4096; step >= 1; step /= 2:
                    lctSq1 = SumLabeled(ctx, lctSq1, RotateColumns(params, lctSq1, step, evk))
                  lct_sq = lct_sq == nil ? lctSq1 : SumLabeled(ctx, lct_sq, lctSq1)
                  [idem para lct₂[b] → acumula en lct_sq]

                // sum: rotate-and-sum sin multiplicación
                lct_s = nil
                Para cada bloque b:
                  lctS1 = lct₁[b]
                  Para step = 4096; step >= 1; step /= 2:
                    lctS1 = SumLabeled(ctx, lctS1, RotateColumns(params, lctS1, step, evk))
                  lct_s = lct_s == nil ? lctS1 : SumLabeled(ctx, lct_s, lctS1)
                  [idem para lct₂[b] → acumula en lct_s]

Fase "decrypt": GenLabeledDecryptionShare × 2 para lct_sq → decoded_sum_sq
                GenLabeledDecryptionShare × 2 para lct_s → decoded_sum
                commBytes = shares(lct_sq.β) + shares(lct_s.β)  ← ambos a level=1
                correct = (decoded_sum_sq == expected_sum_sq) && (decoded_sum == expected_sum)
```

### Verificación del resultado esperado

```go
ds := harness.GenerateDataset(db.n, 42, plaintextModulus)
// Cada valor ≤ 1000: xᵢ² ≤ 10^6 < t. Suma acumulada ≤ N×10^6 ≤ 10^12 < 2^64 → sin overflow.
var expectedSum, expectedSumSq uint64
for _, v := range ds.Values {
    expectedSum = (expectedSum + v) % plaintextModulus
    expectedSumSq = (expectedSumSq + v*v%plaintextModulus) % plaintextModulus
}
// La varianza se computa en claro (solo para informar, no para el campo Correct):
// var_unnorm = (uint64(ds.N)*expectedSumSq - expectedSum*expectedSum + t) % t
```

### Matriz de experimentos

```
3 perfiles × 2 variantes × 3 DBs × 20 reps × 5 fases = 1800 filas en CSV
```

### Ejemplo de bloque CSV

```
UC3,std,DB1,512,1,setup,340.0,75000000,0,0,false,full
UC3,std,DB1,512,1,precomp,0.1,0,0,0,false,full
UC3,std,DB1,512,1,encrypt,2.5,51200,0,0,false,full
UC3,std,DB1,512,1,eval,5.8,204800,0,0,false,full
UC3,std,DB1,512,1,decrypt,10.4,16384,6720,1,true,full
```

---

## Casos Edge

- [ ] S2/S3: parámetros inválidos → log warning, skip perfil, no abortar
- [ ] `correct=false` en S2 (label) y S3 (ambos) es el resultado esperado, no un error
- [ ] Último bloque con < blockSize valores: relleno de ceros → no contamina la suma ni el auto-producto
- [ ] Auto-producto `MultLabeled(ctx, rlk, lct, lct)`: seguro porque tensorStandard escribe en opOut separado; la compartición de ring.Poly en los parámetros de entrada es read-only
- [ ] `N` impar: parte 1 toma `⌈N/2⌉`, parte 2 toma `⌊N/2⌋`; expected_sum y expected_sum_sq usan los valores reales
- [ ] CommBytes incluye shares de AMBAS decryptions (sum_sq + sum)
- [ ] `Correct = false` si cualquiera de los dos valores descifrados es incorrecto

---

## Dependencias

- Spec #008: harness (`BenchmarkRun` con `ParamProfile`, `AppendCSV`, `GenerateDataset`, `Run`)
- Spec #009: perfiles S1/S2/S3 calibrados, función `genCollectiveGaloisKeys`, función `blocks`
- Spec #002: `NewMHEContext`, `EncryptLabeled`
- Spec #003: `GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`, `DecryptThresholdLabeled`
- Spec #004: `MultLabeled`, `GenCollectiveRelinKey`, `RotateColumns`, `SumLabeled`
- Lattigo: `bgv`, `multiparty.GaloisKeyGenProtocol`, `multiparty.KeySwitchProtocol`, `rlwe`, `ring`

---

## Criterios de Aceptación

- [x] `go build ./benchmarks/...` exitoso
- [x] `go vet ./benchmarks/...` sin warnings
- [x] `go run ./benchmarks/uc3_variance/ -reps 1` completa sin errores y produce CSV
- [x] CSV contiene `3 perfiles × 2 variantes × 3 DBs × 1 rep × 5 fases` = 90 filas para `-reps 1`
- [x] S1: `correct=true` para ambas variantes en los tres DBs
- [x] S2 [38,37,50,50]: `correct=false` para label, `correct=true` para std
- [x] S3 [35,35]: `correct=false` para ambas variantes
- [x] Auto-producto: `MultLabeled(ctx, rlk, lct, lct)` produce el cuadrado correcto (verificado en S1)
- [x] CommBytes de label ≈ la mitad que std en S1 (ambas quantities a level=1 vs MaxLevel)
- [x] `go test -race ./benchmarks/...` sin data races

---

## Notas de Implementación

### Copia de infraestructura de UC2

Las funciones `genCollectiveGaloisKeys`, `blocks`, `rotationGaloisEls`, `shareSize` y los `profiles` se copian de `benchmarks/uc2_dotproduct/main.go` al nuevo `benchmarks/uc3_variance/main.go`. Son idénticas: mismo `blockSize`, mismos `logQ`, mismos galois elements.

### Compute sum con lcts originales, no con copias

En el eval para la suma en label, los bloques `lct₁[b]` y `lct₂[b]` se reutilizan del paso de encrypt. **No es necesario re-encriptar.** La función `RotateColumns` ahora hace deep-copy del β (fix de spec 009), por lo que reutilizar los lcts es seguro.

### Auto-producto en label y std

Para std: `eval.MulRelinNew(ct, ct)` activa el path de squaring en tensorStandard (`op0.El() == op1.El()`).

Para label: `MultLabeled(ctx, rlk, lct, lct)` pasa la misma variable dos veces. Como Go pasa structs por valor, dentro de `Mult` son copias separadas con los mismos datos; `op0.El() != op1.El()` (punteros distintos), pero el resultado es algebraicamente correcto (non-squaring path produce el mismo resultado).

### CommBytes en decrypt con dos ciphertexts

```go
// std decrypt: dos CKS, uno para sum_sq (a MaxLevel) y otro para sum (a MaxLevel)
commBytes += shareSize(params, ctSumSq.Level()) * nParties
commBytes += shareSize(params, ctSum.Level()) * nParties

// label decrypt: dos threshold decrypts a level=1
commBytes += shareSize(params, shareSq.Value.Level()) * nParties
commBytes += shareSize(params, shareSum.Value.Level()) * nParties
```

### Lo que NO implementa esta spec

- Cálculo completamente homomórfico de N²×Var (requeriría elevar sum al cuadrado homomórficamente, profundidad 2)
- Varianza en coma flotante (el benchmark usa aritmética modular mod t)
- UC4+ (especificaciones futuras)
- Scripts Python de análisis estadístico
- Más de 2 partes
