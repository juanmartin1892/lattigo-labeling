# UC4: Varianza con Compactación de β en Descifrado Threshold

**ID:** 011  
**Estado:** Ready  
**Fecha:** 2026-06-08  
**Autor:** juanmartin

---

## Objetivo

Implementar el cuarto caso de uso (`benchmarks/uc4_variance_compact/main.go`) que demuestra la **compactación de β en el auto-producto** como contribución original: cuando se aplica `MultOverflow` seguido de un árbol de rotate-and-sum sobre el mismo ciphertext, todos los pares β del resultado son rotaciones del único β original. Por tanto, el descifrado threshold puede ejecutarse con **una sola ronda de CKS** (sobre β_orig) en lugar de O(log n) rondas, reduciendo la comunicación de descifrado de O(K × 2 log n × nParties) a O(K × nParties).

Adicionalmente, `MultOverflow` no usa relinearización, por lo que el protocolo de generación colectiva de rlk (2 rondas interactivas) queda eliminado del setup.

---

## Contexto

### La proposición matemática (§5 del documento de referencia)

Sea `C = (a, β)` un labeled ciphertext y sea `C² = MultOverflow(C, C)`. Después de `L = log₂(blockSize)` pasos de rotate-and-sum:

```
Paso 0: MultOverflow(C, C) → β_pairs = [(β, β)]
Paso 1: SumOverflow(C², rot_k1(C²)) → β_pairs = [(β, β), (rot_k1(β), rot_k1(β))]
Paso 2: → β_pairs = [(β,β), (rot_k1(β),rot_k1(β)), (rot_k2(β),rot_k2(β)), (rot_{k1+k2}(β),rot_{k1+k2}(β))]
...
Paso L: β_pairs tiene 2^L = 2·blockSize pares, todos de la forma (rot_k(β), rot_k(β))
```

**Proposición.** Para cualquier par (β₁ᵢ, β₂ᵢ) en el resultado: β₁ᵢ = β₂ᵢ = rot_{kᵢ}(β), donde β es el componente original y kᵢ es el desplazamiento público del árbol diádico.

**Consecuencia para el descifrado threshold.** El descifrado estándar `DecryptThresholdOverflow` necesita descifrar 2^(L+1) componentes β. Con la compactación:

1. Descifrar β_orig una sola vez → b (vector en Mᴺ)
2. Calcular b_sq_sum = Σₖ rot_k(b ⊙ b) mod t en claro (sin comunicación)
3. Descifrar α una sola vez → plainAlpha
4. Resultado: `(plainAlpha + b_sq_sum) mod t`

### Diferencia con UC3

| Aspecto | UC3 label | UC4 label_compact |
|---------|-----------|-------------------|
| Multiplicación | `MultLabeled` (relineariza β → size 1 at level=1) | `MultOverflow` (sin relin, β se expande pero luego se compacta) |
| Protocolo setup | CKG + RKG (2 rondas extra para rlk) | CKG solamente |
| β en decrypt | 1 ciphertext a level=1 por bloque | 1 ciphertext a MaxLevel por bloque (β_orig) |
| CommBytes sum_sq | `K × size(level=1) × 2` | `K × size(MaxLevel) × 2` |
| Rondas CKS reales | 1 por bloque | 1 por bloque (compactado desde 2log(n)) |

El beneficio principal de UC4 no es la comunicación absoluta (β_orig está a MaxLevel, no a level=1) sino eliminar la generación colectiva de rlk y demostrar que el número de rondas de descifrado no crece con n.

### Por qué no se cambia UC3

UC3 usa `MultLabeled` (con relinearización). Eso produce β a level=1, lo cual reduce comunicación pero requiere rlk colectivo. Son dos trade-offs distintos:
- UC3: prioriza comunicación mínima en threshold (level=1, rlk requerida)
- UC4: prioriza setup mínimo (sin rlk) con compactación que evita la explosión de rondas

Ambos benchmarks juntos ilustran el espacio de diseño de CF labeling en MHE.

---

## Interfaz Pública

### Nuevas funciones en `labeling/mhe_labeling.go`

```go
// CompactSelfProductShare holds one party's CKS shares for the compact threshold
// decryption of a self-product CiphertextLabeledciphertext. Only the original β
// (before MultOverflow + rotate-and-sum) and the α component need shares.
type CompactSelfProductShare struct {
    Alpha LabeledDecryptionShare
    Beta  LabeledDecryptionShare
}

// GenCompactSelfProductShare generates party i's compact decryption shares for a
// self-product result. betaOrig must be the β component of the original
// PlaintextLabeledciphertext that was passed to MultOverflow as both operands.
// Only one CKS share is generated for betaOrig (instead of one per β pair).
func GenCompactSelfProductShare(
    ctx MHEContext,
    sk *rlwe.SecretKey,
    clct CiphertextLabeledciphertext,
    betaOrig *rlwe.Ciphertext,
) (CompactSelfProductShare, error)

// AggregateCompactSelfProductShares combines all parties' CompactSelfProductShares
// into a single share for use in DecryptThresholdCompact.
func AggregateCompactSelfProductShares(
    ctx MHEContext,
    shares []CompactSelfProductShare,
) (CompactSelfProductShare, error)

// DecryptThresholdCompact recovers the slot-sum of squares from a self-product
// CiphertextLabeledciphertext using the compact β representation.
//
// betaOrig must be the same β passed to GenCompactSelfProductShare.
// rotOffsets must be the rotation steps used in the rotate-and-sum tree, in the
// same order they were applied (e.g. []int{4096, 2048, 1024, ..., 1}).
//
// Internally: decrypts betaOrig once → b; computes b_sq_sum = Σ rot_k(b⊙b) in
// plaintext; decrypts α; returns (plainAlpha + b_sq_sum) mod t.
func DecryptThresholdCompact(
    ctx MHEContext,
    combined CompactSelfProductShare,
    clct CiphertextLabeledciphertext,
    betaOrig *rlwe.Ciphertext,
    rotOffsets []int,
) ([]uint64, error)
```

### Nueva función en `labeling/mhe_labeling.go`

```go
// MultOverflowLabeledFree multiplies two PlaintextLabeledciphertexts using the overflow
// technique without requiring a relinearization key. Unlike MultOverflowLabeled, this
// function does not perform any key-switching and requires only the collective public key
// available in ctx.
//
// This is the correct function to use when the caller intends to apply the compact
// self-product decryption (DecryptThresholdCompact), since no rlk is generated.
func MultOverflowLabeledFree(
    ctx MHEContext,
    lct1, lct2 PlaintextLabeledciphertext,
) (CiphertextLabeledciphertext, error)
```

### Ejecutable `benchmarks/uc4_variance_compact/main.go`

Sin API exportada. Flags:

```
-out   string  ruta del CSV de salida   (default: "results/uc4_variance_compact.csv")
-reps  int     repeticiones por celda   (default: 20)
```

---

## Comportamiento Esperado

### Protocolo UC4

Mismos datasets que UC3 (DB1/DB2/DB3) y mismos perfiles S1/S2/S3.

**Variante `std`:** idéntica a UC3 std (MulRelinNew + rotate-and-sum + CKS threshold).

**Variante `label_compact`:**

```
Setup:    NewMHEContext → pk colectiva
          GenCollectiveGaloisKeys → 13 galKeys  ← igual que UC3
          (sin GenCollectiveRelinKey)            ← diferencia clave

Encrypt:  lct₁[b] = EncryptLabeled(ctx, bloque b de v₁)
          lct₂[b] = EncryptLabeled(ctx, bloque b de v₂)
          betaOrig₁[b] = &lct₁[b].elementsB[0][0]  ← puntero guardado antes del eval
          betaOrig₂[b] = &lct₂[b].elementsB[0][0]

Eval:     // sum_sq con MultOverflow (sin rlk) + rotate-and-sum
          clct_sq = nil
          Para bloque b de parte 1:
            clctSq1 = MultOverflowLabeledFree(ctx, lct₁[b], lct₁[b])
            Para step = 4096; step >= 1; step /= 2:
              clctSq1 = SumOverflowCiphertextLabeled(ctx, clctSq1,
                          RotateColumnsOverflow(params, clctSq1, step, evk))
            clct_sq = (clct_sq == nil) ? clctSq1 : SumOverflowCiphertextLabeled(ctx, clct_sq, clctSq1)
          [idem para parte 2]

          // sum con SumLabeled (igual que UC3 label)
          lct_s = nil
          [mismo rotate-and-sum sin multiplicación]

Decrypt:  // sum_sq: compact (1 ronda de CKS por bloque, reconstrucción en claro)
          Para cada bloque b:
            sharesSq = [GenCompactSelfProductShare(ctx, sk_j, clct_sq_block, betaOrig[b]) para j=1,2]
            combinedSq = AggregateCompactSelfProductShares(ctx, sharesSq)
            sumSqBlock = DecryptThresholdCompact(ctx, combinedSq, clct_sq_block, betaOrig[b], rotOffsets)
          sumSq = acumular slot 0 de cada bloque

          // sum: estándar (igual que UC3 label)
          [GenLabeledDecryptionShare + DecryptThresholdLabeled]

          commBytes = shares(betaOrig × K + α × K) × 2  ← solo 2K shares en lugar de 2K×2×log(n)
          correct = (sumSq == expectedSumSq) && (sum == expectedSum)
```

### Métrica principal: CommBytes de descifrado

Para DB3 (K=62 bloques, nParties=2, log(blockSize)=13):

| Variante | Shares en decrypt | CommBytes aprox. |
|----------|-------------------|-----------------|
| std | 2 × CKS shares a MaxLevel | ~4 MB |
| UC3 label | 2 × CKS shares a level=1 | ~2 MB |
| UC4 label_compact | 2 × (1 β_orig + 1 α) × K a MaxLevel | ~4 MB × K (grande) |

> **Nota:** CommBytes absolutos de UC4 son mayores que UC3 porque β_orig está a MaxLevel. El beneficio se mide como **número de rondas de CKS**, no en bytes totales: UC4 usa 2K rondas (constante en log n) frente a 2K×2^13 = 16384K rondas del overflow ingenuo sin compactación.

El benchmark incluye también una variante `label_naive` (overflow sin compactación) para medir el ahorro real.

---

## Casos Edge

- [ ] `betaOrig` después de rotate-and-sum: la β original puede haber sido mutada si no se hace deep-copy antes del eval. El benchmark debe capturar `betaOrig` antes de llamar a `MultOverflowLabeledFree`.
- [ ] Árbol de rotaciones incompleto (K=1 bloque, n < blockSize): `rotOffsets` contiene solo los pasos aplicados realmente.
- [ ] S2/S3: `correct=false` esperado para `label_compact` en S2 (mismo fenómeno que UC3: β_orig a MaxLevel tiene más presupuesto que level=1, verificar si el umbral cambia respecto a UC3).
- [ ] `MultOverflowLabeledFree` con ambos operandos siendo el mismo lct: la función debe ser segura para `lct1 == lct2` (misma referencia).
- [ ] `rotOffsets` vacío: `DecryptThresholdCompact` debe devolver el valor sin rotate-and-sum (un solo bloque sin rotaciones).

---

## Dependencias

- Spec #008: harness con `ParamProfile`
- Spec #009: perfiles S1/S2/S3, `genCollectiveGaloisKeys`, `blocks`
- Spec #010: referencia para el cálculo de varianza (sum_sq + sum)
- Spec #002: `NewMHEContext`, `EncryptLabeled`
- Spec #003: `GenLabeledDecryptionShare`, `DecryptThresholdLabeled` (para sum)
- Spec #004: `MultOverflow`, `SumOverflowCiphertext`, `RotateColumnsOverflow`
- Spec #005/006: `GenOverflowDecryptionShare` / `DecryptThresholdOverflow` (para variante naive de comparación)
- Documento: `~/vault/proyectos/tfm-uvigo/La varianza mediante cifrado homomórfico multi-partido.md` §5

---

## Criterios de Aceptación

- [ ] `go build ./benchmarks/...` exitoso
- [ ] `go vet ./benchmarks/...` sin warnings
- [ ] `go test -race ./labeling/... ./benchmarks/...` sin data races
- [ ] `go run ./benchmarks/uc4_variance_compact/ -reps 1` produce CSV con 90 filas (3×2×3×1×5)
- [ ] S1: `correct=true` para std y label_compact en los tres DBs
- [ ] S2: `correct=true` para std; verificar empíricamente si label_compact falla (β_orig a MaxLevel puede cambiar el umbral respecto a UC3)
- [ ] S3: `correct=false` para ambas variantes
- [ ] CommBytes de label_compact = `2 × K × (size(β_MaxLevel) + size(α)) × nParties` (verificado en CSV)
- [ ] CommBytes de label_naive = `2 × K × 2^(L+1) × size(β_MaxLevel) × nParties` (verificado en CSV)
- [ ] Tests unitarios para `GenCompactSelfProductShare`, `AggregateCompactSelfProductShares`, `DecryptThresholdCompact`
- [ ] Test que verifica que `DecryptThresholdCompact` produce el mismo resultado que `DecryptThresholdOverflow` (naive) para el mismo ciphertext

---

## Notas de Implementación

### MultOverflowLabeledFree: por qué no necesita rlk

`MultOverflow` en `labeling.go` usa `evaluator.Mul(β, plaintext, out)` (multiplicación ciphertext-por-plaintext) y `Encryptor.EncryptNew`. Ninguna de estas operaciones requiere la clave de evaluación. El `evk` pasado al evaluator es ignorado en estos paths. `MultOverflowLabeledFree` simplemente llama `MultOverflow(ctx.Params, lct1, lct2, ctx.CollectivePK, nil)`.

### Captura de betaOrig antes del eval

En UC3 label, `RotateColumns` hace deep-copy (fix de spec 009), así que el β original de `lct` no se muta durante el eval. Sin embargo, `MultOverflowLabeledFree` captura β por valor (Go pasa `rlwe.Ciphertext` por valor en el struct, pero los `ring.Poly` subyacentes son punteros). El benchmark debe copiar explícitamente el β antes de llamar a `MultOverflowLabeledFree`:

```go
betaOrig := *rlwe.NewCiphertext(ctx.Params.Parameters, lct.elementsB[0][0].Degree(), lct.elementsB[0][0].Level())
// deep-copy ring.Poly data (igual que en RotateColumns)
```

O exponer un método en `PlaintextLabeledciphertext` que devuelva una copia profunda del β.

### Reconstrucción en claro en DecryptThresholdCompact

```
b = Dec_threshold(betaOrig)  // vector de MaxSlots uint64
b_sq[i] = (b[i] * b[i]) % t  para todo i
b_sq_sum = b_sq
Para cada offset k en rotOffsets:
    b_sq_sum[i] = (b_sq_sum[i] + b_sq[(i + k) % halfSlots]) % t
plainAlpha = Dec_threshold(clct.elementsA)
result[i] = (plainAlpha[i] + b_sq_sum[i]) % t
```

La reconstrucción respeta la semántica BGV de rotación en dos mitades independientes (igual que `RotateColumns`).

### Variante label_naive para comparación

Usa `GenOverflowDecryptionShare` + `DecryptThresholdOverflow` existentes (sin modificación). El CommBytes lo calcula el benchmark sumando `shareSize × número de componentes β`. Sirve como baseline para cuantificar el ahorro de la compactación.

### Setup simplificado

UC4 label_compact llama solo a `NewMHEContext` + `genCollectiveGaloisKeys`. No llama a `GenCollectiveRelinKey`. El benchmark mide este ahorro en la fase "setup".
