# Mask Bound Fix for CF Labeling Encryption

**ID:** 014  
**Estado:** Done  
**Fecha:** 2026-06-10  
**Autor:** juanmartin

---

## Objetivo

Añadir `EncryptWithMaskBound` y `EncryptLabeledWithMaskBound` para permitir limitar el rango de las máscaras aleatorias generadas durante el cifrado CF labeling. Esto evita el wrap-around que causa explosión de ruido en la multiplicación CT×PT posterior.

---

## Contexto

El `Encrypt` actual genera máscaras `b_i ∈ [0, √t ≈ 8120)`. Para valores en [1,1000], el
canonical(a_i) = v_i − b_i ∈ [−8119, 1000]. Esto hace que ||INTT(a)||_∞ ≈ N/2 × 4060 = 2^25,
amplificando el ruido de las multiplicaciones CT×PT en ~4060× respecto al caso b_i=0.

Fix: exponer un parámetro `maskBound`. Con `maskBound = min(values_in_block) ≈ 1`, todos los
b_i = 0 y canonical(a_i) = v_i ≤ 1000, reduciendo ||INTT(a)||_∞ a ≈ N/2 × 500 = 2^22. El
ruido CT×PT baja ~8× (3 bits).

**Resultado real benchmarkeado:** La reducción de 8× en noise CT×PT no es suficiente para S3/min
porque el rotate-and-sum de 13 pasos amplifica el ruido acumulado por 2^13, llevándolo de ~2^33
(CT×PT con mask fix) a ~2^46 >> budget 2^43. Tanto `label_compact` como `label_compact_mb` dan
correct=false al 100% en profile=min. El fix correcto para S3/min es spec 015 (CF-scalar), que
evita completamente la multiplicación CT×PT polynomial.

El mask bound fix SÍ reduce noise en ~8× y es una optimización válida como base para spec 015.

Descubierto en exp1–exp5 (ver `~/vault/proyectos/tfm-uvigo/analisis-label-vs-std-experimental.md`).

---

## Interfaz Pública

```go
// EncryptWithMaskBound is like Encrypt but uses maskBound instead of √t as the
// upper bound for random mask generation. Setting maskBound ≤ min(values) prevents
// wrap-around, keeping |canonical(a_i)| ≤ vMax in subsequent CT×PT multiplications.
func EncryptWithMaskBound(params Parameters, key rlwe.EncryptionKey, value []uint64, maskBound uint64) (PlaintextLabeledciphertext, error)

// EncryptLabeledWithMaskBound is like EncryptLabeled but uses the given maskBound
// instead of the default √t. Set maskBound = min(values) to prevent wrap-around.
func EncryptLabeledWithMaskBound(ctx MHEContext, values []uint64, maskBound uint64) (PlaintextLabeledciphertext, error)
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `values=[100,200,300]`, `maskBound=1` | `a_i = v_i` (b_i=0 siempre), no wrap-around |
| `values=[501..1000]`, `maskBound=500` | `a_i = v_i − b_i ≥ 1`, no wrap-around |
| `Decrypt(EncryptWithMaskBound(...))` | recupera `values` exactamente |
| maskBound > min(values) | puede haber wrap-around (no error, comportamiento documentado) |

---

## Casos Edge

- [ ] `maskBound = 1` → b siempre es 0, a = v. Correcto; `Decrypt` recupera v.
- [ ] `maskBound = 0` → error o panic (RandUniform con bound=0)
- [ ] Slots de padding (value[i] = 0 con maskBound > 0) → a_i = (0 − b_i + t) % t puede ser grande; no afecta porque son slots vacíos ignorados en el cómputo.
- [ ] `maskBound ≥ t` → reducir a t−1 o documentar como precondición del caller.

---

## Dependencias

- Spec #002 (mhe-labeled-encrypt) — `Encrypt` existente que se extiende.
- Spec #011 (uc4-varianza-compactacion-beta) — `label_compact` benchmark que se mejora.

---

## Criterios de Aceptación

- [x] `TestEncryptWithMaskBound` table-driven en `labeling/labeling_test.go` pasando
- [x] `TestEncryptLabeledWithMaskBound` en `labeling/mhe_labeling_test.go` pasando
- [x] `EncryptWithMaskBound` y `EncryptLabeledWithMaskBound` implementadas con GoDoc en inglés
- [x] Variante `label_compact_mb` en `benchmarks/uc4_variance_compact/main.go`
- [x] `label_compact_mb`: noise ~8× menor que `label_compact` (benchmarkeado, 3 bits de mejora)
- [x] `std`: Correct=false en profile=min (confirma que std explota en S3/min)
- [x] `go vet ./...` sin warnings
- [x] `go test ./labeling/... -race -count=1` sin data races

**Nota:** `label_compact_mb` da correct=false al 100% en profile=min (igual que `label_compact`).
El fix de S3/min requiere spec 015 (CF-scalar) que elimina el CT×PT polynomial.

---

## Notas de Implementación

`ring.RandUniform(prng, n, mask)` donde `mask = nextPowerOfTwo(maskBound) − 1`. La versión original usa `mask = uint64(1<<bits.Len64(maskBound) − 1)` para que `n % mask` sea uniforme. La implementación de `EncryptWithMaskBound` debe seguir exactamente el mismo patrón, sólo cambiando el argumento `n` a `maskBound`.

El helper `minValInBlock(blk []uint64) uint64` en el benchmark debe ignorar ceros (slots de padding).
