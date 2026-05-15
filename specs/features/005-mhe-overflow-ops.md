# MHE Phase 5: Overflow Operations on Labeled Ciphertexts

**ID:** 005  
**Estado:** Done  
**Fecha:** 2026-05-15  
**Autor:** juanmartin

---

## Objetivo

Exponer adaptadores MHE para las tres operaciones overflow — `MultOverflowLabeled`, `SumOverflowLabeled` y `SumOverflowCiphertextLabeled` — de modo que el evaluador pueda operar sobre `CiphertextLabeledciphertext` cifrados bajo la clave pública colectiva sin conocer ningún share secreto. Estas operaciones extienden la profundidad multiplicativa más allá de lo que permite `MultLabeled`.

---

## Contexto

La técnica de overflow almacena el componente `α` como un `CiphertextElement` (en lugar de `PlaintextElements`) para diferir el ruido: `α = Enc(pk, a₁·a₂) + a₁β₂ + a₂β₁`. Esto permite multiplicaciones adicionales sobre resultados intermedios, que es la principal ventaja del labeling en profundidad multiplicativa.

Spec 004 adapta `Sum` y `Mult` (que producen `PlaintextLabeledciphertext`) para MHE. Esta spec extiende ese patrón a las funciones overflow, que producen y consumen `CiphertextLabeledciphertext`.

En el flujo completo:
1. Las partes cifran sus datos con `EncryptLabeled` → `PlaintextLabeledciphertext`.
2. El evaluador usa `MultOverflowLabeled` → produce `CiphertextLabeledciphertext`.
3. El evaluador puede continuar con `SumOverflowLabeled` / `SumOverflowCiphertextLabeled`.
4. El descifrado threshold de `CiphertextLabeledciphertext` — que requiere protocolos adicionales porque `α` está cifrado — es competencia de spec 006.

Para los tests de esta spec se usa `DecryptOverflow(params, skIdeal, clct)` como oráculo de correctitud; `skIdeal` existe únicamente en el contexto de test, igual que en specs 002–004.

**Relación con otras specs:**
- Depende de spec 002 (`MHEContext`, `EncryptLabeled`).
- Depende de spec 004 (`GenCollectiveRelinKey`; el `rlk` es input de `MultOverflowLabeled`).
- Spec 006 implementará el descifrado threshold de `CiphertextLabeledciphertext`.

**Archivos a modificar:** `labeling/mhe_labeling.go` (añadir funciones), `labeling/mhe_labeling_test.go` (añadir tests).

---

## Interfaz Pública

```go
// MultOverflowLabeled multiplies two PlaintextLabeledciphertexts encrypted under the
// same MHEContext collective public key using the overflow technique, returning a
// CiphertextLabeledciphertext that supports deeper multiplicative depth.
//
// The evaluator does not need any secret key share; it uses ctx.CollectivePK for
// the fresh encryption of the a₁·a₂ component and rlk for the evaluation key set.
//
// The overflow formula is:
//   α = Enc(pk_col, a₁·a₂) + a₁·β₂ + a₂·β₁
//   elementsB = [β₁, β₂]
//
// Returns an error if rlk is nil or if either ciphertext contains no ciphertext component.
func MultOverflowLabeled(ctx MHEContext, rlk *rlwe.RelinearizationKey, lct1, lct2 PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error)

// SumOverflowLabeled adds a CiphertextLabeledciphertext and a PlaintextLabeledciphertext
// encrypted under the same MHEContext, returning a CiphertextLabeledciphertext.
//
// The evaluator does not need any secret key share. The algebra is:
//   α_out = α₁ + a₂   (ciphertext + plaintext addition)
//   elementsB_out = [β₁…, β₂]  (B components concatenated)
//
// Returns an error if either operand contains no ciphertext component.
func SumOverflowLabeled(ctx MHEContext, clct CiphertextLabeledciphertext, lct PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error)

// SumOverflowCiphertextLabeled adds two CiphertextLabeledciphertexts encrypted under
// the same MHEContext, returning a CiphertextLabeledciphertext.
//
// The evaluator does not need any secret key share. The algebra is:
//   α_out = α₁ + α₂   (ciphertext addition)
//   elementsB_out = [β₁…, β₂…]  (all B components concatenated)
//
// Returns an error if either operand contains no ciphertext or A component.
func SumOverflowCiphertextLabeled(ctx MHEContext, clct1, clct2 CiphertextLabeledciphertext) (CiphertextLabeledciphertext, error)
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada (DecryptOverflow con skIdeal) |
|---------|----------------|
| `MultOverflowLabeled(ctx, rlk, Enc([3,…]), Enc([4,…]))` | `[12,…]` |
| `MultOverflowLabeled(ctx, rlk, Enc([1,…]), Enc([0,…]))` | `[0,…]` |
| `MultOverflowLabeled(ctx, rlk, Enc([PT-1,…]), Enc([2,…]))` | `[(PT-1)×2 mod T,…]` |
| `SumOverflowLabeled(ctx, MultOverflow(Enc([3]), Enc([4])), Enc([5]))` | `[17,…]` |
| `SumOverflowCiphertextLabeled(ctx, MultOverflow(Enc([3]),Enc([4])), MultOverflow(Enc([2]),Enc([5])))` | `[22,…]` (12 + 10) |
| `MultOverflowLabeled(ctx, nil, lct1, lct2)` | error descriptivo |
| `MultOverflowLabeled(ctx, rlk, emptyLct, lct2)` | error descriptivo |
| `SumOverflowLabeled(ctx, emptyClct, lct)` | error descriptivo |
| `SumOverflowCiphertextLabeled(ctx, emptyClct, clct2)` | error descriptivo |

---

## Casos Edge

- [ ] `MultOverflowLabeled` con `rlk == nil` retorna error (no panic)
- [ ] `MultOverflowLabeled` con `lct` sin `elementsB` retorna error (no panic)
- [ ] `SumOverflowLabeled` con `clct` sin `elementsA` retorna error (no panic)
- [ ] `SumOverflowLabeled` con `lct` sin `elementsB` retorna error (no panic)
- [ ] `SumOverflowCiphertextLabeled` con algún operando vacío retorna error (no panic)
- [ ] Multiplicación con producto que desborda `T`: resultado correcto módulo T
- [ ] Round-trip N=2: `DecryptOverflow(skIdeal, MultOverflowLabeled(lct1, lct2)) == m1×m2 mod T`
- [ ] Round-trip N=3: mismo esquema con tres parties
- [ ] `SumOverflowLabeled` sobre resultado de `MultOverflowLabeled`: descifra a `m1·m2 + m3`
- [ ] `SumOverflowCiphertextLabeled` sobre dos `MultOverflowLabeled`: descifra a `m1·m2 + m3·m4`

---

## Dependencias

- Spec #002: `MHEContext`, `EncryptLabeled`
- Spec #004: `GenCollectiveRelinKey` (produce el `rlk` requerido por `MultOverflowLabeled`)
- Funciones existentes a envolver: `MultOverflow`, `SumOverflow`, `SumOverflowCiphertext` (en `labeling.go`)
- Paquetes ya en `go.mod`: `github.com/tuneinsight/lattigo/v6/core/rlwe`

---

## Criterios de Aceptación

- [x] `go build ./...` exitoso
- [x] `go vet ./...` sin warnings
- [x] `go test -race ./labeling/` sin data races
- [x] `TestMultOverflowLabeled`: round-trip N=2 (3×4, 1×0, (PT-1)×2) + errors (nil rlk, lct vacío)
- [x] `TestSumOverflowLabeled`: round-trip composición `MultOverflow + SumOverflow` + errors
- [x] `TestSumOverflowCiphertextLabeled`: round-trip composición `MultOverflow + MultOverflow + SumOverflowCiphertext` + errors
- [x] `TestOverflowOpsN3`: `MultOverflowLabeled` y `SumOverflowLabeled` con tres parties
- [x] GoDoc completo en inglés para `MultOverflowLabeled`, `SumOverflowLabeled`, `SumOverflowCiphertextLabeled`
- [x] Verificación matemática: `DecryptOverflow(skIdeal, MultOverflowLabeled(lct1,lct2)) == m1×m2 mod T`
- [x] Verificación matemática: `DecryptOverflow(skIdeal, SumOverflow(Mult(lct1,lct2),lct3)) == m1·m2+m3 mod T`

---

## Notas de Implementación

### Estrategia: delegación directa

Igual que spec 004, las tres funciones son thin wrappers sobre sus equivalentes single-party:

```go
func MultOverflowLabeled(ctx MHEContext, rlk *rlwe.RelinearizationKey, lct1, lct2 PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error) {
    if rlk == nil { return ..., errors.New("...") }
    // validar elementsB de lct1 y lct2
    evk := GenerateMemEvaluationKeySet(rlk)
    return MultOverflow(ctx.Params, lct1, lct2, ctx.CollectivePK, evk)
}

func SumOverflowLabeled(ctx MHEContext, clct CiphertextLabeledciphertext, lct PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error) {
    // validar clct.elementsA y lct.elementsB
    return SumOverflow(ctx.Params, clct, lct)
}

func SumOverflowCiphertextLabeled(ctx MHEContext, clct1, clct2 CiphertextLabeledciphertext) (CiphertextLabeledciphertext, error) {
    // validar ambos clct.elementsA
    return SumOverflowCiphertext(ctx.Params, clct1, clct2)
}
```

### Validación de `CiphertextLabeledciphertext` vacío

Un `CiphertextLabeledciphertext{}` tiene `elementsA == nil`. La validación es:

```go
if clct.elementsA == nil {
    return ..., errors.New("...: clct contains no A component")
}
```

Para `SumOverflow`/`SumOverflowCiphertext`, `SumOverflow` accede a `ct1 := (*rlwe.Ciphertext)(labeledciphertext1.elementsA)` — panics si nil. Validar antes de delegar.

### Tests: oráculo con `skIdeal`

Los tests usan `buildMHETestSetup` que ya devuelve `skIdeal`. Para descifrar el resultado:

```go
got, err := DecryptOverflow(params, skIdeal, clct)
```

El `skIdeal` existe únicamente en el helper de test; ninguna función de producción lo recibe.

### Composición para tests de `SumOverflow*`

```
lct1 = EncryptLabeled(ctx, [3])
lct2 = EncryptLabeled(ctx, [4])
lct3 = EncryptLabeled(ctx, [5])
clct12 = MultOverflowLabeled(ctx, rlk, lct1, lct2)   // α=Enc(12), B=[β1,β2]
result  = SumOverflowLabeled(ctx, clct12, lct3)        // α=Enc(17), B=[β1,β2,β3]
DecryptOverflow(skIdeal, result) → [17]
```

### Lo que NO implementa esta spec

- Descifrado threshold de `CiphertextLabeledciphertext` — eso es spec 006.
- Operaciones Galois (rotaciones) en MHE con overflow.
- Threshold t-of-n — spec 007.
