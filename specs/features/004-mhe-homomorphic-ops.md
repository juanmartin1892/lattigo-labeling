# MHE Phase 4: Homomorphic Operations on Labeled Ciphertexts

**ID:** 004  
**Estado:** Done  
**Fecha:** 2026-05-15  
**Autor:** juanmartin

---

## Objetivo

Exponer `SumLabeled` y `MultLabeled` para que un evaluador MHE pueda operar sobre `PlaintextLabeledciphertext` cifrados bajo la clave pública colectiva sin conocer ningún share secreto. Para que `MultLabeled` pueda relinearizar, se añade `GenCollectiveRelinKey` que ejecuta el protocolo distribuido de generación de clave de relinearización de Lattigo.

---

## Contexto

Specs 002 y 003 cubren cifrado y descifrado threshold. Esta spec cubre la fase de evaluación: el evaluador recibe ciphertexts etiquetados (`PlaintextLabeledciphertext`) cifrados bajo `pk_col` y necesita sumarlos y multiplicarlos sin acceso a ningún `sk_i`.

La **suma** en labeling no requiere clave de evaluación: basta con sumar `elementsA` y sumar `β`. La **multiplicación** sí requiere relinearización (para reducir el ciphertext de grado 2 a grado 1 tras `MulRelin`), lo que exige una clave de relinearización colectiva generada mediante el protocolo `multiparty.RelinearizationKeyGenProtocol` de Lattigo, sin que ninguna parte ensamble `sk_ideal`.

El protocolo ya existe en Lattigo y está validado informalmente por `runRelinKeyGen` en `labeling/multiparty_integration_test.go` (spec 001). Esta spec lo envuelve en una API pública estable y lo integra con `MHEContext`.

**Relación con otras specs:**
- Depende de spec 001 (verifica que `multiparty.RelinearizationKeyGenProtocol` funciona con los params del proyecto).
- Depende de spec 002 (`MHEContext`, `EncryptLabeled`, `PlaintextLabeledciphertext`).
- Depende de spec 003 (`DecryptThresholdLabeled` se usa en los tests de round-trip).
- Spec 005 (overflow en MHE) reutilizará `MultLabeled` como base.

**Archivos a modificar:** `labeling/mhe_labeling.go` (añadir funciones), `labeling/mhe_labeling_test.go` (añadir tests).

---

## Interfaz Pública

```go
// GenCollectiveRelinKey runs the two-round collective relinearization key generation
// protocol for the given secret key shares and CRS, returning the collective
// relinearization key required by MultLabeled.
//
// skShares contains one *rlwe.SecretKey per party, the same shares used in
// NewMHEContext. crs must be initialised with the same seed on all parties
// (e.g. sampling.NewKeyedPRNG(sharedSeed)).
//
// The collective relinearization key enables relinearization of ciphertexts
// encrypted under the collective public key without assembling the ideal secret key.
//
// Returns an error if skShares is empty or any element is nil.
func GenCollectiveRelinKey(params Parameters, skShares []*rlwe.SecretKey, crs multiparty.CRS) (*rlwe.RelinearizationKey, error)

// SumLabeled adds two PlaintextLabeledciphertexts encrypted under the same
// MHEContext collective public key and returns their labeled sum.
//
// The evaluator does not need any secret key share to perform this operation.
// The algebra is: elementsA_out = (a1 + a2) mod T, β_out = β1 + β2.
//
// Returns an error if the two ciphertexts have incompatible dimensions.
func SumLabeled(ctx MHEContext, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error)

// MultLabeled multiplies two PlaintextLabeledciphertexts encrypted under the same
// MHEContext collective public key, using the collective relinearization key for
// degree reduction.
//
// The evaluator does not need any secret key share; it uses ctx.CollectivePK
// for the fresh encryption of the random mask r and rlk for relinearization.
//
// The labeling formula is:
//   a_out = (a1 × a2 − r) mod T
//   β_out = (β1 × β2) + a1·β2 + a2·β1 + Enc(pk_col, r)
//
// Returns an error if rlk is nil or if the two ciphertexts have incompatible
// parameters.
func MultLabeled(ctx MHEContext, rlk *rlwe.RelinearizationKey, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error)
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `SumLabeled(ctx, EncryptLabeled(ctx,[3,…]), EncryptLabeled(ctx,[4,…]))` → DecryptThreshold | `[7,…]` |
| `SumLabeled(ctx, EncryptLabeled(ctx,[0,…]), EncryptLabeled(ctx,[0,…]))` → DecryptThreshold | `[0,…]` |
| `SumLabeled(ctx, EncryptLabeled(ctx,[PT-1,…]), EncryptLabeled(ctx,[1,…]))` → DecryptThreshold | `[0,…]` (wraps mod T) |
| `MultLabeled(ctx, rlk, EncryptLabeled(ctx,[3,…]), EncryptLabeled(ctx,[4,…]))` → DecryptThreshold | `[12,…]` |
| `MultLabeled(ctx, rlk, EncryptLabeled(ctx,[1,…]), EncryptLabeled(ctx,[0,…]))` → DecryptThreshold | `[0,…]` |
| `MultLabeled(ctx, rlk, EncryptLabeled(ctx,[a]), EncryptLabeled(ctx,[b]))` → DecryptThreshold, a×b < T | `[a×b,…]` |
| `MultLabeled(ctx, nil, lct1, lct2)` | error descriptivo |
| `SumLabeled(ctx, lct_vacío, lct2)` | error descriptivo |
| `GenCollectiveRelinKey(params, [], crs)` | error descriptivo |
| `GenCollectiveRelinKey(params, [nil], crs)` | error descriptivo |

---

## Casos Edge

- [x] `SumLabeled` con `lct` sin `elementsB` retorna error (no panic)
- [x] `MultLabeled` con `rlk == nil` retorna error (no panic)
- [x] `MultLabeled` con `lct` sin `elementsB` retorna error (no panic)
- [x] `GenCollectiveRelinKey` con `skShares` vacío retorna error
- [x] `GenCollectiveRelinKey` con algún `sk_i == nil` retorna error
- [x] `SumLabeled` con suma que desborda `PlaintextModulus` produce resultado correcto módulo T
- [x] `MultLabeled` con producto que desborda `PlaintextModulus` produce resultado correcto módulo T
- [x] Round-trip N=2: `DecryptThresholdLabeled(Aggregate(GenShares), MultLabeled(ctx, rlk, lct1, lct2)) == m1×m2 mod T`
- [x] Round-trip N=3: mismo esquema con tres parties
- [x] `SumLabeled` es conmutativa: `Sum(a,b)` descifra igual que `Sum(b,a)`

---

## Dependencias

- Spec #001: `multiparty.RelinearizationKeyGenProtocol` validado con los params del proyecto
- Spec #002: `MHEContext`, `EncryptLabeled`, `PlaintextLabeledciphertext`
- Spec #003: `DecryptThresholdLabeled` (usado en tests de round-trip)
- Paquetes ya en `go.mod`: `github.com/tuneinsight/lattigo/v6/multiparty`, `github.com/tuneinsight/lattigo/v6/core/rlwe`

---

## Criterios de Aceptación

- [x] `go build ./...` exitoso
- [x] `go vet ./...` sin warnings
- [x] `go test -race ./labeling/` sin data races
- [x] `TestGenCollectiveRelinKey`: happy path N=2,3 + errors (vacío, nil)
- [x] `TestSumLabeled`: round-trip completo N=2 con valores 3+4, 0+0, (PT-1)+1; error con lct vacío
- [x] `TestMultLabeled`: round-trip completo N=2 con valores 3×4, 1×0, a×b < T; errors nil rlk y lct vacío
- [x] `TestSumLabeledCommutativity`: `Sum(a,b)` == `Sum(b,a)` tras descifrado
- [x] `TestMHEHomomorphicOpsN3`: sum y mult con tres parties
- [x] GoDoc completo en inglés para `GenCollectiveRelinKey`, `SumLabeled`, `MultLabeled`
- [x] Verificación matemática: `DecryptThresholdLabeled(ctx, combined, MultLabeled(ctx,rlk,lct1,lct2)) == m1×m2 mod T`

---

## Notas de Implementación

### `GenCollectiveRelinKey`

El protocolo de Lattigo es de dos rondas. Se puede ejecutar en memoria (simulando comunicación) siguiendo el patrón de `runRelinKeyGen` en `multiparty_integration_test.go`:

```go
// Round 1: cada parte genera (share1_i, share2_i) con su propio ephemeral key
proto := multiparty.NewRelinearizationKeyGenProtocol(params)
ephemeralKeys[i], round1Shares[i], round2Shares[i] = proto.AllocateShare()
proto.GenShareRoundOne(skShares[i], crs, ephemeralKeys[i], &round1Shares[i])

// Agrega round1 de todos: combined_r1 = Σ round1_i
proto.AggregateShares(round1Shares[0], round1Shares[1], &combined1)

// Round 2: cada parte usa combined_r1 para generar round2
proto.GenShareRoundTwo(ephemeralKeys[i], skShares[i], combined1, &round2Shares[i])

// Agrega round2: combined_r2 = Σ round2_i
proto.AggregateShares(round2Shares[0], round2Shares[1], &combined2)

// Construye la clave de relinearización final
rlk := rlwe.NewRelinearizationKey(params)
proto.GenRelinearizationKey(combined1, combined2, rlk)
```

### `SumLabeled`

Delega en la función `Sum` existente, adaptando la firma al `MHEContext`:

```go
func SumLabeled(ctx MHEContext, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error) {
    return Sum(ctx.Params, lct1, lct2)
}
```

La validación de `lct` vacío ya está en `Sum`; si no, añadirla aquí.

### `MultLabeled`

Delega en la función `Mult` existente, pasando `ctx.CollectivePK` como clave de encriptación para `Enc(r)` y construyendo el `evk` desde `rlk`:

```go
func MultLabeled(ctx MHEContext, rlk *rlwe.RelinearizationKey, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error) {
    if rlk == nil {
        return PlaintextLabeledciphertext{}, errors.New("MultLabeled: rlk must not be nil")
    }
    evk := GenerateMemEvaluationKeySet(rlk)
    return Mult(ctx.Params, lct1, lct2, ctx.CollectivePK, evk)
}
```

### Tests: helper `buildMHETestSetupWithRLK`

Extender el helper existente `buildMHETestSetup` (de spec 002) para devolver también el `rlk` colectivo. Alternatively, crear un nuevo helper que acepte N y devuelva `(ctx, rlk, skShares)`.

### Lo que NO implementa esta spec

- `MultOverflow` / `SumOverflow` en contexto MHE (`CiphertextLabeledciphertext`) — eso es spec 005.
- Claves de Galois distribuidas (rotaciones MHE) — fuera del alcance actual.
- Threshold t-of-n (< N partes) — eso es spec 006.
- Benchmarks formales — planificados para una spec de benchmark independiente.
