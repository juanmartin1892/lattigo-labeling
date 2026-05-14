# MHE Phase 2: Labeled Encryption with Collective Public Key

**ID:** 002  
**Estado:** Done  
**Fecha:** 2026-05-14  
**Autor:** juanmartin

---

## Objetivo

Introducir `MHEContext` y `EncryptLabeled` como la API de producción que conecta el esquema de labeling single-party con el contexto multipartito establecido en spec 001. Cada parte puede cifrar sus datos privados de forma independiente usando la clave pública colectiva, produciendo un `PlaintextLabeledciphertext` compatible con las operaciones MHE posteriores (specs 003–006).

---

## Contexto

Spec 001 demostró que `*rlwe.PublicKey` (colectiva) es un `rlwe.EncryptionKey` válido y que la función `Encrypt` existente acepta cualquier `rlwe.EncryptionKey`. Sin embargo, exponer directamente los primitivos multiparty a los llamantes de `labeling` rompe la abstracción del paquete. Esta spec introduce una capa delgada que:

1. Ejecuta el protocolo de generación de clave pública colectiva (`multiparty.PublicKeyGenProtocol`) y empaqueta el resultado en `MHEContext`.
2. Provee `EncryptLabeled(ctx, values)` como punto de entrada canónico para el cifrado labeled en MHE — equivalente a `Encrypt(ctx.Params, ctx.CollectivePK, values)`.

**Relación con otras specs:**
- Depende de spec 001 (establece que la pk colectiva es un `*rlwe.PublicKey` válido y que la CRS compartida garantiza determinismo).
- Specs 003–006 consumen `MHEContext` y `PlaintextLabeledciphertext`.

**Archivos a crear:** `labeling/mhe_labeling.go`, `labeling/mhe_labeling_test.go` (sin build tag, tests ordinarios)

---

## Interfaz Pública

```go
// MHEContext holds the shared parameters and collective public key for an MHE labeling session.
// Produced by NewMHEContext; consumed by EncryptLabeled and (spec 003) DecryptThresholdLabeled.
type MHEContext struct {
    Params       Parameters
    CollectivePK *rlwe.PublicKey
}

// NewMHEContext runs the collective public key generation protocol for the given
// secret key shares and CRS, returning the MHEContext shared by all parties.
//
// skShares contains one independently generated *rlwe.SecretKey per party.
// crs must be a deterministic PRNG initialised with the same seed on all parties
// (e.g. sampling.NewKeyedPRNG(sharedSeed)).
//
// The ideal secret key (sum of all shares) is never stored in MHEContext; it
// exists only during setup and is never assembled in production use.
func NewMHEContext(params Parameters, skShares []*rlwe.SecretKey, crs multiparty.CRS) (MHEContext, error)

// EncryptLabeled encrypts a vector of values under the MHE collective public key
// using the labeling scheme.
//
// Returns a PlaintextLabeledciphertext where elementsA holds the plaintext mask
// component and elementsB holds the ciphertext component encrypted under the
// collective key.
//
// It is semantically equivalent to Encrypt(ctx.Params, ctx.CollectivePK, values).
func EncryptLabeled(ctx MHEContext, values []uint64) (PlaintextLabeledciphertext, error)
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `NewMHEContext(params, [sk1, sk2], crs)` | `MHEContext` sin error; `CollectivePK` válida para cifrar |
| `EncryptLabeled(ctx, [7,7,…])` → `Decrypt(params, skIdeal, lct)` | `[7,7,…]` |
| `EncryptLabeled(ctx, [0,0,…])` → `Decrypt(params, skIdeal, lct)` | `[0,0,…]` |
| `EncryptLabeled(ctx, [PT-1, PT-1, …])` → `Decrypt(params, skIdeal, lct)` | `[PT-1, PT-1, …]` (PT = PlaintextModulus) |
| `EncryptLabeled(ctx, v)` llamado dos veces con los mismos `v` | Dos lct distintos (masks aleatorias independientes) |

---

## Casos Edge

- [x] `skShares` con N=1: degenera a single-party; `skIdeal = sk1`; resultado correcto
- [x] `values` con todos los slots a 0: `Decrypt(skIdeal, lct)` devuelve todo ceros
- [x] `values` con slot = `PlaintextModulus - 1` (valor máximo): sin desbordamiento
- [x] `crs` nil: `NewMHEContext` retorna error descriptivo (no panic)
- [x] `skShares` nil o vacío: `NewMHEContext` retorna error descriptivo (no panic)
- [x] `skShares` contiene un nil: `NewMHEContext` retorna error (no panic)
- [x] El ciphertext en `lct.elementsB` no es descifrable con ningún `skShares[i]` individual: `Decrypt(params, sk1, lct)` produce valores ≠ original con probabilidad abrumadora (verificado comparando slot 0 contra el valor cifrado; fallo esperado = colisión con prob ≈ 1/PT)

---

## Dependencias

- Spec #001: establece que `*rlwe.PublicKey` colectiva es válida como `rlwe.EncryptionKey` y que `multiparty.PublicKeyGenProtocol` funciona con los parámetros BGV del proyecto
- Paquetes ya en `go.mod`: `github.com/tuneinsight/lattigo/v6/multiparty`, `github.com/tuneinsight/lattigo/v6/core/rlwe`

---

## Criterios de Aceptación

- [x] `go build ./...` exitoso
- [x] `go test -run TestMHEContext -run TestEncryptLabeled ./labeling/` pasan (sin build tag)
- [x] `go vet ./...` sin warnings
- [x] `go test -race ./labeling/` sin data races
- [x] GoDoc completo en inglés para `MHEContext`, `NewMHEContext`, `EncryptLabeled`
- [x] Verificación matemática: `Decrypt(params, skIdeal, EncryptLabeled(ctx, m)) == m` para todo `m` en los tests
- [x] Verificación de aleatoriedad: dos llamadas a `EncryptLabeled(ctx, m)` producen `elementsA` distintos (masks independientes)
- [x] Verificación negativa: `Decrypt(params, skShares[0], lct)` produce resultado ≠ original (propiedad de clave colectiva)

---

## Notas de Implementación

### `labeling/mhe_labeling.go` — producción

`NewMHEContext` es la función `runPublicKeyGen` de los tests de spec 001 elevada a código de producción. Validación defensiva de entradas antes de ejecutar el protocolo:

```go
func NewMHEContext(params Parameters, skShares []*rlwe.SecretKey, crs multiparty.CRS) (MHEContext, error) {
    if crs == nil {
        return MHEContext{}, errors.New("NewMHEContext: crs must not be nil")
    }
    if len(skShares) == 0 {
        return MHEContext{}, errors.New("NewMHEContext: skShares must not be empty")
    }
    for i, sk := range skShares {
        if sk == nil {
            return MHEContext{}, fmt.Errorf("NewMHEContext: skShares[%d] is nil", i)
        }
    }
    // ... protocolo PublicKeyGenProtocol ...
}
```

`EncryptLabeled` es un one-liner sobre `Encrypt`:

```go
func EncryptLabeled(ctx MHEContext, values []uint64) (PlaintextLabeledciphertext, error) {
    return Encrypt(ctx.Params, ctx.CollectivePK, values)
}
```

### `labeling/mhe_labeling_test.go` — tests ordinarios (sin build tag)

Los tests usan `Decrypt(params, skIdeal, lct)` como oráculo de correctitud. `skIdeal` se construye en el test como suma de todos los `skShares` — igual que en spec 001, nunca existe en producción.

Para la **verificación negativa** (propiedad MHE): `Decrypt(params, skShares[0], lct)` retorna valores distintos al original con probabilidad ≈ 1 − 1/PT. El test usa un valor suficientemente alejado de 0 (e.g., 42) para que la colisión accidental sea despreciable.

### Lo que NO implementa esta spec

- Descifrado threshold (`DecryptThresholdLabeled`) — eso es spec 003
- Relinearización colectiva — eso es spec 004 (Mult en MHE)
- Operaciones homomórficas sobre labeled ciphertexts MHE
