# MHE Phase 6: Threshold Decryption of Overflow Labeled Ciphertexts

**ID:** 006  
**Estado:** Done  
**Fecha:** 2026-05-15  
**Autor:** juanmartin

---

## Objetivo

Añadir descifrado threshold N-of-N para `CiphertextLabeledciphertext` — el resultado de `MultOverflowLabeled`, `SumOverflowLabeled` y `SumOverflowCiphertextLabeled`. A diferencia de spec 003 (que solo descifra `PlaintextLabeledciphertext`), aquí `α` es un ciphertext homomorfo y puede haber múltiples filas de `β_ij`, lo que exige shares independientes para cada componente cifrado.

---

## Contexto

`DecryptOverflow(params, sk, clct)` calcula:

```
m = (Dec(α) + Σᵢ ∏ⱼ Dec(βᵢⱼ)) mod T
```

donde `α = (*rlwe.Ciphertext)(clct.elementsA)` y `βᵢⱼ = clct.elementsB[i][j]`.

Para hacer esto sin `sk_ideal`, se aplica el protocolo CKS-a-zeroSK a **cada ciphertext** presente en `clct`: uno para `α` y uno por cada `βᵢⱼ`. Cada party genera un share por componente; los shares se agregan componente a componente; y el descifrado final sustituye cada `Dec(sk, ·)` por `Dec(zeroSK, CKS(·, combined_share))`.

El tipo `OverflowDecryptionShare` encapsula todos los shares de una `CiphertextLabeledciphertext` en una sola estructura paralela a la misma.

**Relación con otras specs:**
- Depende de spec 003 (`LabeledDecryptionShare`, `GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`; reutiliza la lógica CKS interna).
- Depende de spec 005 (`MultOverflowLabeled`, `SumOverflowLabeled`, `SumOverflowCiphertextLabeled` producen los `CiphertextLabeledciphertext` que esta spec descifra).

**Archivos a modificar:** `labeling/mhe_labeling.go` (nuevo tipo + 3 funciones), `labeling/mhe_labeling_test.go` (tests, sin build tag).

---

## Interfaz Pública

```go
// OverflowDecryptionShare holds one party's collective key-switch shares for all
// ciphertext components of a CiphertextLabeledciphertext: one share for the α
// component (elementsA) and one share per β_ij component (elementsB[i][j]).
//
// The shape of Betas mirrors the shape of the corresponding CiphertextLabeledciphertext:
// Betas[i][j] corresponds to elementsB[i][j].
type OverflowDecryptionShare struct {
    Alpha LabeledDecryptionShare
    Betas [][]LabeledDecryptionShare
}

// GenOverflowDecryptionShare generates party i's CKS shares for all ciphertext
// components of clct: one share for α (elementsA) and one per β_ij (elementsB[i][j]).
//
// Uses the same smudging noise as GenLabeledDecryptionShare (σ = 8·rlwe.DefaultNoise).
//
// Returns an error if sk is nil or if clct contains no A component (α).
func GenOverflowDecryptionShare(ctx MHEContext, sk *rlwe.SecretKey, clct CiphertextLabeledciphertext) (OverflowDecryptionShare, error)

// AggregateOverflowDecryptionShares combines all parties' OverflowDecryptionShares
// into a single combined share for use in DecryptThresholdOverflow.
//
// All input shares must have the same Betas shape as each other. Returns an error if
// shares is empty or if a Betas shape mismatch is detected during aggregation.
func AggregateOverflowDecryptionShares(ctx MHEContext, shares []OverflowDecryptionShare) (OverflowDecryptionShare, error)

// DecryptThresholdOverflow recovers the plaintext from clct using the combined
// OverflowDecryptionShare. No individual or collective secret key is required.
//
// Applies CKS to each ciphertext component and reconstructs:
//
//   m[k] = (plainAlpha[k] + Σᵢ ∏ⱼ plainBeta_ij[k]) mod T
//
// Returns an error if clct contains no A component or if the combined share's Betas
// shape is incompatible with clct.elementsB.
func DecryptThresholdOverflow(ctx MHEContext, combined OverflowDecryptionShare, clct CiphertextLabeledciphertext) ([]uint64, error)
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `MultOverflowLabeled(Enc([3]), Enc([4]))` → threshold decrypt | `[12,…]` |
| `MultOverflowLabeled(Enc([1]), Enc([0]))` → threshold decrypt | `[0,…]` |
| `SumOverflowLabeled(MultOverflow(Enc([3]),Enc([4])), Enc([5]))` → threshold decrypt | `[17,…]` |
| `SumOverflowCiphertextLabeled(MultOverflow(Enc([3]),Enc([4])), MultOverflow(Enc([2]),Enc([5])))` → threshold decrypt | `[22,…]` |
| N=3, `MultOverflowLabeled(Enc([6]), Enc([7]))` → threshold decrypt | `[42,…]` |
| `GenOverflowDecryptionShare(ctx, nil, clct)` | error descriptivo |
| `GenOverflowDecryptionShare(ctx, sk, CiphertextLabeledciphertext{})` | error descriptivo |
| `AggregateOverflowDecryptionShares(ctx, [])` | error descriptivo |
| `DecryptThresholdOverflow(ctx, combined, CiphertextLabeledciphertext{})` | error descriptivo |

---

## Casos Edge

- [x] `sk == nil` en `GenOverflowDecryptionShare`: retorna error (no panic)
- [x] `clct.elementsA == nil` en `GenOverflowDecryptionShare`: retorna error (no panic)
- [x] `clct.elementsA == nil` en `DecryptThresholdOverflow`: retorna error (no panic)
- [x] `shares` vacío en `AggregateOverflowDecryptionShares`: retorna error (no panic)
- [x] `clct.elementsB` vacío (solo α, sin β): `GenOverflowDecryptionShare` produce `Betas = [][]`, descifrado equivale a `Dec(α)` solo
- [x] Round-trip N=1: degenera a single-party; resultado correcto
- [x] Round-trip N=2 con `MultOverflowLabeled` + `SumOverflowLabeled`
- [x] Round-trip N=2 con `SumOverflowCiphertextLabeled` de dos `MultOverflowLabeled`
- [x] Round-trip N=3 con `MultOverflowLabeled`
- [x] Multiplicación con producto que desborda `T`: resultado correcto módulo T
- [x] El resultado coincide con `DecryptOverflow(params, skIdeal, clct)` para los mismos `clct`

---

## Dependencias

- Spec #003: `LabeledDecryptionShare`, `smudgingNoise()` (función interna del paquete), patrón de acumulador fresco en `AggregateShares`
- Spec #005: `MultOverflowLabeled`, `SumOverflowLabeled`, `SumOverflowCiphertextLabeled`
- Paquetes ya en `go.mod`: `github.com/tuneinsight/lattigo/v6/multiparty`, `github.com/tuneinsight/lattigo/v6/core/rlwe`, `github.com/tuneinsight/lattigo/v6/schemes/bgv`

---

## Criterios de Aceptación

- [x] `go build ./...` exitoso
- [x] `go vet ./...` sin warnings
- [x] `go test -race ./labeling/` sin data races
- [x] `TestGenOverflowDecryptionShare`: HappyPath N=1,2 + Errors (nil sk, empty clct)
- [x] `TestAggregateOverflowDecryptionShares`: HappyPath N=2,3 + Error (empty shares)
- [x] `TestDecryptThresholdOverflow/MultOnly`: round-trip `MultOverflowLabeled` N=2 con valores (3×4, 1×0, (PT-1)×2)
- [x] `TestDecryptThresholdOverflow/WithSum`: round-trip `MultOverflow + SumOverflow` → 17
- [x] `TestDecryptThresholdOverflow/SumOfMults`: round-trip `SumOverflowCiphertext(Mult, Mult)` → 22
- [x] `TestDecryptThresholdOverflow/N3`: round-trip N=3 con `MultOverflowLabeled`
- [x] `TestDecryptThresholdOverflow/Errors`: empty clct retorna error
- [x] GoDoc completo en inglés para `OverflowDecryptionShare`, `GenOverflowDecryptionShare`, `AggregateOverflowDecryptionShares`, `DecryptThresholdOverflow`
- [x] Verificación de consistencia: `DecryptThresholdOverflow` y `DecryptOverflow(skIdeal)` producen el mismo resultado para el mismo `clct`

---

## Notas de Implementación

### `OverflowDecryptionShare` y acceso a campos unexported

Todas las funciones de spec 006 viven en el paquete `labeling`, por lo que pueden acceder directamente a `clct.elementsA` y `clct.elementsB[i][j]` (campos unexported de `Labeledciphertext`).

### `GenOverflowDecryptionShare`

```go
func GenOverflowDecryptionShare(ctx MHEContext, sk *rlwe.SecretKey, clct CiphertextLabeledciphertext) (OverflowDecryptionShare, error) {
    if sk == nil {
        return OverflowDecryptionShare{}, errors.New("GenOverflowDecryptionShare: sk must not be nil")
    }
    if clct.elementsA == nil {
        return OverflowDecryptionShare{}, errors.New("GenOverflowDecryptionShare: clct contains no A component")
    }

    // Share for α
    α := (*rlwe.Ciphertext)(clct.elementsA)
    proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
    if err != nil { return OverflowDecryptionShare{}, fmt.Errorf("...: %w", err) }
    zeroSK := rlwe.NewSecretKey(ctx.Params)

    alphaShare := proto.AllocateShare(α.Level())
    proto.GenShare(sk, zeroSK, α, &alphaShare)

    // Shares for each β_ij
    betas := make([][]LabeledDecryptionShare, len(clct.elementsB))
    for i, row := range clct.elementsB {
        betas[i] = make([]LabeledDecryptionShare, len(row))
        for j := range row {
            β := &clct.elementsB[i][j]
            share := proto.AllocateShare(β.Level())
            proto.GenShare(sk, zeroSK, β, &share)
            betas[i][j] = LabeledDecryptionShare{Value: share}
        }
    }

    return OverflowDecryptionShare{
        Alpha: LabeledDecryptionShare{Value: alphaShare},
        Betas: betas,
    }, nil
}
```

Note: a single `proto` (single `KeySwitchProtocol`) can be reused across multiple `GenShare` calls at different levels — each `AllocateShare(level)` and `GenShare` pair is independent.

### `AggregateOverflowDecryptionShares`

Follows the same fresh-accumulator pattern as `AggregateLabeledDecryptionShares`:

```go
func AggregateOverflowDecryptionShares(ctx MHEContext, shares []OverflowDecryptionShare) (OverflowDecryptionShare, error) {
    if len(shares) == 0 {
        return OverflowDecryptionShare{}, errors.New("AggregateOverflowDecryptionShares: shares must not be empty")
    }
    proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
    if err != nil { return OverflowDecryptionShare{}, fmt.Errorf("...: %w", err) }

    // Fresh accumulator for Alpha
    combinedAlpha := LabeledDecryptionShare{Value: proto.AllocateShare(shares[0].Alpha.Value.Level())}
    for _, s := range shares {
        proto.AggregateShares(combinedAlpha.Value, s.Alpha.Value, &combinedAlpha.Value)
    }

    // Fresh accumulators for each Betas[i][j]
    combinedBetas := make([][]LabeledDecryptionShare, len(shares[0].Betas))
    for i, row := range shares[0].Betas {
        combinedBetas[i] = make([]LabeledDecryptionShare, len(row))
        for j := range row {
            combinedBetas[i][j] = LabeledDecryptionShare{Value: proto.AllocateShare(shares[0].Betas[i][j].Value.Level())}
            for _, s := range shares {
                proto.AggregateShares(combinedBetas[i][j].Value, s.Betas[i][j].Value, &combinedBetas[i][j].Value)
            }
        }
    }

    return OverflowDecryptionShare{Alpha: combinedAlpha, Betas: combinedBetas}, nil
}
```

### `DecryptThresholdOverflow`

Mirrors `DecryptOverflow` but replaces `Dec(sk, ct)` with `CKS + Dec(zeroSK, ctSwitched)`:

```go
func DecryptThresholdOverflow(ctx MHEContext, combined OverflowDecryptionShare, clct CiphertextLabeledciphertext) ([]uint64, error) {
    if clct.elementsA == nil {
        return nil, errors.New("DecryptThresholdOverflow: clct contains no A component")
    }
    proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
    if err != nil { return nil, fmt.Errorf("...: %w", err) }

    encoder := bgv.NewEncoder(ctx.Params.Parameters)
    zeroSK := rlwe.NewSecretKey(ctx.Params)
    dec := rlwe.NewDecryptor(ctx.Params, zeroSK)

    // Helper: CKS + decode
    switchAndDecode := func(ct *rlwe.Ciphertext, share LabeledDecryptionShare) ([]uint64, error) {
        ctSwitched := rlwe.NewCiphertext(ctx.Params, 1, ct.Level())
        proto.KeySwitch(ct, share.Value, ctSwitched)
        out := make([]uint64, ctx.Params.MaxSlots())
        return out, encoder.Decode(dec.DecryptNew(ctSwitched), out)
    }

    // Decrypt α
    α := (*rlwe.Ciphertext)(clct.elementsA)
    plainAlpha, err := switchAndDecode(α, combined.Alpha)
    if err != nil { return nil, fmt.Errorf("DecryptThresholdOverflow: decode α: %w", err) }

    // Decrypt each β_ij and accumulate
    T := ctx.Params.PlaintextModulus()
    sumBetas := make([]uint64, ctx.Params.MaxSlots())
    for i, row := range clct.elementsB {
        multBetas := make([]uint64, ctx.Params.MaxSlots())
        for k := range multBetas { multBetas[k] = 1 }
        for j := range row {
            plainBeta, err := switchAndDecode(&clct.elementsB[i][j], combined.Betas[i][j])
            if err != nil { return nil, fmt.Errorf("DecryptThresholdOverflow: decode β[%d][%d]: %w", i, j, err) }
            for k := range multBetas {
                multBetas[k] = (multBetas[k] * plainBeta[k]) % T
            }
        }
        for k := range sumBetas {
            sumBetas[k] = (sumBetas[k] + multBetas[k]) % T
        }
    }

    result := make([]uint64, ctx.Params.MaxSlots())
    for k := range result {
        result[k] = (plainAlpha[k] + sumBetas[k] + T) % T
    }
    return result, nil
}
```

### Tests: oráculo de consistencia con `DecryptOverflow`

Además del round-trip con `skIdeal`, se puede verificar que `DecryptThresholdOverflow` produce exactamente el mismo resultado que `DecryptOverflow(params, skIdeal, clct)` para el mismo `clct`, como doble verificación.

### Lo que NO implementa esta spec

- Claves de Galois distribuidas (rotaciones) sobre `CiphertextLabeledciphertext`.
- Threshold t-of-n (< N parties necesarias para descifrar).
- Benchmarks formales.
