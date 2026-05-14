# MHE Phase 3: Threshold Decryption of Labeled Ciphertexts

**ID:** 003  
**Estado:** Done  
**Fecha:** 2026-05-14  
**Autor:** juanmartin

---

## Objetivo

Añadir el descifrado threshold N-of-N a `MHEContext` para que un `PlaintextLabeledciphertext` cifrado bajo la clave pública colectiva sea descifrado sin que ningún nodo reconstruya la clave secreta ideal. Cada parte aporta un share de descifrado; los shares se agregan; el resultado se descifra sin secreto.

---

## Contexto

Spec 002 introdujo `EncryptLabeled(ctx, m)` que produce un `PlaintextLabeledciphertext` cuyo componente `elementsB[0][0]` está cifrado bajo la clave pública colectiva `sk_ideal = Σ sk_i`. Para descifrar sin exponer `sk_ideal`, se usa el protocolo **Collective Key Switch (CKS)** de Mouchet et al. 2021: cada parte genera un share que cambia el key de `sk_i` a `sk=0`; la suma de shares equivale al switch completo de `sk_ideal` a `sk=0`; el ciphertext resultante es un polinomio de ruido pequeño que se decodifica directamente.

La fórmula de `Decrypt` existente es:
```
m[i] = (elementsA[i] + Dec(sk_ideal, β)) mod T
```
Esta spec la adapta a:
```
m[i] = (elementsA[i] + Decode(CKS(β, Σ share_i))) mod T
```
donde `CKS(β, Σ share_i)` produce `β` bajo `sk=0`, evitando montar `sk_ideal`.

**Relación con otras specs:**
- Depende de spec 001 (verifica que `multiparty.KeySwitchProtocol` funciona con los params BGV del proyecto y que `LogP > 0` es suficiente para noise flooding).
- Depende de spec 002 (`MHEContext`, `EncryptLabeled`, `PlaintextLabeledciphertext`).
- Specs 004–006 reutilizan `DecryptThresholdLabeled` como paso final de sus protocolos.

**Archivos a modificar:** `labeling/mhe_labeling.go` (añadir tipos y funciones), `labeling/mhe_labeling_test.go` (añadir tests, sin build tag)

---

## Interfaz Pública

```go
// LabeledDecryptionShare holds one party's key-switch share for the B-component
// of a PlaintextLabeledciphertext. It is produced by GenLabeledDecryptionShare
// and consumed by AggregateLabeledDecryptionShares.
type LabeledDecryptionShare struct {
    Value multiparty.KeySwitchShare
}

// GenLabeledDecryptionShare generates party i's collective key-switch share for
// switching lct.elementsB[0][0] from sk (the party's individual secret key share)
// to the zero secret key. All N parties must contribute a share before decryption.
//
// Noise flooding uses σ = 8·rlwe.DefaultNoise with bound 6σ, following the
// standard parameter choice from Mouchet et al. 2021 (PETS).
//
// Returns an error if sk is nil or if lct contains no ciphertext component.
func GenLabeledDecryptionShare(ctx MHEContext, sk *rlwe.SecretKey, lct PlaintextLabeledciphertext) (LabeledDecryptionShare, error)

// AggregateLabeledDecryptionShares combines all parties' decryption shares into a
// single combined share that can be passed to DecryptThresholdLabeled.
//
// shares must contain exactly one share per party; order does not matter.
// Returns an error if shares is empty or any element has a nil Value.
func AggregateLabeledDecryptionShares(ctx MHEContext, shares []LabeledDecryptionShare) (LabeledDecryptionShare, error)

// DecryptThresholdLabeled recovers the plaintext from lct using the combined
// decryption share produced by AggregateLabeledDecryptionShares. No individual
// or collective secret key is required at this step.
//
// Internally applies KeySwitch to lct.elementsB[0][0] to obtain a ciphertext
// under sk=0, then reconstructs m[i] = (elementsA[i] + b[i]) mod T.
//
// Returns an error if lct contains no ciphertext component.
func DecryptThresholdLabeled(ctx MHEContext, combined LabeledDecryptionShare, lct PlaintextLabeledciphertext) ([]uint64, error)
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `GenLabeledDecryptionShare(ctx, sk_i, lct)` (sk_i válido, lct válido) | `LabeledDecryptionShare` sin error |
| `AggregateLabeledDecryptionShares(ctx, [s1, s2])` | Share combinado sin error |
| `DecryptThresholdLabeled(ctx, combined, EncryptLabeled(ctx, [7,7,…]))` | `[7,7,…]` |
| `DecryptThresholdLabeled(ctx, combined, EncryptLabeled(ctx, [0,0,…]))` | `[0,0,…]` |
| `DecryptThresholdLabeled(ctx, combined, EncryptLabeled(ctx, [PT-1,…]))` | `[PT-1,…]` |
| Full round-trip N=1: degenera a single-party | Resultado correcto |
| Full round-trip N=3 | Resultado correcto |
| `GenLabeledDecryptionShare(ctx, nil, lct)` | Error descriptivo |
| `AggregateLabeledDecryptionShares(ctx, [])` | Error descriptivo |
| `DecryptThresholdLabeled(ctx, combined, lct_vacío)` | Error descriptivo |

---

## Casos Edge

- [ ] N=1: `GenLabeledDecryptionShare` con un solo share + `Aggregate` + `DecryptThreshold` recupera el mensaje (degeneración a single-party)
- [ ] `sk == nil` en `GenLabeledDecryptionShare`: retorna error (no panic)
- [ ] `lct.elementsB` vacío en `GenLabeledDecryptionShare`: retorna error (no panic)
- [ ] `lct.elementsB` vacío en `DecryptThresholdLabeled`: retorna error (no panic)
- [ ] `shares` nil o vacío en `AggregateLabeledDecryptionShares`: retorna error (no panic)
- [ ] Un share con `Value` zero-value en `AggregateLabeledDecryptionShares`: no panic (zero-value es un share nulo pero estructuralmente válido)
- [ ] `values` todos a 0: `DecryptThresholdLabeled` retorna todo ceros
- [ ] `values` con slot = `PlaintextModulus - 1`: sin desbordamiento
- [ ] Shares agregados en distinto orden producen el mismo resultado (conmutatividad de `AggregateShares`)

---

## Dependencias

- Spec #001: verifica que `multiparty.KeySwitchProtocol` funciona con los params BGV del proyecto
- Spec #002: `MHEContext`, `EncryptLabeled`, `PlaintextLabeledciphertext`
- Paquetes ya en `go.mod`: `github.com/tuneinsight/lattigo/v6/multiparty`, `github.com/tuneinsight/lattigo/v6/core/rlwe`, `github.com/tuneinsight/lattigo/v6/ring`

---

## Criterios de Aceptación

- [x] `go build ./...` exitoso
- [x] `go test -run TestGenLabeledDecryptionShare -run TestAggregateLabeledDecryptionShares -run TestDecryptThresholdLabeled ./labeling/` pasan (sin build tag)
- [x] `go vet ./...` sin warnings
- [x] `go test -race ./labeling/` sin data races
- [x] GoDoc completo en inglés para `LabeledDecryptionShare`, `GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`, `DecryptThresholdLabeled`
- [x] Verificación matemática: `DecryptThresholdLabeled(ctx, Aggregate([GenShare(sk_i, lct)…]), lct) == m` donde `lct = EncryptLabeled(ctx, m)`
- [x] Verificación N=1: round-trip correcto con un solo party
- [x] Verificación N=3: round-trip correcto con tres parties
- [x] Caso edge `values=[0,…,0]` y `values=[PT-1,…,PT-1]` verificados
- [x] Ningún path ensambla `sk_ideal` (el test helper que construye `skIdeal` existe solo como oráculo de sanidad, no como input de ninguna función de spec 003)

---

## Notas de Implementación

### Protocolo CKS en detalle

```
Para i = 1..N:
    proto_i = multiparty.NewKeySwitchProtocol(params, gaussianNoise)
    share_i = proto_i.AllocateShare(β.Level())
    proto_i.GenShare(sk_i, zeroSK, β, &share_i)

combined = share_1
Para i = 2..N:
    proto_1.AggregateShares(combined, share_i, &combined)

βSwitched = rlwe.NewCiphertext(params, 1, β.Level())
proto_1.KeySwitch(β, combined, βSwitched)

// βSwitched ahora está cifrado bajo zeroSK → Dec(zeroSK, βSwitched) == b
b = Decode(Dec(zeroSK, βSwitched))
m[i] = (elementsA[i] + b[i]) mod T
```

El ruido gaussiano de smudging: `ring.DiscreteGaussian{Sigma: 8 * rlwe.DefaultNoise, Bound: 6 * 8 * rlwe.DefaultNoise}`.

### Acceso a `lct.elementsB`

`PlaintextLabeledciphertext` es `Labeledciphertext[PlaintextElements]` con campos unexported. `GenLabeledDecryptionShare` y `DecryptThresholdLabeled` están en el **mismo paquete** `labeling`, por lo que pueden acceder directamente a `lct.elementsB[0][0]`.

### Validación de `lct` vacío

```go
if len(lct.elementsB) == 0 || len(lct.elementsB[0]) == 0 {
    return ..., errors.New("...: lct contains no ciphertext component")
}
```

### `GenLabeledDecryptionShare` — creación del protocolo

Cada llamada crea su propio `KeySwitchProtocol` internamente; no se almacena estado entre llamadas. El `zeroSK` se crea con `rlwe.NewSecretKey(params)` (no inicializar el polinomio = coeficientes todos cero).

```go
func GenLabeledDecryptionShare(ctx MHEContext, sk *rlwe.SecretKey, lct PlaintextLabeledciphertext) (LabeledDecryptionShare, error) {
    if sk == nil {
        return LabeledDecryptionShare{}, errors.New("GenLabeledDecryptionShare: sk must not be nil")
    }
    if len(lct.elementsB) == 0 || len(lct.elementsB[0]) == 0 {
        return LabeledDecryptionShare{}, errors.New("GenLabeledDecryptionShare: lct contains no ciphertext component")
    }
    β := &lct.elementsB[0][0]
    noise := ring.DiscreteGaussian{Sigma: 8 * rlwe.DefaultNoise, Bound: 6 * 8 * rlwe.DefaultNoise}
    proto := multiparty.NewKeySwitchProtocol(ctx.Params, noise)
    zeroSK := rlwe.NewSecretKey(ctx.Params)
    share := proto.AllocateShare(β.Level())
    proto.GenShare(sk, zeroSK, β, &share)
    return LabeledDecryptionShare{Value: share}, nil
}
```

### `AggregateLabeledDecryptionShares`

```go
func AggregateLabeledDecryptionShares(ctx MHEContext, shares []LabeledDecryptionShare) (LabeledDecryptionShare, error) {
    if len(shares) == 0 {
        return LabeledDecryptionShare{}, errors.New("AggregateLabeledDecryptionShares: shares must not be empty")
    }
    noise := ring.DiscreteGaussian{Sigma: 8 * rlwe.DefaultNoise, Bound: 6 * 8 * rlwe.DefaultNoise}
    proto := multiparty.NewKeySwitchProtocol(ctx.Params, noise)
    combined := shares[0]
    for i := 1; i < len(shares); i++ {
        proto.AggregateShares(combined.Value, shares[i].Value, &combined.Value)
    }
    return combined, nil
}
```

### `DecryptThresholdLabeled`

```go
func DecryptThresholdLabeled(ctx MHEContext, combined LabeledDecryptionShare, lct PlaintextLabeledciphertext) ([]uint64, error) {
    if len(lct.elementsB) == 0 || len(lct.elementsB[0]) == 0 {
        return nil, errors.New("DecryptThresholdLabeled: lct contains no ciphertext component")
    }
    β := &lct.elementsB[0][0]
    noise := ring.DiscreteGaussian{Sigma: 8 * rlwe.DefaultNoise, Bound: 6 * 8 * rlwe.DefaultNoise}
    proto := multiparty.NewKeySwitchProtocol(ctx.Params, noise)
    βSwitched := rlwe.NewCiphertext(ctx.Params, 1, β.Level())
    proto.KeySwitch(β, combined.Value, βSwitched)

    zeroSK := rlwe.NewSecretKey(ctx.Params)
    b := make([]uint64, ctx.Params.MaxSlots())
    if err := bgv.NewEncoder(ctx.Params.Parameters).Decode(
        rlwe.NewDecryptor(ctx.Params, zeroSK).DecryptNew(βSwitched), b,
    ); err != nil {
        return nil, fmt.Errorf("DecryptThresholdLabeled: decode failed: %w", err)
    }

    result := make([]uint64, len(lct.elementsA))
    T := ctx.Params.PlaintextModulus()
    for i, a := range lct.elementsA {
        result[i] = (a + b[i] + T) % T
    }
    return result, nil
}
```

### Tests en `labeling/mhe_labeling_test.go`

Tests nuevos a añadir (sin build tag, reutilizan `buildMHETestSetup` y `fillSlots` de spec 002):

- `TestGenLabeledDecryptionShare`: HappyPath (N=1,2,3) + Errors (nil sk, lct vacío)
- `TestAggregateLabeledDecryptionShares`: HappyPath + Error (vacío)
- `TestDecryptThresholdLabeled`: RoundTrip (N=1,2,3 × valores 7, 0, PT-1) + Error (lct vacío)
- `TestThresholdDecryptCommutativity`: agregar shares en orden inverso produce el mismo resultado

### Lo que NO implementa esta spec

- Descifrado threshold de `CiphertextLabeledciphertext` (resultado de `MultOverflow`/`SumOverflow`) — eso es spec 006
- Relinearización colectiva — eso es spec 004
- Threshold para más de un `elementsB[0][0]` — se limita a `PlaintextLabeledciphertext` estándar
