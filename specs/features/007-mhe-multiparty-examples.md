# MHE Phase 7: Multiparty Labeling Examples

**ID:** 007  
**Estado:** Done  
**Fecha:** 2026-05-15  
**Autor:** juanmartin

---

## Objetivo

Añadir tres programas ejecutables en `examples/` que demuestren el uso completo de la API MHE de labeling (specs 002–006) con N=2 parties: setup colectivo, cifrado etiquetado, operaciones homomórficas y descifrado threshold, sin que ninguna parte reconstruya la clave secreta ideal.

---

## Contexto

Los ejemplos existentes en `examples/` (`sum-mult-overflow`, `evaluationKeys`, `rotate`, `rotate-overflow`) son todos single-party: usan `GenerateKeyPair` + `Encrypt` + `DecryptOverflow`. El único ejemplo multiparty (`multiparty_basic`) usa la API raw de Lattigo sin la capa de labeling.

Esta spec cubre el hueco: tres ejemplos autocontenidos que usan exclusivamente la API pública de `labeling` para demostrar el flujo MHE end-to-end.

**Relación con otras specs:**
- Depende de spec 002 (`MHEContext`, `EncryptLabeled`)
- Depende de spec 003 (`GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`, `DecryptThresholdLabeled`)
- Depende de spec 004 (`GenCollectiveRelinKey`, `SumLabeled`, `MultLabeled`)
- Depende de spec 005 (`MultOverflowLabeled`, `SumOverflowLabeled`, `SumOverflowCiphertextLabeled`)
- Depende de spec 006 (`GenOverflowDecryptionShare`, `AggregateOverflowDecryptionShares`, `DecryptThresholdOverflow`)

**Archivos a crear:**
- `examples/mhe_threshold_basic/main.go`
- `examples/mhe_threshold_ops/main.go`
- `examples/mhe_threshold_overflow/main.go`

---

## Ejemplos a Implementar

### Ejemplo 1 — `examples/mhe_threshold_basic/main.go`

Demuestra el flujo mínimo MHE con labeling:
1. `NewMHEContext` con N=2 parties y CRS compartida
2. `EncryptLabeled(ctx, [7,7,…])` por la parte evaluadora
3. `GenLabeledDecryptionShare` por cada party
4. `AggregateLabeledDecryptionShares`
5. `DecryptThresholdLabeled` → verificar resultado == 7

**Mensaje pedagógico**: el evaluador nunca ve el plaintext; ninguna party reconstruye `sk_ideal`.

### Ejemplo 2 — `examples/mhe_threshold_ops/main.go`

Demuestra operaciones homomórficas sobre `PlaintextLabeledciphertext`:
1. `NewMHEContext` + `GenCollectiveRelinKey` con N=2 parties
2. P1 cifra `[3,3,…]`, P2 cifra `[4,4,…]` con `EncryptLabeled`
3. Evaluador calcula `SumLabeled` → descifrado threshold → verificar 7
4. Evaluador calcula `MultLabeled` → descifrado threshold → verificar 12

### Ejemplo 3 — `examples/mhe_threshold_overflow/main.go`

Demuestra operaciones overflow + descifrado threshold overflow:
1. `NewMHEContext` + `GenCollectiveRelinKey` con N=2 parties
2. P1 cifra `[3,3,…]`, P2 cifra `[4,4,…]`; P3 cifra `[5,5,…]`
3. `MultOverflowLabeled(lct1, lct2)` → `CiphertextLabeledciphertext` con resultado esperado 12
4. `SumOverflowLabeled(clct, lct3)` → `CiphertextLabeledciphertext` con resultado esperado 17
5. `GenOverflowDecryptionShare` por cada party, `AggregateOverflowDecryptionShares`, `DecryptThresholdOverflow` → verificar 17
6. Adicionalmente: `SumOverflowCiphertextLabeled` de dos `MultOverflowLabeled` → verificar 22

---

## Comportamiento Esperado

| Ejemplo | Operación | Resultado esperado |
|---------|-----------|-------------------|
| `mhe_threshold_basic` | `EncryptLabeled([7])` → threshold decrypt | `7` en todos los slots |
| `mhe_threshold_ops` | `SumLabeled(Enc(3), Enc(4))` → threshold decrypt | `7` en todos los slots |
| `mhe_threshold_ops` | `MultLabeled(Enc(3), Enc(4))` → threshold decrypt | `12` en todos los slots |
| `mhe_threshold_overflow` | `MultOverflow(Enc(3), Enc(4))` → threshold overflow decrypt | `12` en todos los slots |
| `mhe_threshold_overflow` | `SumOverflow(MultOverflow(Enc(3),Enc(4)), Enc(5))` → threshold overflow decrypt | `17` en todos los slots |
| `mhe_threshold_overflow` | `SumOverflowCiphertext(MultOverflow(Enc(3),Enc(4)), MultOverflow(Enc(2),Enc(5)))` → threshold overflow decrypt | `22` en todos los slots |

---

## Convenciones de Estilo

Cada ejemplo debe seguir el mismo patrón que `examples/multiparty_basic/main.go`:

- **Cabecera de licencia** Apache 2.0 al inicio del fichero
- **Package doc comment** en inglés explicando el protocolo y las fases, con el comando `go run ./examples/<nombre>/`
- **Fases marcadas** con `fmt.Println("=== Phase N: descripción ===")` para legibilidad
- **Verificación explícita** al final: todos los slots correctos o `log.Fatal`
- **`log.Fatalf`** para errores no recuperables
- **Sin dependencias nuevas** — solo `labeling`, `sampling.NewKeyedPRNG` y stdlib
- **CRS seed fija** (constante `var fixedCRSSeed = []byte("...")`) para reproducibilidad
- **Parámetros BGV** como constantes al inicio: `LogN=14`, `LogQ=[56,55,55,54,54,54]`, `LogP=[55,55]`, `PlaintextModulus=0x3ee0001`

---

## Casos Edge

- [x] Verificación slot a slot (no solo slot 0) en todos los ejemplos
- [x] El ejemplo 3 incluye tanto `SumOverflowLabeled` como `SumOverflowCiphertextLabeled`
- [x] En ningún momento se ensambla `sk_ideal` en los ejemplos (no existe variable `skIdeal`)
- [x] Los valores elegidos (3, 4, 5) son pequeños para evitar overflow de uint64 en la verificación
- [x] `go run ./examples/mhe_threshold_basic/` imprime un resumen legible del resultado

---

## Dependencias

- Spec #002: `NewMHEContext`, `EncryptLabeled`
- Spec #003: `GenLabeledDecryptionShare`, `AggregateLabeledDecryptionShares`, `DecryptThresholdLabeled`
- Spec #004: `GenCollectiveRelinKey`, `SumLabeled`, `MultLabeled`
- Spec #005: `MultOverflowLabeled`, `SumOverflowLabeled`, `SumOverflowCiphertextLabeled`
- Spec #006: `GenOverflowDecryptionShare`, `AggregateOverflowDecryptionShares`, `DecryptThresholdOverflow`
- Paquetes ya en `go.mod`: `github.com/tuneinsight/lattigo/v6/utils/sampling`

---

## Criterios de Aceptación

- [x] `go build ./examples/mhe_threshold_basic/` exitoso
- [x] `go build ./examples/mhe_threshold_ops/` exitoso
- [x] `go build ./examples/mhe_threshold_overflow/` exitoso
- [x] `go run ./examples/mhe_threshold_basic/` imprime "All slots correct" y termina con código 0
- [x] `go run ./examples/mhe_threshold_ops/` imprime "All slots correct" para Sum y Mult, termina con código 0
- [x] `go run ./examples/mhe_threshold_overflow/` imprime "All slots correct" para las tres operaciones, termina con código 0
- [x] Ningún ejemplo contiene variable `skIdeal` ni ensambla la clave secreta ideal
- [x] Package doc comment en inglés presente en cada fichero
- [x] Cabecera Apache 2.0 presente en cada fichero
- [x] Fases marcadas con `=== Phase N ===` para facilitar lectura del output

---

## Notas de Implementación

### Setup compartido entre ejemplos

Los tres ejemplos necesitan el mismo bloque de setup. El patrón es:

```go
// Shared CRS seed — all parties use the same seed to derive the same CRS.
var fixedCRSSeed = []byte("mhe-example-crs-seed-v1")

// In main():
params, err := labeling.NewParametersFromLiteral(14,
    []int{56, 55, 55, 54, 54, 54},
    []int{55, 55},
    0x3ee0001,
)

crs, err := sampling.NewKeyedPRNG(fixedCRSSeed)
skShares := make([]*rlwe.SecretKey, nParties)
for i := range skShares {
    skShares[i] = rlwe.NewKeyGenerator(params).GenSecretKeyNew()
}
ctx, err := labeling.NewMHEContext(params, skShares, crs)
```

### Generación del share de descifrado (helper inline)

Para claridad en los ejemplos, el loop de descifrado threshold puede escribirse inline:

```go
decShares := make([]labeling.LabeledDecryptionShare, nParties)
for i, sk := range skShares {
    decShares[i], err = labeling.GenLabeledDecryptionShare(ctx, sk, lct)
    // handle err
}
combined, err := labeling.AggregateLabeledDecryptionShares(ctx, decShares)
result, err := labeling.DecryptThresholdLabeled(ctx, combined, lct)
```

### `GenCollectiveRelinKey` requiere un CRS fresco

La CRS del ejemplo 2 y 3 se puede reutilizar para la generación de la clave colectiva pública, pero `GenCollectiveRelinKey` necesita su propia CRS (o bien la misma si está en el estado correcto). Lo más limpio es usar una CRS separada con distinto seed para la RLK:

```go
rlkCRS, err := sampling.NewKeyedPRNG([]byte("mhe-example-rlk-seed-v1"))
rlk, err := labeling.GenCollectiveRelinKey(params, skShares, rlkCRS)
```

### Verificación de slots

```go
allCorrect := true
for i, v := range result {
    if v != expected {
        fmt.Printf("  ERROR slot %d: got %d, want %d\n", i, v, expected)
        allCorrect = false
    }
}
if !allCorrect {
    log.Fatal("Round-trip FAILED.")
}
fmt.Printf("  All %d slots correct: got %d\n", params.MaxSlots(), expected)
```

### Lo que NO implementa esta spec

- Tests unitarios para los ejemplos (son programas `main`, no librerías)
- Benchmarks de rendimiento
- Ejemplos con N > 2 parties (suficiente para demostrar el protocolo)
- Rotaciones distribuidas (fuera del alcance de specs 002–006)
