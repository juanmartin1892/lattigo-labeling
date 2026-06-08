# Modulus-switch en std: comparación simétrica de comunicación de descifrado

**ID:** 012  
**Estado:** Ready  
**Fecha:** 2026-06-08  
**Autor:** juanmartin

---

## Objetivo

Determinar si la ventaja de comunicación de la variante `label` (−50% de bytes en el
descifrado threshold, observada en UC2/UC3) es **intrínseca a la construcción CF** o
simplemente un **artefacto de implementación**: `label` opera α/β a `level=1`, mientras
que `std` descifra a `MaxLevel`. Se añade una tercera variante `std_modsw` que aplica
modulus switching (BGV `Rescale`) al ciphertext resultante hasta `level=1` antes del CKS
threshold, igualando el tamaño de los shares al de `label`. La pregunta científica:
¿`std_modsw` consigue los mismos bytes que `label` **manteniendo** la corrección en el
perfil `tight` donde `label` falla?

---

## Contexto

### El hallazgo que motiva el experimento (memoria `project-noise-finding`)

En UC2/UC3, `label` descifra a `level=1` → shares de `2 × N × 2 × 8` bytes, la mitad que
`std` a `level=3` (`2 × N × 4 × 8`). Esto produjo la lectura "label optimiza
comunicación". Pero `label` también **falla** en `tight` mientras `std` resiste. Las dos
observaciones estaban confundidas porque comparaban niveles distintos:

| Variante | Nivel en decrypt | CommBytes (UC3, DB3) | Correcto en tight |
|----------|------------------|----------------------|-------------------|
| std      | MaxLevel (3)     | 4.2 MB               | sí                |
| label    | 1                | 2.1 MB               | no                |

`std_modsw` rompe la confusión: lleva `std` a `level=1` con `Rescale` (que **divide el
ruido** por cada primo descartado, preservando el plaintext). Si `std_modsw` resulta
correcto en `tight`, entonces:

1. La ventaja de bytes de `label` **no es intrínseca**: `std` la iguala con un modswitch.
2. El fallo de `label` en `tight` **sí es intrínseco** al ruido de la construcción CF
   (el enmascaramiento β nace con ruido fresco a `level=1`), no a operar a `level=1`.

### Por qué `Rescale` es la operación correcta

`bgv.Evaluator.Rescale` divide (redondeando) el ciphertext por el último primo de la
cadena, **dividiendo el ruido** por ese primo y preservando los bits MSB del plaintext.
El escalado (`Scale`) se actualiza para que el `Decode` posterior recupere el valor
correcto. Es nop solo si el evaluator se instancia como scale-invariant (BFV); los
benchmarks usan `bgv.NewEvaluator(params, evk)` sin ese flag → modo BGV → `Rescale`
activo.

### La tesis teórica a contrastar empíricamente

El modulus switching en BGV preserva aproximadamente el cociente ruido/presupuesto: una
operación correcta a `level=3` rescalada a `level=1` debería seguir siendo correcta,
porque tanto el ruido como el presupuesto `Q_ℓ/(2t)` se dividen por el mismo factor. La
predicción es `std_modsw` correcto ⟺ `std` correcto. El benchmark lo verifica.

---

## Interfaz Pública

### Nueva función en `labeling/labeling.go`

```go
// RescaleToLevel reduces a BGV ciphertext to targetLevel by successive modulus
// switching (Rescale), dividing the noise by each dropped prime while preserving the
// plaintext's most-significant bits. The ciphertext Scale is updated so a subsequent
// Decode recovers the correct value.
//
// If the ciphertext is already at or below targetLevel it is returned as a deep copy
// without modification. Requires the BGV (non scale-invariant) evaluator; with these
// parameters Rescale is active.
//
// Returns an error if targetLevel is negative.
func RescaleToLevel(parameters Parameters, ciphertext *rlwe.Ciphertext, targetLevel int) (*rlwe.Ciphertext, error)
```

### Variante `std_modsw` en `benchmarks/uc2_dotproduct` y `benchmarks/uc3_variance`

Sin API exportada. Idéntica a `std` salvo que, antes del CKS threshold, cada ciphertext
resultado se pasa por `RescaleToLevel(params, ct, 1)`. Se añade `"std_modsw"` al barrido
de variantes junto a `"std"` y `"label"`.

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `RescaleToLevel(params_full, ct@level3, 1)` | ciphertext a `level=1`, decodifica al mismo valor |
| `RescaleToLevel(params_min, ct@level1, 1)` | copia a `level=1` sin rescalar (ya está) |
| `RescaleToLevel(params, ct, -1)` | error |
| UC3 `std_modsw` CommBytes (full, DB3) | `2.1 MB` (= `label`, ½ de `std`) |
| UC3 `std_modsw` correcto (tight) | a determinar empíricamente (hipótesis: `true`) |

---

## Casos Edge

- [ ] `targetLevel` igual al nivel actual: devuelve copia sin rescalar.
- [ ] `targetLevel` mayor al nivel actual: devuelve copia sin rescalar (no se sube nivel).
- [ ] `targetLevel` negativo: error.
- [ ] Perfil `min` (MaxLevel=1): `std_modsw` no rescala, queda idéntico a `std`.
- [ ] Preservación del valor: el slot 0 tras `RescaleToLevel` + CKS coincide con el de `std`.

---

## Dependencias

- Spec #009: perfiles S1/S2/S3, UC2 dot-product.
- Spec #010: UC3 variance.
- Paquete `bgv` de Lattigo (Rescale, no scale-invariant).
- Memoria `project-noise-finding` (hallazgo que motiva el experimento).

---

## Criterios de Aceptación

- [ ] Tests table-driven para `RescaleToLevel` (nivel baja, valor preservado, edge cases).
- [ ] `RescaleToLevel` implementada según interfaz, GoDoc en inglés.
- [ ] `go vet ./...` sin warnings.
- [ ] `go test -race ./labeling/...` sin data races.
- [ ] `go build ./...` exitoso.
- [ ] UC2 y UC3 ejecutan 3 variantes (std, std_modsw, label) con `param_profile`.
- [ ] CommBytes de `std_modsw` = CommBytes de `label` (verificado en CSV).
- [ ] Determinación empírica de la corrección de `std_modsw` en `tight` documentada.

---

## Notas de Implementación

### Número de rescales

`RescaleToLevel(params, ct, 1)` rescala `ct.Level() - 1` veces. En `full`/`tight`
(MaxLevel=3) son 2 rescales (3→2→1). En `min` (MaxLevel=1) son 0 (copia directa). El
target=1 se elige para igualar exactamente el nivel al que `label` descifra.

### Coste de comunicación esperado

`shareSize(level=1) = 2 × 2^14 × 2 × 8 = 524 288` bytes por share. Con `nParties=2` y dos
cantidades (sum_sq + sum): `4 × 524 288 ≈ 2.1 MB`, idéntico a `label`.

### Interpretación de los dos resultados posibles

- **`std_modsw` correcto en tight** → la ventaja de bytes de `label` es un artefacto;
  `std` la replica sin perder corrección. El valor real de CF queda en setup (UC4, sin
  rlk) y rondas de protocolo, no en bytes de descifrado.
- **`std_modsw` incorrecto en tight** → operar a `level=1` es lo que rompe la corrección
  (ruido de smudging + rescale sobre presupuesto reducido), y `label` no está en
  desventaja real frente a `std` a igualdad de nivel.
