# Comparativa honesta a nivel fijo: rejilla 2×2 {std, label} × {MaxLevel, level=1}

**ID:** 013
**Estado:** Done
**Fecha:** 2026-06-09
**Autor:** juanmartin

---

## Objetivo

Eliminar el **factor de confusión del nivel de descifrado** en toda la comparación std
vs label. Hasta ahora `std` descifraba a `MaxLevel` y `label` a `level=1` por
construcción, de modo que las diferencias de comunicación medían el nivel, no la técnica.
Esta feature mide cada variante en una **rejilla de doble entrada** `{std, label} ×
{MaxLevel, level=1}` en UC2/UC3/UC4, de forma que cualquier comparación se hace **a igual
nivel**. El objetivo es una conclusión honesta sobre el valor real de CF labeling, incluso
si el resultado es que no aporta ventaja en ningún escenario.

---

## Contexto

### El confound que motiva la spec

`label` vive a `level=1` no por casualidad sino porque `Mult` (y `MultOverflow`) **alocan
β/α a `level=1` de forma hardcodeada** (`rlwe.NewCiphertext(params, params.MaxLevel(), 1)`,
tercer argumento = nivel). Verificado empíricamente (probe spec 013):

```
after EncryptLabeled: beta level=3 (MaxLevel) degree=1
after MultLabeled:     beta level=1          degree=1
```

`label` **nace** a MaxLevel y `Mult` lo baja a `level=1`. No hay `Rescale` explícito: el
nivel lo fija la alocación del ciphertext de salida.

La spec 012 ya resolvió la mitad de la simetría bajando `std` a `level=1` (`std_modsw`).
Esta spec completa la rejilla subiendo `label` a `MaxLevel` y mide **las cuatro celdas**.

### La rejilla 2×2

| nivel ↓ \ variante → | `std` | `label` |
|----------------------|-------|---------|
| **MaxLevel**         | `std` (natural) | `label_max` (**nuevo**: Mult preserva nivel) |
| **level=1**          | `std_modsw` (Rescale→1, spec 012) | `label` (natural, Mult fuerza level=1) |

Predicciones a contrastar empíricamente:

- **Comunicación**: a igual nivel, `std` y `label` descifran shares del **mismo tamaño**
  (`shareSize` depende solo de `level`). → fila MaxLevel: ambos full; fila level=1: ambos
  ½. La "ventaja −50%" de `label` desaparece por completo.
- **Corrección**: a igual nivel, `label` arrastra el ruido extra de la máscara CF. Si en
  `tight`/level=1 `std_modsw` acierta (60/60, spec 012) y `label` falla (0/60), entonces el
  fallo de `label` **sí** es intrínseco a CF. En MaxLevel ambos deberían acertar (presupuesto
  holgado): comprobar si `label_max` recupera la corrección que `label` pierde a level=1.
- **Tiempo/memoria**: `label`/`label_max` añaden el coste de la construcción CF (máscara α,
  doble componente) sobre `std`/`std_modsw`. A igual nivel se aísla ese sobrecoste.

### UC4

UC4 usa la ruta overflow (`MultOverflow*` + `CompactRotateAndSumAlpha` +
`DecryptThresholdCompact`); su `α` se aloca a `level=1` igual que `Mult`. Para la
comparación honesta se añade el espejo `label_compact_max` (α a MaxLevel). La directiva del
usuario es explícita: incluir UC4 en la comparación a nivel fijo **aunque ello elimine la
ventaja de compactación de rondas** — no se busca "ganar" sino comparar con honestidad.

---

## Interfaz Pública

### Nuevas funciones en `labeling/labeling.go`

```go
// MultKeepLevel multiplies two PlaintextLabeledciphertext exactly like Mult, but keeps
// the resulting β at the inputs' level (MaxLevel for fresh ciphertexts) instead of
// forcing level=1. Used to compare std and label threshold decryption on equal footing
// (same ciphertext level ⇒ same share size). See spec 013.
func MultKeepLevel(parameters Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext, key rlwe.EncryptionKey, evk *rlwe.MemEvaluationKeySet) (PlaintextLabeledciphertext, error)

// MultOverflowKeepLevel computes MultOverflow keeping α at the inputs' level instead of
// level=1, for the UC4 fixed-level comparison. See spec 013.
func MultOverflowKeepLevel(parameters Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext, key rlwe.EncryptionKey, evk *rlwe.MemEvaluationKeySet) (CiphertextLabeledciphertext, error)

// SumKeepLevel adds two PlaintextLabeledciphertext keeping β at the inputs' level instead
// of level=1, so a label rotate-and-sum runs entirely at MaxLevel. (RotateColumns already
// preserves level; only Sum forced level=1.) See spec 013.
func SumKeepLevel(params bgv.Parameters, labeledciphertext1, labeledciphertext2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error)
```

### Nuevos wrappers MHE en `labeling/mhe_labeling.go`

```go
// MultLabeledKeepLevel is MultLabeled but keeps β at MaxLevel. See spec 013.
func MultLabeledKeepLevel(ctx MHEContext, rlk *rlwe.RelinearizationKey, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error)

// MultOverflowLabeledFreeKeepLevel is the rlk-free MaxLevel mirror of the UC4 overflow
// multiply. SumLabeledKeepLevel is the level-preserving labeled sum. See spec 013.
func MultOverflowLabeledFreeKeepLevel(ctx MHEContext, lct1, lct2 PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error)
func SumLabeledKeepLevel(ctx MHEContext, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error)
```

### Variantes nuevas en benchmarks (sin API exportada)

- `benchmarks/uc2_dotproduct`, `benchmarks/uc3_variance`: añadir `"label_max"` al barrido
  (usa `MultLabeledKeepLevel`, descifra a MaxLevel).
- `benchmarks/uc4_variance_compact`: añadir `"label_compact_max"` (usa
  `MultOverflowLabeledKeepLevel`, α a MaxLevel).

La columna `param_profile` y el formato CSV no cambian (backward compatible).

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `MultKeepLevel(params_full, lct1@L3, lct2@L3)` | β a `level=3`, decodifica al producto correcto |
| `MultKeepLevel` vs `Mult` (mismo input) | mismo plaintext; β a MaxLevel vs β a level=1 |
| `MultLabeledKeepLevel` + threshold decrypt (full) | correcto; share a MaxLevel |
| UC2 `label_max` CommBytes (full) | = `std` CommBytes (full), doble que `label` |
| UC2 `label` CommBytes (full) | = `std_modsw` CommBytes (½ de `std`) |
| `label_max` correcto en `tight` | a determinar (hipótesis: recupera corrección que `label` pierde) |

---

## Casos Edge

- [ ] Perfil `min` (MaxLevel=1): `MultKeepLevel` y `Mult` coinciden (no hay nivel que bajar).
- [ ] Preservación del valor: `MultKeepLevel` decodifica al mismo plaintext que `Mult`.
- [ ] β tras `MultKeepLevel` tiene `degree==1` (rotate-and-sum posterior requiere degree 1).
- [ ] `MultKeepLevel` seguido de `RescaleToLevel(→1)` ≈ `Mult` directo (mismo nivel y valor).
- [ ] `MultOverflowKeepLevel`: α a MaxLevel, `AlphaLevel` lo refleja; decrypt compacto correcto.

---

## Dependencias

- Spec #009 (perfiles S1/S2/S3, UC2), #010 (UC3), #011 (UC4 compacta), #012 (`RescaleToLevel`, `std_modsw`).
- Paquete `bgv`/`rlwe` de Lattigo.

---

## Criterios de Aceptación

- [x] Tests table-driven para `MultKeepLevel`, `SumKeepLevel` y `MultOverflowKeepLevel` (nivel preservado, valor, degree, rescale).
- [x] `MultKeepLevel`/`SumKeepLevel`/`MultOverflowKeepLevel` + wrappers MHE implementados, GoDoc en inglés.
- [x] `go vet ./...` sin warnings.
- [x] `go test -race ./labeling/...` sin data races.
- [x] `go build ./...` exitoso.
- [x] UC2/UC3 ejecutan `{std, std_modsw, label, label_max}`; UC4 ejecuta `{std, label_compact, label_compact_max}`.
- [x] CommBytes a igual nivel coinciden entre std y label en UC2/UC3 (byte a byte); UC4 documenta el blow-up de CF.
- [x] Determinación empírica de corrección de `label_max` en `tight` documentada.
- [x] Análisis de doble entrada escrito en `~/vault/proyectos/tfm-uvigo`.

---

## Resultado Empírico (20 reps × 3 DB × 3 perfiles)

**Comunicación a igual nivel (UC2/UC3):** std y label coinciden **byte a byte**
(UC2: 2 097 152 B MaxLevel / 1 048 576 B level=1; UC3: el doble). La "ventaja −50 %" de label
era el artefacto del nivel.

**Comunicación UC4:** `label_compact` transmite **~93×** la de `std` en DB3 (124× para
`label_compact_max`), porque descifra por bloque mientras std agrega antes de descifrar. El
descifrado compacto resuelve la explosión 2^L pero no la asimetría estructural frente a std.

**Corrección en `tight`:** a `level=1`, `std_modsw` acierta (20/20) y `label` falla (0/20) →
el ruido de la máscara CF es intrínseco. A `MaxLevel`, std y `label_max` aciertan ambos
(20/20) → el presupuesto amplio absorbe la máscara. UC4 reproduce el patrón
(`label_compact` 0/20, `label_compact_max` 20/20 en tight).

**Tiempo/memoria:** label es 16–62 % más lento y usa 1.5–4× la memoria de std a igual nivel.

**Conclusión:** **no existe ningún escenario medido en el que CF labeling supere al
estándar.** A igual nivel: empata en comunicación (UC2/UC3) o pierde por ~100× (UC4), pierde
en corrección (falla en tight/level=1), y pierde en tiempo y memoria. Lo único a favor de CF
es el setup sin rlk colectiva (UC4), eclipsado por el blow-up de comunicación. El relato del
TFM debe ser honesto: CF es interesante teóricamente pero sin ventaja práctica en estos casos.

Análisis detallado: `~/vault/proyectos/tfm-uvigo/analisis-comparativa-nivel-fijo.md`.

---

## Notas de Implementación

### Dónde se fuerza level=1 hoy

- `Mult` (`labeling.go`): β `elementsB[0][0]` y temporales `labeledciphertext{1,2}elementsB`
  alocados con `NewCiphertext(params, params.MaxLevel(), 1)` → nivel = tercer arg = 1.
- `MultOverflow` (`labeling.go`): `a1beta2`, `a2beta1`, `alpha` (vía `minLevel`) a level=1.

`KeepLevel` reusa la misma álgebra pero aloca esos ciphertexts al nivel de las entradas
(MaxLevel para frescos). Para no duplicar lógica, extraer un helper privado parametrizado
por nivel y que `Mult`/`MultOverflow` lo llamen con `level=1` (comportamiento actual
intacto, sin romper tests existentes).

### Equivalencia esperada

`MultKeepLevel(...)` + `RescaleToLevel(→1)` debe coincidir (nivel y valor decodificado) con
`Mult(...)` directo, confirmando que computar-a-MaxLevel-y-rescalar ≈ computar-a-level=1.
Esto valida que la celda `label`/level=1 y `label_max`+rescale son la misma medida.

### Coste de re-ejecución

UC2/UC3: 4 variantes × 3 DB × 3 perfiles × 20 reps. UC4: 3 variantes × 3 DB × 3 perfiles ×
20 reps. CSVs regenerados, backward compatible (misma cabecera).
