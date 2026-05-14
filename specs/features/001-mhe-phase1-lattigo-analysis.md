# MHE Phase 1: Análisis y Validación de APIs Lattigo Multiparty

**ID:** 001  
**Estado:** Done  
**Fecha:** 2026-05-14  
**Autor:** juanmartin

---

## Objetivo

Validar que las APIs del paquete `multiparty` de Lattigo v6.1.1 (y su sub-paquete `mpbgv`) son utilizables con los parámetros BGV del proyecto, ejecutando el ciclo completo MHE: generación distribuida de claves → cifrado colectivo → evaluación homomórfica → descifrado threshold. El resultado es un ejemplo ejecutable y tests de integración que sirven de base para las Fases 2-5.

---

## Contexto

El roadmap del TFM exige extender el labeling a escenarios multipartitos. Antes de implementar adaptadores propios (Fases 2-5), es necesario verificar qué ofrece Lattigo y cómo encaja con los tipos ya existentes en el proyecto.

**Hallazgo clave**: en Lattigo v6.1.1 el paquete se llama `multiparty` (no `mhe`), con `multiparty/mpbgv` para las funcionalidades específicas de BGV. Las claves de evaluación distribuidas usan `multiparty.RelinearizationKeyGenProtocol` (2 rondas), y el descifrado threshold N-of-N se implementa mediante `multiparty.KeySwitchProtocol` (switch hacia sk=0). El módulo del proyecto es `github.com/juanmartin1892/lattigo-labeling`.

**Papers de referencia**:
- Mouchet et al. (2021): "Multiparty HE from RLWE" — <https://eprint.iacr.org/2020/304.pdf>
- Asharov et al. (2012): "MPC with low communication via threshold FHE" — <https://eprint.iacr.org/2011/613.pdf>

---

## Interfaz Pública

Esta fase no expone tipos nuevos al paquete `labeling`. El artefacto entregable es un ejemplo en `examples/multiparty_basic/` y un test de integración en `multiparty_integration_test.go`.

```go
// examples/multiparty_basic/main.go
// Demuestra el protocolo MHE completo (N-of-N) con BGV y 2 partes.
// Fases: setup → keygen colectivo → encrypt → eval (suma) → keyswitch → decrypt.
func main()

// multiparty_integration_test.go — tests de integración (build tag: integration)
// TestMHESetupBGVParams verifica que los parámetros BGV del proyecto
// son compatibles con multiparty.PublicKeyGenProtocol.
func TestMHESetupBGVParams(t *testing.T)

// TestMHECollectiveKeyGen verifica generación colectiva de pk con 2 y 3 partes.
func TestMHECollectiveKeyGen(t *testing.T)

// TestMHERelinKeyGen verifica generación de rlk distribuida (2 rondas).
func TestMHERelinKeyGen(t *testing.T)

// TestMHEThresholdDecrypt verifica descifrado threshold N-of-N con KeySwitchProtocol.
func TestMHEThresholdDecrypt(t *testing.T)

// TestMHEFullRoundTrip ejercita setup + encrypt + eval (suma) + decrypt con 2 partes.
func TestMHEFullRoundTrip(t *testing.T)
```

---

## Comportamiento Esperado

| Escenario | Resultado esperado |
|-----------|-------------------|
| `TestMHESetupBGVParams` con params del proyecto | `PublicKeyGenProtocol` se inicializa sin error; `CRS` muestrea correctamente |
| `TestMHECollectiveKeyGen` con N=2 partes | `rlwe.PublicKey` final es válida para cifrar; descifrable con sk_ideal = sk₁ + sk₂ |
| `TestMHECollectiveKeyGen` con N=3 partes | Idem con sk_ideal = sk₁ + sk₂ + sk₃ |
| `TestMHERelinKeyGen` con N=2 partes | `rlwe.RelinearizationKey` generada en 2 rondas; evaluador puede multiplicar compactamente |
| `TestMHEThresholdDecrypt` con N=2 | `KeySwitchProtocol` (sk'=0) produce ciphertext descifrable por cualquier parte con sk_ideal |
| `TestMHEFullRoundTrip`: P₁ cifra 7, P₂ cifra 3, suma homomórfica, descifrado colectivo | Resultado descifrado = 10 |

---

## Casos Edge

- [x] Los params de test MHE (`LogP=55,55`) son distintos de los de los ejemplos existentes (`PlaintextModulus: 0x3ee0001`) — ambos conjuntos de params coexisten en el mismo test file sin conflicto
- [x] CRS con la misma semilla en distintas partes produce el mismo `PublicKeyGenCRP` (determinismo requerido)
- [x] Agregación de shares fuera de orden (P₂ antes que P₁) da el mismo resultado (conmutatividad)
- [x] N=1 parte: Lattigo acepta N=1 sin error; degenera correctamente a single-party

---

## Dependencias

- Paquetes de Lattigo ya en `go.mod`: `github.com/tuneinsight/lattigo/v6/multiparty`, `github.com/tuneinsight/lattigo/v6/multiparty/mpbgv`, `github.com/tuneinsight/lattigo/v6/schemes/bgv`
- No requiere spec previa; es la primera del roadmap MHE
- Las Fases 2-5 dependen de esta spec

---

## Criterios de Aceptación

- [x] `go build ./examples/multiparty_basic/` exitoso
- [x] `go test -run TestMHE -tags integration ./...` pasan todos los tests
- [x] `go vet ./...` sin warnings
- [x] `go test -race -tags integration ./...` sin data races
- [x] Cada test verifica correctitud matemática (no solo ausencia de error): el plaintext recuperado coincide con el esperado
- [x] Los parámetros BGV usados en los tests están documentados con `LogN`, `LogQ`, `LogP`, `PlaintextModulus` y justificación
- [x] El ejemplo `examples/multiparty_basic/main.go` es ejecutable y produce output legible que muestra cada fase del protocolo

---

## Notas de Implementación

### Parámetros BGV recomendados para los tests

Los parámetros actuales del proyecto (`bgv.ParametersLiteral`) deben verificarse contra los requisitos de `multiparty`: el paquete exige `LogP > 0` para el flooding de ruido en key-switching. Si los params actuales tienen `LogP=0`, añadir un conjunto de params de test exclusivo para integración MHE.

Punto de partida sugerido (compatible con `multiparty` según tests de Lattigo):
```go
bgv.ParametersLiteral{
    LogN:             14,
    LogQ:             []int{56, 55, 55, 54, 54, 54},
    LogP:             []int{55, 55},
    PlaintextModulus: 0x101,  // 257 — primo, permite slots
}
```

### Modelo de ejecución (simulado en un único proceso)

Los tests simulan las N partes en goroutines o de forma secuencial compartiendo canales Go. No se requiere red real. El CRS se implementa como `utils.KeyedPRNG` con la misma semilla en todas las "partes".

### Tipos clave a usar

| Protocolo | Tipo Lattigo |
|-----------|-------------|
| Keygen individual | `rlwe.KeyGenerator` |
| Keygen colectivo pk | `multiparty.PublicKeyGenProtocol` + `PublicKeyGenShare` |
| Keygen rlk (2 rondas) | `multiparty.RelinearizationKeyGenProtocol` + `RelinearizationKeyGenShare` |
| Cifrado | `bgv.Encryptor` con `rlwe.PublicKey` colectiva |
| Evaluación | `bgv.Evaluator` (igual que single-party) |
| Descifrado threshold | `multiparty.KeySwitchProtocol` → `rlwe.Decryptor` |
### Lo que NO implementa esta fase

- Adaptadores propios (`MHELabeledEncryptor`, `MHELabeledDecryptor`) — eso es Fase 2
- Threshold t-of-N (`Thresholdizer`/`Combiner`) — fuera de scope, solo N-of-N
- Receptor externo (`PublicKeySwitchProtocol`) — el foco del TFM es en adaptadores labeling
- Red real o serialización de shares — solo simulación local
