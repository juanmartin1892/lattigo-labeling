# CF-Scalar Protocol for UC4 Variance

**ID:** 015  
**Estado:** Done  
**Fecha:** 2026-06-10  
**Autor:** juanmartin

---

## Objetivo

Implementar el protocolo CF-scalar que elimina la multiplicación CT×polinomio-heterogéneo
del pipeline de varianza (UC4), sustituyéndola por una multiplicación CT×escalar. Esto reduce
el ruido de 2^46 (label_compact con rotate-and-sum) a ~2^33, pasando el perfil S3/min 5/5.

---

## Contexto

El protocolo CF-scalar (exp8) usa una máscara broadcast constante b_j por bloque:
```
a_i = v_i − b_j   (público)
S = Σ a_i          (escalar público)
S2 = Σ a_i²        (escalar público)
β = Enc([b_j,...,b_j])
β_sq = Enc([b_j²,...,b_j²])
α = 2·S·β + blockSize·β_sq     (dos scalar×CT, sin CT×CT, sin rotaciones)
decrypt(α)[0] + S2 = Σ v_i²   ✓
```

Clave: con plaintext constante [c,...,c], INTT(p) = c en pos=0 y 0 en el resto,
por lo que la multiplicación CT×constantePT es ruido O(c × B_fresh) en vez de
O(N × max_coeff × B_fresh). Exp8 confirma CF-scalar = 5/5 en S3/min.

**No requiere rlk ni Galois keys** — la evaluación es solo CT+CT y CT×escalar.

---

## Interfaz Pública

```go
// EncryptCFScalar generates β = Enc([bj,...,bj]) and βSq = Enc([bj²,...,bj²]) for a
// broadcast mask bj chosen uniformly in [0, maskBound). Also returns S = Σ(v_i−bj) mod t
// and S2 = Σ(v_i−bj)² mod t over the first N/2 data slots of values.
//
// The result satisfies: decrypt(CFScalarAlpha(β, βSq, S, N/2))[0] + S2 = Σ v_i² mod t.
func EncryptCFScalar(ctx MHEContext, values []uint64, maskBound uint64) (beta, betaSq *rlwe.Ciphertext, S, S2, bj uint64, err error)

// CFScalarAlpha computes α = 2·S·β + blockSize·β_sq using two scalar×CT multiplications.
// No relinearization or Galois keys are required.
//
// blockSize must equal params.N()/2 (8192 for LogN=14), NOT params.MaxSlots().
func CFScalarAlpha(ctx MHEContext, beta, betaSq *rlwe.Ciphertext, S, blockSize uint64) (*rlwe.Ciphertext, error)

// AggregateRawAlphas sums a slice of α ciphertexts into a single aggregate ciphertext
// via CT additions only. No evaluation keys are required.
func AggregateRawAlphas(ctx MHEContext, alphas []*rlwe.Ciphertext) (*rlwe.Ciphertext, error)

// GenCiphertextDecryptionShare generates party i's CKS share for switching ct from sk
// (the party's individual secret key share) to the zero secret key.
func GenCiphertextDecryptionShare(ctx MHEContext, sk *rlwe.SecretKey, ct *rlwe.Ciphertext) (LabeledDecryptionShare, error)

// DecryptThresholdCiphertext decrypts ct using the combined CKS share produced by
// AggregateLabeledDecryptionShares, returning the plaintext slot values.
func DecryptThresholdCiphertext(ctx MHEContext, combined LabeledDecryptionShare, ct *rlwe.Ciphertext) ([]uint64, error)
```

---

## Comportamiento Esperado

| Entrada | Salida Esperada |
|---------|----------------|
| `EncryptCFScalar(ctx, values, maskBound)` | β descifra a [bj,...,bj]; βSq a [bj²,...,bj²] |
| `CFScalarAlpha(ctx, β, βSq, S, N/2)` | slot0(decrypt(α)) = 2·S·bj + N/2·bj² |
| `AggregateRawAlphas(ctx, alphas)` | CT suma de todos los bloques |
| `decrypt(alphaTotal)[0] + S2_total mod t` | Σ v_i² mod t (correcto en S3/min) |

---

## Casos Edge

- [ ] `maskBound = 0` → error (RandUniform con bound=0 no está definido)
- [ ] `alphas` vacío → error en AggregateRawAlphas
- [ ] `sk = nil` → error en GenCiphertextDecryptionShare
- [ ] `ct = nil` → error en GenCiphertextDecryptionShare y DecryptThresholdCiphertext
- [ ] `blockSize = 0` → comportamiento indefinido; caller debe pasar N/2

---

## Dependencias

- Spec #014 (mask-bound-fix) — `EncryptWithMaskBound`, `minValInBlock` reutilizados
- Spec #011 (uc4-varianza-compactacion-beta) — benchmark UC4 que se extiende

---

## Criterios de Aceptación

- [x] `TestEncryptCFScalar` table-driven en `labeling/mhe_labeling_test.go` pasando
- [x] `TestCFScalarAlpha` en `labeling/mhe_labeling_test.go` pasando
- [x] `TestCFScalarE2E` (perfiles full/tight/min) en `labeling/mhe_labeling_test.go` pasando
- [x] `TestGenCiphertextDecryptionShare` pasando
- [x] `TestDecryptThresholdCiphertext` pasando
- [x] Variante `label_cf_scalar` en `benchmarks/uc4_variance_compact/main.go`
- [x] `label_cf_scalar`: correct=true para profile=full y tight (20/20)
- [x] `label_cf_scalar`: correct=true para profile=min (20/20) — objetivo principal
- [x] `std`: correct=false para profile=min (baseline)
- [x] CF-scalar setup NO genera rlk ni Galois keys
- [x] `go vet ./...` sin warnings
- [x] `go test ./labeling/... -race -count=1` sin data races

---

## Notas de Implementación

- `blockSize = ctx.Params.N() / 2` (no `MaxSlots()` que devuelve N para t ≡ 1 mod 2N)
- `ring.RandUniform(prng, maskBound, uint64(1<<bits.Len64(maskBound)-1))` para bj
- `bgv.NewEvaluator(ctx.Params.Parameters, nil)` — sin eval keys en CFScalarAlpha
- `eval.MulNew(β, scalarSlice)` donde scalarSlice `[]uint64` de longitud blockSize
- Para la suma total: agregar todos los β_j → betaTotal; CKS → decBeta[0] = Σbj;
  sum = (S_total + blockSize × Σbj) % t. Así se obtiene sum con 1 CKS adicional.
