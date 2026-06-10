// Copyright 2025 Juan Martín Pérez
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package labeling

import (
	"errors"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
)

// CopyBeta returns a deep copy of lct.elementsB[0][0], the β component used for
// compact self-product decryption. The returned ciphertext shares no ring.Poly
// memory with lct and is safe to hold across MultOverflowLabeledFree calls.
func CopyBeta(ctx MHEContext, lct PlaintextLabeledciphertext) (*rlwe.Ciphertext, error) {
	if len(lct.elementsB) == 0 || len(lct.elementsB[0]) == 0 {
		return nil, errors.New("CopyBeta: lct contains no ciphertext component")
	}
	src := &lct.elementsB[0][0]
	dst := rlwe.NewCiphertext(ctx.Params, 1, src.Level())
	eval := bgv.NewEvaluator(ctx.Params.Parameters, nil)
	if err := eval.Add(src, []uint64{0}, dst); err != nil {
		return nil, fmt.Errorf("CopyBeta: %w", err)
	}
	return dst, nil
}

// CompactSelfProductShare holds one party's CKS shares for compact threshold
// decryption of a self-product CiphertextLabeledciphertext. Only α (the
// accumulated α_final after rotate-and-sum) and β_orig (the β before
// MultOverflowLabeledFree) need individual shares.
//
// This reduces the number of CKS operations from O(2^L) to O(1) per block,
// where L is the number of rotate-and-sum steps.
type CompactSelfProductShare struct {
	Alpha LabeledDecryptionShare
	Beta  LabeledDecryptionShare
}

// GenCompactSelfProductShare generates party i's compact decryption shares for a
// self-product result. clct must hold the α_final produced by
// CompactRotateAndSumAlpha; betaOrig must be the β of the original
// PlaintextLabeledciphertext before MultOverflowLabeledFree was called.
//
// Only two CKS shares are generated — one for α_final and one for betaOrig —
// regardless of how many rotate-and-sum steps were applied.
func GenCompactSelfProductShare(ctx MHEContext, sk *rlwe.SecretKey, clct CiphertextLabeledciphertext, betaOrig *rlwe.Ciphertext) (CompactSelfProductShare, error) {
	if sk == nil {
		return CompactSelfProductShare{}, errors.New("GenCompactSelfProductShare: sk must not be nil")
	}
	if clct.elementsA == nil {
		return CompactSelfProductShare{}, errors.New("GenCompactSelfProductShare: clct contains no A component")
	}
	if betaOrig == nil {
		return CompactSelfProductShare{}, errors.New("GenCompactSelfProductShare: betaOrig must not be nil")
	}

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return CompactSelfProductShare{}, fmt.Errorf("GenCompactSelfProductShare: %w", err)
	}
	zeroSK := rlwe.NewSecretKey(ctx.Params)

	α := (*rlwe.Ciphertext)(clct.elementsA)
	alphaShare := proto.AllocateShare(α.Level())
	proto.GenShare(sk, zeroSK, α, &alphaShare)

	betaShare := proto.AllocateShare(betaOrig.Level())
	proto.GenShare(sk, zeroSK, betaOrig, &betaShare)

	return CompactSelfProductShare{
		Alpha: LabeledDecryptionShare{Value: alphaShare},
		Beta:  LabeledDecryptionShare{Value: betaShare},
	}, nil
}

// AggregateCompactSelfProductShares combines all parties' CompactSelfProductShares
// into a single combined share for DecryptThresholdCompact.
//
// shares must contain at least one element and all shares must have matching
// Alpha and Beta levels.
func AggregateCompactSelfProductShares(ctx MHEContext, shares []CompactSelfProductShare) (CompactSelfProductShare, error) {
	if len(shares) == 0 {
		return CompactSelfProductShare{}, errors.New("AggregateCompactSelfProductShares: shares must not be empty")
	}

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return CompactSelfProductShare{}, fmt.Errorf("AggregateCompactSelfProductShares: %w", err)
	}

	combined := CompactSelfProductShare{
		Alpha: LabeledDecryptionShare{Value: proto.AllocateShare(shares[0].Alpha.Value.Level())},
		Beta:  LabeledDecryptionShare{Value: proto.AllocateShare(shares[0].Beta.Value.Level())},
	}
	for i, s := range shares {
		if err := proto.AggregateShares(combined.Alpha.Value, s.Alpha.Value, &combined.Alpha.Value); err != nil {
			return CompactSelfProductShare{}, fmt.Errorf("AggregateCompactSelfProductShares: alpha share %d: %w", i, err)
		}
		if err := proto.AggregateShares(combined.Beta.Value, s.Beta.Value, &combined.Beta.Value); err != nil {
			return CompactSelfProductShare{}, fmt.Errorf("AggregateCompactSelfProductShares: beta share %d: %w", i, err)
		}
	}
	return combined, nil
}

// CompactRotateAndSumAlpha runs the rotate-and-sum accumulation tree on the α
// component of clct, returning a new CiphertextLabeledciphertext that contains
// only the accumulated α_final (no β component).
//
// This is the memory-efficient alternative to running SumOverflowCiphertextLabeled
// + RotateColumnsOverflow: it avoids the exponential β explosion (2^L β ciphertexts
// after L steps) by operating exclusively on the α ciphertext.
//
// rotOffsets must be the same slice passed later to DecryptThresholdCompact.
// evk must contain Galois keys for each step in rotOffsets.
func CompactRotateAndSumAlpha(ctx MHEContext, clct CiphertextLabeledciphertext, rotOffsets []int, evk *rlwe.MemEvaluationKeySet) (CiphertextLabeledciphertext, error) {
	if clct.elementsA == nil {
		return CiphertextLabeledciphertext{}, errors.New("CompactRotateAndSumAlpha: clct contains no A component")
	}
	eval := bgv.NewEvaluator(ctx.Params.Parameters, evk)
	acc := (*rlwe.Ciphertext)(clct.elementsA)
	for _, step := range rotOffsets {
		rotated, err := eval.RotateColumnsNew(acc, step)
		if err != nil {
			return CiphertextLabeledciphertext{}, fmt.Errorf("CompactRotateAndSumAlpha rotate step=%d: %w", step, err)
		}
		newAcc, err := eval.AddNew(acc, rotated)
		if err != nil {
			return CiphertextLabeledciphertext{}, fmt.Errorf("CompactRotateAndSumAlpha add step=%d: %w", step, err)
		}
		acc = newAcc
	}
	ct := CiphertextElement(*acc)
	return CiphertextLabeledciphertext{elementsA: &ct}, nil
}

// DecryptThresholdCompact recovers the slot-sum of squares from a self-product
// CiphertextLabeledciphertext using the compact β representation.
//
// clct must be the output of CompactRotateAndSumAlpha (contains only α_final).
// betaOrig must be the same ciphertext passed to GenCompactSelfProductShare.
// rotOffsets must be the same slice used in CompactRotateAndSumAlpha, applied in
// the same order.
//
// Internally: decrypts betaOrig once → b; computes b_sq_sum = Σ_k rot_k(b⊙b)
// in plaintext; decrypts α_final; returns (plainAlpha + b_sq_sum) mod t.
func DecryptThresholdCompact(ctx MHEContext, combined CompactSelfProductShare, clct CiphertextLabeledciphertext, betaOrig *rlwe.Ciphertext, rotOffsets []int) ([]uint64, error) {
	if clct.elementsA == nil {
		return nil, errors.New("DecryptThresholdCompact: clct contains no A component")
	}
	if betaOrig == nil {
		return nil, errors.New("DecryptThresholdCompact: betaOrig must not be nil")
	}

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return nil, fmt.Errorf("DecryptThresholdCompact: %w", err)
	}
	encoder := bgv.NewEncoder(ctx.Params.Parameters)
	zeroSK := rlwe.NewSecretKey(ctx.Params)
	dec := rlwe.NewDecryptor(ctx.Params, zeroSK)

	switchAndDecode := func(ct *rlwe.Ciphertext, share LabeledDecryptionShare) ([]uint64, error) {
		ctSwitched := rlwe.NewCiphertext(ctx.Params, 1, ct.Level())
		proto.KeySwitch(ct, share.Value, ctSwitched)
		out := make([]uint64, ctx.Params.MaxSlots())
		return out, encoder.Decode(dec.DecryptNew(ctSwitched), out)
	}

	// Decrypt β_orig once → b.
	b, err := switchAndDecode(betaOrig, combined.Beta)
	if err != nil {
		return nil, fmt.Errorf("DecryptThresholdCompact: decode betaOrig: %w", err)
	}

	// Decrypt α_final → plainAlpha.
	α := (*rlwe.Ciphertext)(clct.elementsA)
	plainAlpha, err := switchAndDecode(α, combined.Alpha)
	if err != nil {
		return nil, fmt.Errorf("DecryptThresholdCompact: decode α: %w", err)
	}

	// Reconstruct b_sq_sum = Σ_k rot_k(b⊙b) in plaintext.
	// BGV rotates each half of the slot vector independently (circular within halfSlots).
	T := ctx.Params.PlaintextModulus()
	maxSlots := ctx.Params.MaxSlots()
	halfSlots := maxSlots / 2

	bSq := make([]uint64, maxSlots)
	for i := range maxSlots {
		bSq[i] = (b[i] * b[i]) % T
	}

	tmp := make([]uint64, maxSlots)
	for _, step := range rotOffsets {
		// Build rot_step(bSq) into tmp without aliasing.
		for i := 0; i < halfSlots; i++ {
			tmp[i] = bSq[(i+step)%halfSlots]
		}
		for i := halfSlots; i < maxSlots; i++ {
			tmp[i] = bSq[halfSlots+(i-halfSlots+step)%halfSlots]
		}
		for i := range maxSlots {
			bSq[i] = (bSq[i] + tmp[i]) % T
		}
	}

	result := make([]uint64, maxSlots)
	for i := range maxSlots {
		result[i] = (plainAlpha[i] + bSq[i] + T) % T
	}
	return result, nil
}

// MHEContext holds the shared parameters and collective public key for an MHE labeling
// session. It is produced by NewMHEContext and consumed by EncryptLabeled and subsequent
// MHE operations (specs 003–006).
//
// The ideal secret key (sum of all party shares) is never stored here; it must not be
// assembled in production use.
type MHEContext struct {
	Params       Parameters
	CollectivePK *rlwe.PublicKey
}

// NewMHEContext runs the collective public key generation protocol for the given secret
// key shares and CRS, returning the MHEContext shared by all parties.
//
// skShares contains one independently generated *rlwe.SecretKey per party. crs must be
// a deterministic PRNG initialised with the same seed on all parties so that they agree
// on the common reference polynomial without network communication
// (e.g. sampling.NewKeyedPRNG(sharedSeed)).
//
// Returns an error if any input is nil or skShares is empty; the protocol itself is not
// run until all inputs are validated.
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

	n := len(skShares)
	protos := make([]multiparty.PublicKeyGenProtocol, n)
	protos[0] = multiparty.NewPublicKeyGenProtocol(params)
	for i := 1; i < n; i++ {
		protos[i] = protos[0].ShallowCopy()
	}

	crp := protos[0].SampleCRP(crs)

	shares := make([]multiparty.PublicKeyGenShare, n)
	for i := range shares {
		shares[i] = protos[i].AllocateShare()
		protos[i].GenShare(skShares[i], crp, &shares[i])
	}
	for i := 1; i < n; i++ {
		protos[0].AggregateShares(shares[0], shares[i], &shares[0])
	}

	pk := rlwe.NewPublicKey(params)
	protos[0].GenPublicKey(shares[0], crp, pk)

	return MHEContext{Params: params, CollectivePK: pk}, nil
}

// EncryptLabeled encrypts a vector of values under the MHE collective public key using
// the labeling scheme.
//
// Returns a PlaintextLabeledciphertext where elementsA holds the plaintext mask component
// and elementsB holds the ciphertext component encrypted under the collective key.
//
// It is semantically equivalent to Encrypt(ctx.Params, ctx.CollectivePK, values).
func EncryptLabeled(ctx MHEContext, values []uint64) (PlaintextLabeledciphertext, error) {
	return Encrypt(ctx.Params, ctx.CollectivePK, values)
}

// smudgingNoise returns the discrete Gaussian noise distribution used for CKS smudging.
// σ = 8·DefaultNoise following Mouchet et al. 2021 (PETS); NewKeySwitchProtocol combines
// this with NoiseFreshSK internally.
func smudgingNoise() ring.DiscreteGaussian {
	const sigma = 8 * rlwe.DefaultNoise
	return ring.DiscreteGaussian{Sigma: sigma, Bound: 6 * sigma}
}

// LabeledDecryptionShare holds one party's key-switch share for the B-component of a
// PlaintextLabeledciphertext. It is produced by GenLabeledDecryptionShare and consumed
// by AggregateLabeledDecryptionShares.
type LabeledDecryptionShare struct {
	Value multiparty.KeySwitchShare
}

// GenLabeledDecryptionShare generates party i's collective key-switch share for switching
// lct.elementsB[0][0] from sk (the party's individual secret key share) to the zero secret
// key. All N parties must contribute a share before decryption.
//
// Noise flooding uses σ = 8·rlwe.DefaultNoise with bound 6σ, following the standard
// parameter choice from Mouchet et al. 2021 (PETS). NewKeySwitchProtocol combines this
// with NoiseFreshSK to form the effective smudging standard deviation.
//
// Returns an error if sk is nil or if lct contains no ciphertext component.
func GenLabeledDecryptionShare(ctx MHEContext, sk *rlwe.SecretKey, lct PlaintextLabeledciphertext) (LabeledDecryptionShare, error) {
	if sk == nil {
		return LabeledDecryptionShare{}, errors.New("GenLabeledDecryptionShare: sk must not be nil")
	}
	if len(lct.elementsB) == 0 || len(lct.elementsB[0]) == 0 {
		return LabeledDecryptionShare{}, errors.New("GenLabeledDecryptionShare: lct contains no ciphertext component")
	}
	β := &lct.elementsB[0][0]

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return LabeledDecryptionShare{}, fmt.Errorf("GenLabeledDecryptionShare: NewKeySwitchProtocol: %w", err)
	}

	zeroSK := rlwe.NewSecretKey(ctx.Params)
	share := proto.AllocateShare(β.Level())
	proto.GenShare(sk, zeroSK, β, &share)

	return LabeledDecryptionShare{Value: share}, nil
}

// AggregateLabeledDecryptionShares combines all parties' decryption shares into a single
// combined share that can be passed to DecryptThresholdLabeled.
//
// shares must contain at least one element; order does not affect the result (the
// underlying ring addition is commutative). Returns an error if shares is empty.
func AggregateLabeledDecryptionShares(ctx MHEContext, shares []LabeledDecryptionShare) (LabeledDecryptionShare, error) {
	if len(shares) == 0 {
		return LabeledDecryptionShare{}, errors.New("AggregateLabeledDecryptionShares: shares must not be empty")
	}

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return LabeledDecryptionShare{}, fmt.Errorf("AggregateLabeledDecryptionShares: NewKeySwitchProtocol: %w", err)
	}

	// Allocate a fresh accumulator so no input share's underlying ring.Poly is mutated.
	// Start by copying shares[0] into it (0 + shares[0] = shares[0]).
	combined := LabeledDecryptionShare{Value: proto.AllocateShare(shares[0].Value.Level())}
	for i := range shares {
		if err := proto.AggregateShares(combined.Value, shares[i].Value, &combined.Value); err != nil {
			return LabeledDecryptionShare{}, fmt.Errorf("AggregateLabeledDecryptionShares: share %d: %w", i, err)
		}
	}
	return combined, nil
}

// GenCollectiveRelinKey runs the two-round collective relinearization key generation
// protocol for the given secret key shares and CRS, returning the collective
// relinearization key required by MultLabeled.
//
// skShares contains one *rlwe.SecretKey per party, the same shares used in
// NewMHEContext. crs must be initialised with the same seed on all parties
// (e.g. sampling.NewKeyedPRNG(sharedSeed)).
//
// The collective relinearization key enables relinearization of ciphertexts encrypted
// under the collective public key without assembling the ideal secret key. It is
// produced by a two-round interactive protocol: in round one each party contributes a
// share built from an ephemeral secret key; in round two each party uses the aggregated
// round-one result to produce their second share.
//
// Returns an error if skShares is empty or any element is nil.
func GenCollectiveRelinKey(params Parameters, skShares []*rlwe.SecretKey, crs multiparty.CRS) (*rlwe.RelinearizationKey, error) {
	if len(skShares) == 0 {
		return nil, errors.New("GenCollectiveRelinKey: skShares must not be empty")
	}
	for i, sk := range skShares {
		if sk == nil {
			return nil, fmt.Errorf("GenCollectiveRelinKey: skShares[%d] is nil", i)
		}
	}

	n := len(skShares)
	protos := make([]multiparty.RelinearizationKeyGenProtocol, n)
	protos[0] = multiparty.NewRelinearizationKeyGenProtocol(params)
	for i := 1; i < n; i++ {
		protos[i] = protos[0].ShallowCopy()
	}

	crp := protos[0].SampleCRP(crs)

	ephSKs := make([]*rlwe.SecretKey, n)
	round1 := make([]multiparty.RelinearizationKeyGenShare, n)
	round2 := make([]multiparty.RelinearizationKeyGenShare, n)
	for i := range protos {
		ephSKs[i], round1[i], round2[i] = protos[i].AllocateShare()
		protos[i].GenShareRoundOne(skShares[i], crp, ephSKs[i], &round1[i])
	}
	for i := 1; i < n; i++ {
		protos[0].AggregateShares(round1[0], round1[i], &round1[0])
	}
	for i := range protos {
		protos[i].GenShareRoundTwo(ephSKs[i], skShares[i], round1[0], &round2[i])
	}
	for i := 1; i < n; i++ {
		protos[0].AggregateShares(round2[0], round2[i], &round2[0])
	}

	rlk := rlwe.NewRelinearizationKey(params)
	protos[0].GenRelinearizationKey(round1[0], round2[0], rlk)
	return rlk, nil
}

// MultOverflowLabeledFree multiplies two PlaintextLabeledciphertexts using the overflow
// technique without requiring a relinearization key. Unlike MultOverflowLabeled, no
// key-switching is performed and no collective rlk is needed in the setup phase.
//
// The overflow formula is identical to MultOverflowLabeled:
//
//	α = Enc(pk_col, a₁·a₂) + a₁·β₂ + a₂·β₁
//	elementsB = [β₁, β₂]
//
// The result is a CiphertextLabeledciphertext at the same level as the inputs; no
// multiplicative level is consumed in the inner BGV scheme (depth 0 inner circuit).
//
// Note: subsequent SumOverflowCiphertextLabeled + RotateColumnsOverflow steps cause β
// to grow exponentially (2^L pairs after L rotation steps). Use DecryptThresholdCompact
// from spec 011 to collapse the β back to O(1) shares at decryption time.
//
// Returns an error if either ciphertext contains no ciphertext component.
func MultOverflowLabeledFree(ctx MHEContext, lct1, lct2 PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error) {
	if len(lct1.elementsB) == 0 || len(lct1.elementsB[0]) == 0 {
		return CiphertextLabeledciphertext{}, errors.New("MultOverflowLabeledFree: lct1 contains no ciphertext component")
	}
	if len(lct2.elementsB) == 0 || len(lct2.elementsB[0]) == 0 {
		return CiphertextLabeledciphertext{}, errors.New("MultOverflowLabeledFree: lct2 contains no ciphertext component")
	}
	return MultOverflow(ctx.Params, lct1, lct2, ctx.CollectivePK, nil)
}

// SumLabeled adds two PlaintextLabeledciphertexts encrypted under the same MHEContext
// collective public key and returns their labeled sum.
//
// The evaluator does not need any secret key share. The algebra is:
//
//	elementsA_out = (a1 + a2) mod T
//	β_out = β1 + β2
//
// Returns an error if either ciphertext contains no ciphertext component.
func SumLabeled(ctx MHEContext, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error) {
	if len(lct1.elementsB) == 0 || len(lct1.elementsB[0]) == 0 {
		return PlaintextLabeledciphertext{}, errors.New("SumLabeled: lct1 contains no ciphertext component")
	}
	if len(lct2.elementsB) == 0 || len(lct2.elementsB[0]) == 0 {
		return PlaintextLabeledciphertext{}, errors.New("SumLabeled: lct2 contains no ciphertext component")
	}
	return Sum(ctx.Params.Parameters, lct1, lct2)
}

// MultLabeled multiplies two PlaintextLabeledciphertexts encrypted under the same
// MHEContext collective public key, using the collective relinearization key for degree
// reduction after the homomorphic multiplication.
//
// The evaluator does not need any secret key share; it uses ctx.CollectivePK for the
// fresh encryption of the random mask r and rlk for relinearization. The labeling
// formula is:
//
//	a_out = (a1 × a2 − r) mod T
//	β_out = (β1 × β2) + a1·β2 + a2·β1 + Enc(pk_col, r)
//
// Returns an error if rlk is nil or if either ciphertext contains no ciphertext component.
func MultLabeled(ctx MHEContext, rlk *rlwe.RelinearizationKey, lct1, lct2 PlaintextLabeledciphertext) (PlaintextLabeledciphertext, error) {
	if rlk == nil {
		return PlaintextLabeledciphertext{}, errors.New("MultLabeled: rlk must not be nil")
	}
	if len(lct1.elementsB) == 0 || len(lct1.elementsB[0]) == 0 {
		return PlaintextLabeledciphertext{}, errors.New("MultLabeled: lct1 contains no ciphertext component")
	}
	if len(lct2.elementsB) == 0 || len(lct2.elementsB[0]) == 0 {
		return PlaintextLabeledciphertext{}, errors.New("MultLabeled: lct2 contains no ciphertext component")
	}
	evk := GenerateMemEvaluationKeySet(rlk)
	return Mult(ctx.Params, lct1, lct2, ctx.CollectivePK, evk)
}

// MultOverflowLabeled multiplies two PlaintextLabeledciphertexts encrypted under the same
// MHEContext collective public key using the overflow technique, returning a
// CiphertextLabeledciphertext that supports deeper multiplicative depth.
//
// The evaluator does not need any secret key share; it uses ctx.CollectivePK for the
// fresh encryption of the a₁·a₂ component and rlk for the evaluation key set. The
// overflow formula is:
//
//	α = Enc(pk_col, a₁·a₂) + a₁·β₂ + a₂·β₁
//	elementsB = [β₁, β₂]
//
// Returns an error if rlk is nil or if either ciphertext contains no ciphertext component.
func MultOverflowLabeled(ctx MHEContext, rlk *rlwe.RelinearizationKey, lct1, lct2 PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error) {
	if rlk == nil {
		return CiphertextLabeledciphertext{}, errors.New("MultOverflowLabeled: rlk must not be nil")
	}
	if len(lct1.elementsB) == 0 || len(lct1.elementsB[0]) == 0 {
		return CiphertextLabeledciphertext{}, errors.New("MultOverflowLabeled: lct1 contains no ciphertext component")
	}
	if len(lct2.elementsB) == 0 || len(lct2.elementsB[0]) == 0 {
		return CiphertextLabeledciphertext{}, errors.New("MultOverflowLabeled: lct2 contains no ciphertext component")
	}
	evk := GenerateMemEvaluationKeySet(rlk)
	return MultOverflow(ctx.Params, lct1, lct2, ctx.CollectivePK, evk)
}

// SumOverflowLabeled adds a CiphertextLabeledciphertext and a PlaintextLabeledciphertext
// encrypted under the same MHEContext, returning a CiphertextLabeledciphertext.
//
// The evaluator does not need any secret key share. The algebra is:
//
//	α_out = α₁ + a₂   (ciphertext + plaintext addition)
//	elementsB_out = [β₁…, β₂]  (B components concatenated)
//
// Returns an error if either operand contains no ciphertext component.
func SumOverflowLabeled(ctx MHEContext, clct CiphertextLabeledciphertext, lct PlaintextLabeledciphertext) (CiphertextLabeledciphertext, error) {
	if clct.elementsA == nil {
		return CiphertextLabeledciphertext{}, errors.New("SumOverflowLabeled: clct contains no A component")
	}
	if len(lct.elementsB) == 0 || len(lct.elementsB[0]) == 0 {
		return CiphertextLabeledciphertext{}, errors.New("SumOverflowLabeled: lct contains no ciphertext component")
	}
	return SumOverflow(ctx.Params, clct, lct)
}

// SumOverflowCiphertextLabeled adds two CiphertextLabeledciphertexts encrypted under the
// same MHEContext, returning a CiphertextLabeledciphertext.
//
// The evaluator does not need any secret key share. The algebra is:
//
//	α_out = α₁ + α₂   (ciphertext addition)
//	elementsB_out = [β₁…, β₂…]  (all B components concatenated)
//
// Returns an error if either operand contains no A component.
func SumOverflowCiphertextLabeled(ctx MHEContext, clct1, clct2 CiphertextLabeledciphertext) (CiphertextLabeledciphertext, error) {
	if clct1.elementsA == nil {
		return CiphertextLabeledciphertext{}, errors.New("SumOverflowCiphertextLabeled: clct1 contains no A component")
	}
	if clct2.elementsA == nil {
		return CiphertextLabeledciphertext{}, errors.New("SumOverflowCiphertextLabeled: clct2 contains no A component")
	}
	return SumOverflowCiphertext(ctx.Params, clct1, clct2)
}

// DecryptThresholdLabeled recovers the plaintext from lct using the combined decryption
// share produced by AggregateLabeledDecryptionShares. No individual or collective secret
// key is required at this step.
//
// Internally applies KeySwitch to lct.elementsB[0][0] to obtain a ciphertext under the
// zero secret key, decodes the mask b, then reconstructs m[i] = (elementsA[i] + b[i]) mod T.
//
// Returns an error if lct contains no ciphertext component.
func DecryptThresholdLabeled(ctx MHEContext, combined LabeledDecryptionShare, lct PlaintextLabeledciphertext) ([]uint64, error) {
	if len(lct.elementsB) == 0 || len(lct.elementsB[0]) == 0 {
		return nil, errors.New("DecryptThresholdLabeled: lct contains no ciphertext component")
	}
	β := &lct.elementsB[0][0]

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return nil, fmt.Errorf("DecryptThresholdLabeled: NewKeySwitchProtocol: %w", err)
	}

	βSwitched := rlwe.NewCiphertext(ctx.Params, 1, β.Level())
	proto.KeySwitch(β, combined.Value, βSwitched)

	zeroSK := rlwe.NewSecretKey(ctx.Params)
	b := make([]uint64, ctx.Params.MaxSlots())
	if err := bgv.NewEncoder(ctx.Params.Parameters).Decode(
		rlwe.NewDecryptor(ctx.Params, zeroSK).DecryptNew(βSwitched), b,
	); err != nil {
		return nil, fmt.Errorf("DecryptThresholdLabeled: decode: %w", err)
	}

	T := ctx.Params.PlaintextModulus()
	result := make([]uint64, len(lct.elementsA))
	for i, a := range lct.elementsA {
		result[i] = (a + b[i] + T) % T
	}
	return result, nil
}

// OverflowDecryptionShare holds one party's collective key-switch shares for all
// ciphertext components of a CiphertextLabeledciphertext: one share for the α component
// (elementsA) and one share per β_ij component (elementsB[i][j]).
//
// The shape of Betas mirrors the corresponding CiphertextLabeledciphertext:
// Betas[i][j] corresponds to elementsB[i][j].
type OverflowDecryptionShare struct {
	Alpha LabeledDecryptionShare
	Betas [][]LabeledDecryptionShare
}

// GenOverflowDecryptionShare generates party i's CKS shares for all ciphertext components
// of clct: one share for α (elementsA) and one per β_ij (elementsB[i][j]).
//
// Uses the same smudging noise as GenLabeledDecryptionShare (σ = 8·rlwe.DefaultNoise).
//
// Returns an error if sk is nil or if clct contains no A component (α).
func GenOverflowDecryptionShare(ctx MHEContext, sk *rlwe.SecretKey, clct CiphertextLabeledciphertext) (OverflowDecryptionShare, error) {
	if sk == nil {
		return OverflowDecryptionShare{}, errors.New("GenOverflowDecryptionShare: sk must not be nil")
	}
	if clct.elementsA == nil {
		return OverflowDecryptionShare{}, errors.New("GenOverflowDecryptionShare: clct contains no A component")
	}

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return OverflowDecryptionShare{}, fmt.Errorf("GenOverflowDecryptionShare: NewKeySwitchProtocol: %w", err)
	}
	zeroSK := rlwe.NewSecretKey(ctx.Params)

	α := (*rlwe.Ciphertext)(clct.elementsA)
	alphaShare := proto.AllocateShare(α.Level())
	proto.GenShare(sk, zeroSK, α, &alphaShare)

	betas := make([][]LabeledDecryptionShare, len(clct.elementsB))
	for i, row := range clct.elementsB {
		betas[i] = make([]LabeledDecryptionShare, len(row))
		for j := range row {
			β := &clct.elementsB[i][j]
			s := proto.AllocateShare(β.Level())
			proto.GenShare(sk, zeroSK, β, &s)
			betas[i][j] = LabeledDecryptionShare{Value: s}
		}
	}

	return OverflowDecryptionShare{
		Alpha: LabeledDecryptionShare{Value: alphaShare},
		Betas: betas,
	}, nil
}

// AggregateOverflowDecryptionShares combines all parties' OverflowDecryptionShares into a
// single combined share for use in DecryptThresholdOverflow.
//
// All input shares must have the same Betas shape. Returns an error if shares is empty.
func AggregateOverflowDecryptionShares(ctx MHEContext, shares []OverflowDecryptionShare) (OverflowDecryptionShare, error) {
	if len(shares) == 0 {
		return OverflowDecryptionShare{}, errors.New("AggregateOverflowDecryptionShares: shares must not be empty")
	}

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return OverflowDecryptionShare{}, fmt.Errorf("AggregateOverflowDecryptionShares: NewKeySwitchProtocol: %w", err)
	}

	// Fresh accumulator for Alpha (avoids mutating input ring.Poly slices).
	combinedAlpha := LabeledDecryptionShare{Value: proto.AllocateShare(shares[0].Alpha.Value.Level())}
	for _, s := range shares {
		if err := proto.AggregateShares(combinedAlpha.Value, s.Alpha.Value, &combinedAlpha.Value); err != nil {
			return OverflowDecryptionShare{}, fmt.Errorf("AggregateOverflowDecryptionShares: alpha: %w", err)
		}
	}

	// Fresh accumulators for each Betas[i][j].
	combinedBetas := make([][]LabeledDecryptionShare, len(shares[0].Betas))
	for i, row := range shares[0].Betas {
		combinedBetas[i] = make([]LabeledDecryptionShare, len(row))
		for j := range row {
			combinedBetas[i][j] = LabeledDecryptionShare{Value: proto.AllocateShare(shares[0].Betas[i][j].Value.Level())}
			for _, s := range shares {
				if err := proto.AggregateShares(combinedBetas[i][j].Value, s.Betas[i][j].Value, &combinedBetas[i][j].Value); err != nil {
					return OverflowDecryptionShare{}, fmt.Errorf("AggregateOverflowDecryptionShares: beta[%d][%d]: %w", i, j, err)
				}
			}
		}
	}

	return OverflowDecryptionShare{Alpha: combinedAlpha, Betas: combinedBetas}, nil
}

// DecryptThresholdOverflow recovers the plaintext from clct using the combined
// OverflowDecryptionShare produced by AggregateOverflowDecryptionShares.
// No individual or collective secret key is required at this step.
//
// Applies CKS to each ciphertext component and reconstructs:
//
//	m[k] = (plainAlpha[k] + Σᵢ ∏ⱼ plainBeta_ij[k]) mod T
//
// Returns an error if clct contains no A component.
func DecryptThresholdOverflow(ctx MHEContext, combined OverflowDecryptionShare, clct CiphertextLabeledciphertext) ([]uint64, error) {
	if clct.elementsA == nil {
		return nil, errors.New("DecryptThresholdOverflow: clct contains no A component")
	}

	proto, err := multiparty.NewKeySwitchProtocol(ctx.Params, smudgingNoise())
	if err != nil {
		return nil, fmt.Errorf("DecryptThresholdOverflow: NewKeySwitchProtocol: %w", err)
	}

	encoder := bgv.NewEncoder(ctx.Params.Parameters)
	zeroSK := rlwe.NewSecretKey(ctx.Params)
	dec := rlwe.NewDecryptor(ctx.Params, zeroSK)

	switchAndDecode := func(ct *rlwe.Ciphertext, share LabeledDecryptionShare) ([]uint64, error) {
		ctSwitched := rlwe.NewCiphertext(ctx.Params, 1, ct.Level())
		proto.KeySwitch(ct, share.Value, ctSwitched)
		out := make([]uint64, ctx.Params.MaxSlots())
		return out, encoder.Decode(dec.DecryptNew(ctSwitched), out)
	}

	α := (*rlwe.Ciphertext)(clct.elementsA)
	plainAlpha, err := switchAndDecode(α, combined.Alpha)
	if err != nil {
		return nil, fmt.Errorf("DecryptThresholdOverflow: decode α: %w", err)
	}

	T := ctx.Params.PlaintextModulus()
	sumBetas := make([]uint64, ctx.Params.MaxSlots())
	for i, row := range clct.elementsB {
		multBetas := make([]uint64, ctx.Params.MaxSlots())
		for k := range multBetas {
			multBetas[k] = 1
		}
		for j := range row {
			plainBeta, err := switchAndDecode(&clct.elementsB[i][j], combined.Betas[i][j])
			if err != nil {
				return nil, fmt.Errorf("DecryptThresholdOverflow: decode β[%d][%d]: %w", i, j, err)
			}
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
