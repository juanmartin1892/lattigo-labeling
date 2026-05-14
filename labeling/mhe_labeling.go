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
