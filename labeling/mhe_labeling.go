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
