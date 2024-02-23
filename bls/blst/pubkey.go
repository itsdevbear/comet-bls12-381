//go:build ((linux && amd64) || (linux && arm64) || (darwin && amd64) || (darwin && arm64) || (windows && amd64)) && !blst_disabled

package blst

import (
	"errors"
	"fmt"

	bls "github.com/berachain/comet-bls12-381/bls"
	"github.com/berachain/comet-bls12-381/bls/params"
)

// PublicKey used in the BLS signature scheme.
type PublicKey struct {
	p *blstPublicKey
}

// Marshal a public key into a LittleEndian byte slice.
func (p *PublicKey) Marshal() []byte {
	return p.p.Compress()
}

// Copy the public key to a new pointer reference.
func (p *PublicKey) Copy() bls.PubKey {
	np := *p.p
	return &PublicKey{p: &np}
}

// Equals checks if the provided public key is equal to
// the current one.
func (p *PublicKey) Equals(p2 bls.PubKey) bool {
	return p.p.Equals(p2.(*PublicKey).p)
}

// PublicKeyFromBytes creates a BLS public key from a  BigEndian byte slice.
func PublicKeyFromBytes(pubKey []byte) (bls.PubKey, error) {
	return publicKeyFromBytes(pubKey, true)
}

func publicKeyFromBytes(pubKey []byte, cacheCopy bool) (bls.PubKey, error) {
	if len(pubKey) != params.BLSPubkeyLength { //TODO: make this a parameter
		return nil, fmt.Errorf("public key must be %d bytes", params.BLSPubkeyLength)
	}

	// Subgroup check NOT done when decompressing pubkey.
	p := new(blstPublicKey).Uncompress(pubKey)
	if p == nil {
		return nil, errors.New("could not unmarshal bytes into public key")
	}
	// Subgroup and infinity check
	if !p.KeyValidate() {
		// NOTE: the error is not quite accurate since it includes group check
		return nil, errors.New("publickey is infinite")
	}

	return &PublicKey{p: p}, nil
}
