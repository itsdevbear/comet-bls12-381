//go:build ((linux && amd64) || (linux && arm64) || (darwin && amd64) || (darwin && arm64) || (windows && amd64)) && !blst_disabled

package blst

import (
	"errors"
	"fmt"

	"github.com/itsdevbear/comet-bls12-381/bls"
	"github.com/itsdevbear/comet-bls12-381/bls/params"
)

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

// Signature used in the BLS signature scheme.
type Signature struct {
	s *blstSignature
}

// Marshal a signature into a LittleEndian byte slice.
func (s *Signature) Marshal() []byte {
	return s.s.Compress()
}

// Copy returns a full deep copy of a signature.
func (s *Signature) Copy() bls.Signature {
	sign := *s.s
	return &Signature{s: &sign}
}

// Verify a signature using a public key and message.
func (s *Signature) Verify(pubKey bls.PubKey, msg []byte) bool {
	// Signature and PKs are assumed to have been validated upon decompression!
	return s.s.Verify(false, pubKey.(*PublicKey).p, false, msg, dst)
}

// VerifySignaturePubkeyBytes checks if a given signature is valid for a
// message and public key.
// It returns true if the signature is valid, otherwise it panics if an error
// occurs during the verification process.
func VerifySignaturePubkeyBytes(
	pubKey []byte,
	msg []byte,
	signature []byte,
) bool {
	pubkey, err := PublicKeyFromBytes(pubKey[:])
	if err != nil {
		return false
	}
	sig, err := SignatureFromBytes(signature[:])
	if err != nil {
		return false
	}

	return sig.Verify(pubkey, msg)
}

// VerifySignature verifies a single signature using public key and message.
func VerifySignature(sig []byte, msg [32]byte, pubKey bls.PubKey) (bool, error) {
	rSig, err := SignatureFromBytes(sig)
	if err != nil {
		return false, err
	}
	return rSig.Verify(pubKey, msg[:]), nil
}

// signatureFromBytesNoValidation creates a BLS signature from a LittleEndian
// byte slice. It does not validate that the signature is in the BLS group
func signatureFromBytesNoValidation(sig []byte) (*blstSignature, error) {
	if len(sig) != params.BLSSignatureLength {
		return nil, fmt.Errorf("signature must be %d bytes", params.BLSSignatureLength)
	}
	signature := new(blstSignature).Uncompress(sig)
	if signature == nil {
		return nil, errors.New("could not unmarshal bytes into signature")
	}
	return signature, nil
}

// SignatureFromBytesNoValidation creates a BLS signature from a LittleEndian
// byte slice. It does not validate that the signature is in the BLS group
func SignatureFromBytesNoValidation(sig []byte) (bls.Signature, error) {
	signature, err := signatureFromBytesNoValidation(sig)
	if err != nil {
		return nil, fmt.Errorf("could not create signature from byte slice: %w", err)
	}
	return &Signature{s: signature}, nil
}

// SignatureFromBytes creates a BLS signature from a LittleEndian byte slice.
func SignatureFromBytes(sig []byte) (bls.Signature, error) {
	signature, err := signatureFromBytesNoValidation(sig)
	if err != nil {
		return nil, fmt.Errorf("could not create signature from byte slice: %w", err)
	}
	// Group check signature. Do not check for infinity since an aggregated signature
	// could be infinite.
	if !signature.SigValidate(false) {
		return nil, errors.New("signature not in group")
	}
	return &Signature{s: signature}, nil
}
