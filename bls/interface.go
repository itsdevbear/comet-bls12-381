package bls

type PubKey interface {
	Marshal() []byte
	Copy() PubKey
	Equals(p2 PubKey) bool
}

// Signature represents a BLS signature.
type Signature interface {
	Verify(pubKey PubKey, msg []byte) bool
	Marshal() []byte
	Copy() Signature
}

// SecretKey represents a BLS secret or private key.
type SecretKey interface {
	PublicKey() PubKey
	Sign(msg []byte) Signature
	Marshal() []byte
}
