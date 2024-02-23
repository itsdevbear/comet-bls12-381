package params

type Config struct {
	BLSSecretKeyLength int // BLSSecretKeyLength defines the expected length of BLS secret keys in bytes.
	BLSPubkeyLength    int // BLSPubkeyLength defines the expected length of BLS public keys in bytes.
}

const (
	BLSSignatureLength = 96 // BLSSignatureLength defines the byte length of a BLSSignature.
	BLSPubkeyLength    = 48 // BLSPubkeyLength defines the byte length of a BLSSignature.
)
