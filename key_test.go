package bls_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bls "github.com/itsdevbear/comet-bls12-381"
)

func TestSignAndValidateBLS12381(t *testing.T) {
	privKey, err := bls.GenPrivKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey()

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	require.NoError(t, err)
	sig, err := privKey.Sign(msg)
	require.NoError(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifySignature(msg, sig))

	// Mutate the signature, just one bit.
	// TODO: Replace this with a much better fuzzer, tendermint/ed25519/issues/10
	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.VerifySignature(msg, sig))

	msg = make([]byte, 192)
	_, err = rand.Read(msg)
	require.NoError(t, err)
	sig, err = privKey.Sign(msg)
	require.NoError(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifySignature(msg, sig))
}
