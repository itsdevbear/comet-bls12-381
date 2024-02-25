package bls_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bls "github.com/berachain/comet-bls12-381"
	"github.com/cometbft/cometbft/crypto"
)

func TestSignAndValidateEd25519(t *testing.T) {
	privKey, err := bls.GenPrivKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey()

	// BLST does not support messages longer than 32 bytes
	msg := crypto.CRandBytes(32)
	fmt.Println(len(msg))
	sig, err := privKey.Sign(msg)
	require.NoError(t, err)

	// Test the signature
	assert.True(t, pubKey.VerifySignature(msg, sig))

	// Mutate the signature, just one bit.
	// TODO: Replace this with a much better fuzzer, tendermint/ed25519/issues/10
	sig[7] ^= byte(0x01)

	assert.False(t, pubKey.VerifySignature(msg, sig))
}
