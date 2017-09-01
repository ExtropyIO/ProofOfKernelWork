//

package core

import (
	"crypto/ecdsa"
	"github.com/pkg/errors"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Verify that the Block must have originated from the holder of the expected private key.
// Given the public key that is paired with the expected, unknown, private key check that Block must have been signed by
// the expected private key.
func VerifyBlockAuthenticity(block *types.Block, publicKey *ecdsa.PublicKey) (bool, error) {
	if block == nil || block.Header() == nil || block.ExtendedHeader() == nil || block.ExtendedHeader().Signature == nil {
		return false, errors.New("The Block is not correctly formatted: The Block, it's header and the extended header should not be nil")
	}

	// Extract from the signature the public key that is paired with the private key; that was used to sign the block
	pub, err := crypto.SigToPub(createHash(block.Header().Nonce[:]), block.ExtendedHeader().Signature[:])
	if err != nil {
		return false, err
	}
	return matchesExpectedPublicKey(pub, publicKey)
}

// Create a hash of the 'message' - to ensure that it is the correct length for the ECDSA algorithm
func createHash(msg []byte) []byte {
	return crypto.Keccak256(msg)
}

//
func matchesExpectedPublicKey(publicKey *ecdsa.PublicKey, expectedPublicKey *ecdsa.PublicKey) (matches bool, err error) {
	if publicKey == nil || expectedPublicKey == nil {
		return false, errors.New("Neither of the public keys to compare should be nil")
	}

	// Verify that both of the private keys are on the same Elliptic curve
	if publicKey.Curve != expectedPublicKey.Curve {
		return false, nil
	}

	// Check that the X and Y coordinates of the two public keys match exactly
	return expectedPublicKey.Y.Cmp(publicKey.Y) != 0 || expectedPublicKey.X.Cmp(publicKey.X) != 0, nil
}
