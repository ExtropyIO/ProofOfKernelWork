package core

import (
	"github.com/ethereum/go-ethereum/core/types"
	"testing"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
	"fmt"
	"strings"
)

const (
	nonceValue1 uint64 = uint64(0xa13a5a8c8f2bb1c4)

	extraValue1 string = "test block"
)

func TestCanAuthoriseBlock(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock(false)
	err := AuthoriseBlock(block, priv)
	if err != nil {
		t.Errorf("Expected that authorising the block would have been successful")
		return
	}

	eh := block.ExtendedHeader()
	if eh == nil {
		t.Errorf("Expected that the authorised block would now have an extended header")
		return
	}

	if len(eh.Signature) == 0 {
		t.Errorf("Expected that the signature, of an authorised block, would not be blank")
		return
	}
}

func TestCanVerifyAuthenticBlock(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock(false)
	addSignatureToBlock(block, priv, t)
	valid, err := VerifyBlockAuthenticity(block, &priv.PublicKey)
	if err != nil {
		t.Errorf("Expected that the signature would have validated correctly: %s", err)
		return
	}
	if ! valid {
		t.Errorf("Expected that the signature to be valid: %s", block.ExtendedHeader().Signature)
		return
	}
}

// Check to make sure that even if we have a valid signature, that if it came from a private key that we did not expect
// that the block is not considered valid
func TestDoesNotVerifyValidSignatureButNotAuthenticBlock(t *testing.T) {
	priv1 := getNewKeyPair(t)
	priv2 := getNewKeyPair(t)
	block := getBlock(false)
	addSignatureToBlock(block, priv1, t)
	valid, err := VerifyBlockAuthenticity(block, &priv2.PublicKey)
	if err != nil {
		t.Errorf("Expected that the signature would have validated correctly: %s", err)
		return
	}
	if valid {
		t.Errorf("Expected that the valid signature from an unexpected private key would not be considered authentic: %s", block.ExtendedHeader().Signature)
		return
	}
}

func TestBlockWithNoExtendedHeaderIsNotAuthenticBlock(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock(false)
	_, err := VerifyBlockAuthenticity(block, &priv.PublicKey)
	if err == nil {
		t.Errorf("Expected that an error would have been thrown due to the block not being determined as valid")
		return
	} else {
		s := err.Error()
		expectedError := "The Block, it's header and the extended header should not be nil"
		if ! strings.Contains(s, expectedError) {
			t.Errorf("Expected that an error would have been thrown with the message: %s", expectedError)
		}
	}
}

func TestBlockWithNoSignatureIsNotAuthenticBlock(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock(false)
	block.SetExtendedHeader([]byte(nil))
	_, err := VerifyBlockAuthenticity(block, &priv.PublicKey)
	if err == nil {
		t.Errorf("Expected that an error would be thrown due to it not being possible to validate a nil signature")
		return
	} else {
		s := err.Error()
		expectedError := "recovery failed"
		if ! strings.Contains(s, expectedError) {
			t.Errorf("Expected that an error would have been thrown with the message: %s", expectedError)
		}
	}
}

func TestBlockWithBlankSignatureIsNotAuthenticBlock(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock(false)
	block.SetExtendedHeader([]byte("                                "))
	_, err := VerifyBlockAuthenticity(block, &priv.PublicKey)
	if err == nil {
		t.Errorf("Expected that an error would be thrown due to it not being possible to validate a nil signature")
		return
	} else {
		s := err.Error()
		expectedError := "recovery failed"
		if ! strings.Contains(s, expectedError) {
			t.Errorf("Expected that an error would have been thrown with the message: %s", expectedError)
		}
	}
}

func TestCanAuthoriseAndVerifyABlock(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock(false)

	err := AuthoriseBlock(block, priv)
	if err != nil {
		t.Errorf("Expected that authorising the block would have been successful")
		return
	}

	eh := block.ExtendedHeader()
	if eh == nil {
		t.Errorf("Expected that the authorised block would now have an extended header")
		return
	}

	if len(eh.Signature) == 0 {
		t.Errorf("Expected that the signature, of an authorised block, would not be blank")
		return
	}

	valid, verr := VerifyBlockAuthenticity(block, &priv.PublicKey)
	if verr != nil {
		t.Errorf("Expected that the signature would have validated correctly: %s", verr)
		return
	}
	if ! valid {
		t.Errorf("Expected that the signature to be valid: %s", block.ExtendedHeader().Signature)
		return
	}
}

// A test to make sure that when a block has been authorised by a private key that it is not possible to mistake the
// paired public key for a different one
func TestAuthorisedBlockIsNotVerifiedAgainstADifferentPublicKey(t *testing.T) {
	priv1 := getNewKeyPair(t)
	priv2 := getNewKeyPair(t)
	block := getBlock(false)

	err := AuthoriseBlock(block, priv1)
	if err != nil {
		t.Errorf("Expected that authorising the block would have been successful")
		return
	}

	eh := block.ExtendedHeader()
	if eh == nil {
		t.Errorf("Expected that the authorised block would now have an extended header")
		return
	}

	if len(eh.Signature) == 0 {
		t.Errorf("Expected that the signature, of an authorised block, would not be blank")
		return
	}

	valid, verr := VerifyBlockAuthenticity(block, &priv2.PublicKey)
	if verr != nil {
		t.Errorf("Expected that the signature would have validated correctly: %s", verr)
		return
	}
	if valid {
		t.Errorf("Expected that the valid signature from an unexpected private key would not be considered authentic: %s", block.ExtendedHeader().Signature)
		return
	}
}

func TestAuthorisationWhenNoNonce(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock(true)

	if block.Nonce() != 0 {
		t.Errorf("Expected that the Nonce would be 0")
		return
	}
	fmt.Printf("%v", block)

	err := AuthoriseBlock(block, priv)
	if err != nil {
		t.Errorf("Expected that authorising the block would have been successful")
		return
	}
}

// Private Functions

func getNewKeyPair(t *testing.T) *ecdsa.PrivateKey {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Errorf("Unable to generate the private / public key pair: %s", err)
		return nil
	}
	return priv
}

func addSignatureToBlock(block *types.Block, privKey *ecdsa.PrivateKey, t *testing.T) {
	encodedNonce := block.Header().Nonce
	hash := crypto.Keccak256(encodedNonce[:])
	sig, err := crypto.Sign(hash, privKey)

	if err != nil {
		t.Errorf("Unable to sign the message: %s", err)
	}
	block.SetExtendedHeader(sig)
}

func getBlock(blankNonce bool) *types.Block {

	if blankNonce {
		return getVanillaBlockNoNonce()
	} else {
		// Create a test block to move around the database and make sure it's really new
		return getVanillaBlock()
	}


}

func getVanillaBlock() *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		Extra:       []byte(extraValue1),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Nonce:		 types.EncodeNonce(nonceValue1),
	})
}

func getVanillaBlockNoNonce() *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		Extra:       []byte(extraValue1),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
	})
}
