package core

import (
	"github.com/ethereum/go-ethereum/core/types"
	"testing"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	nonceValue1 uint64 = uint64(0xa13a5a8c8f2bb1c4)

	extraValue1 string = "test block"
)

// TODO test what happens when the 'message' is nil


func TestCanVerifyAuthenticBlock(t *testing.T) {
	priv := getNewKeyPair(t)
	block := getBlock()
	addSignatureToBlock(block, priv)
	fmt.Print("done")
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

func addSignatureToBlock(block *types.Block, privKey *ecdsa.PrivateKey) {
	encodedNonce := block.Header().Nonce
	//var b []byte = []byte("test")
	if sig, err := crypto.Sign(encodedNonce[:], privKey); err == nil {
		fmt.Print(sig)
		*block.ExtendedHeader() = types.ExtendedHeader{ }
	}
}

func getBlock() *types.Block {

	// Create a test block to move around the database and make sure it's really new
	return getVanillaBlock()
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
