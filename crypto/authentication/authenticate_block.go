package authentication

import (
	"github.com/pkg/errors"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
)

// Use the provided private key to sign a block; providing the authorisation that this block was produced by one of the
// authorised nodes and is valid.
func AuthenticateBlock(block *types.Block, am *accounts.Manager, coinbase *common.Address, password string) error {
	if block == nil || block.Header() == nil || am == nil || coinbase == nil  {
	   return errors.New("Unable to authenticate a block without the block account manager and coinbase all not being nil.")
    }

	localKeystore := fetchKeystore(am)
	if localKeystore == nil {
		return errors.New("Unable to retrieve the keystore from the Account Manager.")
	}

	plaintext := retrievePlaintext(block)
	if plaintext == nil || len(plaintext) == 0 {
		return errors.New("Unable to authenticate a block with a missing parent hash.")
	}

	sig, err := localKeystore.SignHashWithPassphrase(accounts.Account{Address: *coinbase} , password, plaintext)

	if err != nil {
		return err
	}

	block.SetExtendedHeader(sig)
	return nil
}

// fetchKeystore retrieves the encrypted keystore from the account manager.
func fetchKeystore(am *accounts.Manager) *keystore.KeyStore {
	return am.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
}

// Useful SE answer: https://ethereum.stackexchange.com/questions/13778/get-public-key-of-any-ethereum-account/13892

// Verify that the Block must have originated from the holder of the expected private key.
// Given the public key that is paired with the expected, unknown, private key check that Block must have been signed by
// the expected private key.
func VerifyBlockAuthenticity(block *types.Block) (bool, error) {
	if block == nil || block.Header() == nil || block.ExtendedHeader() == nil {
		return false, errors.New("The Block is not correctly formatted: The Block, it's header and the extended header should not be nil")
	}

	plaintext := retrievePlaintext(block)
	if plaintext == nil || len(plaintext) == 0 {
		return false, errors.New("Unable to verify a block with a missing parent hash.")
	}

	// Extract from the signature the public key that is paired with the private key; that was used to sign the block
	publicKey, err := crypto.SigToPub(retrievePlaintext(block), *block.ExtendedHeader())
	if err != nil {
		return false, err
	}

	return IsMinerInWhitelist(publicKey), nil
}

func retrievePlaintext(block *types.Block) []byte {
	return block.Header().ParentHash[:]
}
