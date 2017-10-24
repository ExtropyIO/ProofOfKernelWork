package authentication

import (
	"github.com/pkg/errors"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

var (
	ErrInvalidAuth       = errors.New("invalid miner authentication signature in the header")
)


// Use the provided private key to sign a block; providing the authorisation that this block was produced by one of the
// authorised nodes and is valid.
func AuthenticateBlock(header *types.Header, am *accounts.Manager, coinbase *common.Address, password string) error {
	if header == nil || am == nil || coinbase == nil  {
		return errors.New("Unable to authenticate a block without the header, account manager and coinbase all not being nil.")
	}

	localKeystore := fetchKeystore(am)
	if localKeystore == nil {
		return errors.New("Unable to retrieve the keystore from the Account Manager.")
	}

	plaintext := retrievePlaintext(header)
	if plaintext == nil || len(plaintext) == 0 {
		return errors.New("Unable to authenticate a block with a missing parent hash.")
	}

	sig, err := localKeystore.SignHashWithPassphrase(accounts.Account{Address: *coinbase} , password, plaintext)

	if err != nil {
		return err
	}

	header.SetExtendedHeader(sig)
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
func VerifyBlockAuthenticity(authenticatedMinersWhitelist *AuthenticatedMinersWhitelist, header *types.Header) (bool, error) {
	log.Debug("Verifying the authenticity of the block's header: ", "header", header.String())

	blockAuthor, err := RetrieveBlockAuthor(header)
	if(err != nil) {
		return false, err
	}

	// Retrieve the address from the public key and check to see if this is in the whitelist
	return authenticatedMinersWhitelist.IsMinerInWhitelist(blockAuthor)
}

func retrievePlaintext(header *types.Header) []byte {
	return header.ParentHash[:]
}

func RetrieveBlockAuthor(header *types.Header) (common.Address, error) {
	if headerErr := validateHeader(header); headerErr != nil {
		return common.Address{}, headerErr
	}

	plaintext := retrievePlaintext(header)
	if plaintext == nil || len(plaintext) == 0 {
		return common.Address{}, errors.New("Unable to verify a block with a missing parent hash.")
	}
	// Extract from the signature the public key that is paired with the private key; that was used to sign the block
	publicKey, err := crypto.SigToPub(plaintext, header.ExtendedHeader[:])
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*publicKey), nil
}

func validateHeader(header *types.Header) error {
	if header == nil || len(header.ExtendedHeader) == 0 {
		return errors.New("The Block is not correctly formatted: The Block, it's header and the extended header should not be nil")
	} else {
		return nil
	}
}