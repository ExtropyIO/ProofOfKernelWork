package authentication

import (
	"testing"
	"github.com/ethereum/go-ethereum/accounts"
	"io/ioutil"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"os"
	"github.com/ethereum/go-ethereum/core/types"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)


const (
	NONCE_VALUE_1    uint64 = uint64(0xa13a5a8c8f2bb1c4)
	ACCOUNT_PASSWORD string = ""
	EXTRA_VALUE_1    string = "test block"
)

func TestCanAuthenticateBlock(t *testing.T) {
	dir, ks := createKeystore(t)
	defer os.RemoveAll(dir)

	account1 := createNewAccount(t, ks)

	am := createAccountManager(ks)
	block := getBlock(false)

	if block.ExtendedHeader() != nil {
		t.Error("Expected that the block would not have been signed yet.")
	}

	err := AuthenticateBlock(block , am, &account1.Address, ACCOUNT_PASSWORD)
	if err != nil {
		t.Errorf("Unable to add the authentication to the block: %v", err)
	}

	if block.ExtendedHeader() == nil {
		t.Error("Expected that the block would have a signature.")
	}
}

func TestCanAuthoriseAndVerifyABlock(t *testing.T) {
	dir, ks := createKeystore(t)
	defer os.RemoveAll(dir)

	account1 := createNewAccount(t, ks)

	am := createAccountManager(ks)
	block := getBlock(false)

	if block.ExtendedHeader() != nil {
		t.Error("Expected that the block would not have been signed yet.")
	}

	err := AuthenticateBlock(block , am, &account1.Address, ACCOUNT_PASSWORD)
	if err != nil {
		t.Errorf("Unable to add the authentication to the block: %v", err)
	}

	if block.ExtendedHeader() == nil {
		t.Error("Expected that the block would have a signature.")
	}

	key, err := getKey(account1.Address, dir)
	if err != nil {
		t.Errorf("Unable to retrieve the key from the keystore: %v", err)
	}

	pubKey := key.PrivateKey.PublicKey

	// Add the miner / signer to the whitelist
	addMinerToWhitelist(&pubKey)

	valid, err := VerifyBlockAuthenticity(block)
	if err != nil {
		t.Errorf("Unable to validate the signature on the block: %v", err)
	}

	if !valid {
		t.Error("Expected that the block would have a *valid* signature.")
	}
}



// Functions used for setting up the test

func createKeystore(t *testing.T) (dir string, ks *keystore.KeyStore) {
	// Create a file in the current directory
	d, err := ioutil.TempDir("", "geth-keystore-test")
	if err != nil {
		t.Fatal(err)
	}
	return d, keystore.NewPlaintextKeyStore(d)
}

func createAccountManager(ks *keystore.KeyStore) (*accounts.Manager) {
	backends := []accounts.Backend{
		ks,
	}
	return accounts.NewManager(backends...)
}

func createNewAccount(t *testing.T, ks *keystore.KeyStore) (*accounts.Account) {
	acc, err := ks.NewAccount(ACCOUNT_PASSWORD)
	if err != nil {
		t.Errorf("Unable to create the account: %v", err)
	}
	return &acc
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
		Extra:       []byte(EXTRA_VALUE_1),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Nonce:		 types.EncodeNonce(NONCE_VALUE_1),
	})
}

func getVanillaBlockNoNonce() *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		Extra:       []byte(EXTRA_VALUE_1),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
	})
}

// Duplicate of the code in keystore_plain and keystore_passphrase because there seemed to be no other way to
// retrieve the key given a keystore
func getKey(addr common.Address, filename string) (*keystore.Key, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	key := new(keystore.Key)
	if err := json.NewDecoder(fd).Decode(key); err != nil {
		return nil, err
	}
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have address %x, want %x", key.Address, addr)
	}
	return key, nil
}
