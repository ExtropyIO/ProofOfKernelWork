package contract

import (
	"testing"
	"math/big"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/common"
)

var (
	key, _              = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr                = crypto.PubkeyToAddress(key.PublicKey)
	whitelistedAddress1	= common.StringToAddress("0xea30250dd7263a4783c66463c236a2153d6b88b4")
	blockchain          *backends.SimulatedBackend
)

func TestAuthorisedMinersWhitelist_canWhitelistAddress(t *testing.T) {
	// Setup
	whitelistContract := getDeployedContractInstance(t)

	// Check that the address isn't already whitelisted
	callOpts := getCallOptions(&whitelistedAddress1)

	auth, err := whitelistContract.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if auth {
		t.Fatal("expected that the miner would not be whitelisted")
	}

	if _, err := whitelistContract.AuthoriseMiner(getTransactionOptions(), whitelistedAddress1); err != nil {
		t.Fatalf("expected no error whilst authorising the miner that wasn't whitelisted, got %v", err)
	}

	mineNewBlock()

	auth, err = whitelistContract.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if ! auth {
		t.Fatal("expected that the miner would be whitelisted")
	}
}

func TestAuthorisedMinersWhitelist_canRemoveAddressFromWhitelist(t *testing.T) {
	// Setup
	whitelistContract := getDeployedContractInstance(t)

	callOpts := getCallOptions(&whitelistedAddress1)
	txOpts := getTransactionOptions()

	// Check that the address isn't already whitelisted
	auth, err := whitelistContract.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if auth {
		t.Fatal("expected that the miner would not be whitelisted")
	}

	if _, err := whitelistContract.AuthoriseMiner(txOpts, whitelistedAddress1); err != nil {
		t.Fatalf("expected no error whilst authorising the miner that wasn't whitelisted, got %v", err)
	}

	mineNewBlock()

	auth, err = whitelistContract.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if ! auth {
		t.Fatal("expected that the miner would be whitelisted")
	}

	if _, err = whitelistContract.RemoveMinersAuthorisation(txOpts, whitelistedAddress1); err != nil {
		t.Fatalf("expected no error whilst removing the miner that was whitelisted, got %v", err)
	}

	mineNewBlock()

	auth, err = whitelistContract.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if auth {
		t.Fatal("expected that the miner would not be whitelisted")
	}
}

// The generated code provides a 'Caller' object for calling the constant / view functions and a 'Transactor' object
// for interacting with the functions that modify the blockchain - check if these behave the same as the functions
// that are native to the contract instance object
func TestAuthorisedMinersWhitelist_callerAndTransactorBehaveAsExpected(t *testing.T) {
	// Setup
	whitelistContract := getDeployedContractInstance(t)

	callOpts := getCallOptions(&whitelistedAddress1)
	txOpts := getTransactionOptions()

	// Check that the address isn't already whitelisted
	auth, err := whitelistContract.AuthorisedMinersWhitelistCaller.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if auth {
		t.Fatal("expected that the miner would not be whitelisted")
	}

	if _, err := whitelistContract.AuthorisedMinersWhitelistTransactor.AuthoriseMiner(txOpts, whitelistedAddress1); err != nil {
		t.Fatalf("expected no error whilst authorising the miner that wasn't whitelisted, got %v", err)
	}

	mineNewBlock()

	auth, err = whitelistContract.AuthorisedMinersWhitelistCaller.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if ! auth {
		t.Fatal("expected that the miner would be whitelisted")
	}

	if _, err = whitelistContract.AuthorisedMinersWhitelistTransactor.RemoveMinersAuthorisation(txOpts, whitelistedAddress1); err != nil {
		t.Fatalf("expected no error whilst removing the miner that was whitelisted, got %v", err)
	}

	mineNewBlock()

	auth, err = whitelistContract.AuthorisedMinersWhitelistCaller.IsAuthorisedMiner(callOpts, whitelistedAddress1)
	if err != nil {
		t.Fatalf("expected no error whilst checking that the miner wasn't whitelisted, got %v", err)
	}

	if auth {
		t.Fatal("expected that the miner would not be whitelisted")
	}
}

func getTransactionOptions() *bind.TransactOpts {
	transactOpts := bind.NewKeyedTransactor(key)
	// Workaround for bug estimating gas
	transactOpts.GasLimit = big.NewInt(1000000)
	return transactOpts
}

func getCallOptions(from *common.Address) *bind.CallOpts {
	return &bind.CallOpts{
		Pending:false,
		From: *from,
	}
}

func getBlockchainBackend() *backends.SimulatedBackend {
	return backends.NewSimulatedBackend(core.GenesisAlloc{addr: {Balance: big.NewInt(1000000000)}})
}

func getDeployedContractInstance(t *testing.T) *AuthorisedMinersWhitelist {
	// Setup the simulated Blockchain
	blockchain = getBlockchainBackend()

	// Deploy the contract to the simulated
	_, _, theContractInstance, err := DeployAuthorisedMinersWhitelist(getTransactionOptions(), blockchain)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	mineNewBlock()

	return theContractInstance
}

func mineNewBlock() {
	blockchain.Commit()
}
