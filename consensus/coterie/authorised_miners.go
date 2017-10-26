package coterie

import (
	"crypto/ecdsa"
	"github.com/pkg/errors"
	"github.com/ethereum/go-ethereum/consensus/coterie/contract"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
)

// generate the below by running <code>govendor generate +l</code> in the root of the project.
//go:generate abigen --sol contract/authorised_miners_whitelist.sol --pkg contract --out contract/authorised_miners_whitelist.go

var (
	errorMissingWhitelistContract = errors.New("The expected AuthorisedMinersWhitelist Smart Contract is not present")
	callOpts = bind.CallOpts{
		Pending: false,
	}
	// The address that the whitelist smart contract is deployed to in the genesis block
	contractAddress = common.HexToAddress("0x0000000000000000000000000000000000000042")
)

type AuthorisedMinersWhitelist struct {
	whitelistContractInstance *contract.AuthorisedMinersWhitelist
}

func NewAuthorisedMinersWhitelist(contractBackend bind.ContractBackend) (*AuthorisedMinersWhitelist, error) {
	whitelist, err := contract.NewAuthorisedMinersWhitelist(contractAddress, contractBackend)
	if err != nil {
		return nil, err
	}
	return &AuthorisedMinersWhitelist{
		whitelist,
	}, nil
}

// 0x9e5e939fb0a23529934c061d6ecf4c93e7893d4e
// 0xea30250dd7263a4783c66463c236a2153d6b88b4
// 0x46dfb921f8f7edbbd8100458b7c1beefeabf6e15
// 0x6c80e492308f051eba48d03bcc04625682ae3e07
// 0x30ff130a7d11ef9d1efbdf19d5309556acd129cf

func (self *AuthorisedMinersWhitelist) IsMinerInWhitelist(minerAddress common.Address) (bool, error) {
	if self.whitelistContractInstance == nil {
		return false, errorMissingWhitelistContract
	}

	if len(minerAddress) == 0 {
		return false, nil
	}

	if auth, err := self.whitelistContractInstance.IsAuthorisedMiner(&callOpts, minerAddress); err != nil {
		return false, err
	} else {
		return auth, nil
	}
}

func (self *AuthorisedMinersWhitelist) AddMinerToWhitelist(minerAddress common.Address, msgSender *ecdsa.PrivateKey) (*types.Transaction, error) {
	if self.whitelistContractInstance == nil {
		return nil, errorMissingWhitelistContract
	}

	if msgSender == nil {
		return nil, errors.New("A private key to authorise adding the miner must be provided")
	}

	if len(minerAddress) == 0 {
		return nil, errors.New("Invalid address to add to the whitelist")
	}

	return self.whitelistContractInstance.AuthoriseMiner(bind.NewKeyedTransactor(msgSender), minerAddress)
}
