package authentication

import (
	"crypto/ecdsa"
	"github.com/pkg/errors"
	"github.com/ethereum/go-ethereum/crypto/authentication/contract"
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
	whitelistContractInstance *contract.AuthorisedMinersWhitelist
)

// 0xea30250dd7263a4783c66463c236a2153d6b88b4
// 0x46dfb921f8f7edbbd8100458b7c1beefeabf6e15
// 0x6c80e492308f051eba48d03bcc04625682ae3e07
// 0x30ff130a7d11ef9d1efbdf19d5309556acd129cf

func IsMinerInWhitelist(minerAddress common.Address) (bool, error) {
	if whitelistContractInstance == nil {
		return false, errorMissingWhitelistContract
	}

	if len(minerAddress) == 0 {
		return false, nil
	}

	if auth, err := whitelistContractInstance.IsAuthorisedMiner(&callOpts, minerAddress); err != nil {
		return false, err
	} else {
		return auth, nil
	}
}

func AddMinerToWhitelist(minerAddress common.Address, msgSender *ecdsa.PrivateKey) (*types.Transaction, error) {
	if whitelistContractInstance == nil {
		return nil, errorMissingWhitelistContract
	}

	if msgSender == nil {
		return nil, errors.New("A private key to authorise adding the miner must be provided")
	}

	if len(minerAddress) == 0 {
		return nil, errors.New("Invalid address to add to the whitelist")
	}

	return whitelistContractInstance.AuthoriseMiner(bind.NewKeyedTransactor(msgSender), minerAddress)
}