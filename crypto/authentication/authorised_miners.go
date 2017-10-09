package authentication

import (
	"crypto/ecdsa"
	"github.com/pkg/errors"
	"github.com/ethereum/go-ethereum/log"
)

// generate the below by running <code>govendor generate +l</code> in the root of the project.
//go:generate abigen --sol contract/authorised_miners_whitelist.sol --pkg contract --out contract/authorised_miners_whitelist.go

type AuthorisedMiner *ecdsa.PublicKey
type Whitelist []AuthorisedMiner

var cachedWhitelist Whitelist

// 0xea30250dd7263a4783c66463c236a2153d6b88b4
// 0x46dfb921f8f7edbbd8100458b7c1beefeabf6e15
// 0x6c80e492308f051eba48d03bcc04625682ae3e07
// 0x30ff130a7d11ef9d1efbdf19d5309556acd129cf


func RetrieveAuthorisedMiners() Whitelist {
	return cachedWhitelist
}

func IsMinerInWhitelist(pubKey *ecdsa.PublicKey) bool {
	RetrieveAuthorisedMiners()
	if pubKey == nil {
		return false
	}
	miner := AuthorisedMiner(pubKey)
	return contains(cachedWhitelist, miner)
}

func contains(whitelist Whitelist, miner AuthorisedMiner) bool {
	for _, am := range whitelist {
		if matches, err := matchesExpectedPublicKey(miner, am); matches && err == nil {
			return true
		}
	}
	log.Debug("The miner with the public key X: " + miner.X.String() + " Y: " + miner.Y.String() + " is not on the whitelist")
	return false
}

// Check that the private key extracted from the signature matches the expected public key
func matchesExpectedPublicKey(publicKey *ecdsa.PublicKey, expectedPublicKey *ecdsa.PublicKey) (matches bool, err error) {
	if publicKey == nil || expectedPublicKey == nil {
		return false, errors.New("Neither of the public keys to compare should be nil")
	}

	// Verify that both of the private keys are on the same Elliptic curve
	if publicKey.Curve != expectedPublicKey.Curve {
		return false, nil
	}

	// Check that the X and Y coordinates of the two public keys match exactly
	return expectedPublicKey.Y.Cmp(publicKey.Y) == 0 && expectedPublicKey.X.Cmp(publicKey.X) == 0, nil
}

func addMinerToWhitelist(am AuthorisedMiner) {
	RetrieveAuthorisedMiners()
	cachedWhitelist = append(cachedWhitelist, am)
}