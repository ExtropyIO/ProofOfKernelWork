package authentication

import (
	"crypto/ecdsa"
	"math/big"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

type AuthorisedMiner *ecdsa.PublicKey
type Whitelist []AuthorisedMiner

var cachedWhitelist Whitelist

var ValidMiner1 = ecdsa.PublicKey{
	crypto.S256(),
	big.NewInt(0),
	big.NewInt(1),
}

var validMiner2X, _ = new(big.Int).SetString("83627328701153660129122311979087170547012155418906152112136635125509300377318", 10)
var validMiner2Y, _ = new(big.Int).SetString("108196635521158057672584401627437779732742303084877413837400915130868400893055", 10)
var ValidMiner2 = ecdsa.PublicKey{
	crypto.S256(),
	validMiner2X,
	validMiner2Y,
}

func RetrieveAuthorisedMiners() Whitelist {
	cachedWhitelist = []AuthorisedMiner{
		&ValidMiner1,
		&ValidMiner2,
	}

	return cachedWhitelist
}

func IsMinerInWhitelist(pubKey *ecdsa.PublicKey) bool {
	if cachedWhitelist == nil || len(cachedWhitelist) == 0 {
		RetrieveAuthorisedMiners()
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
	cachedWhitelist = append(cachedWhitelist, am)
}