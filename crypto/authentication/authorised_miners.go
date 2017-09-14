package authentication

import (
	"crypto/ecdsa"
	"math/big"
	"github.com/ethereum/go-ethereum/crypto"
)

type AuthorisedMiner *ecdsa.PublicKey
type Whitelist []AuthorisedMiner

var cachedWhitelist Whitelist

var ValidMiner1 = ecdsa.PublicKey{
	crypto.S256(),
	big.NewInt(0),
	big.NewInt(1),
}

func RetrieveAuthorisedMiners() Whitelist {
	var a AuthorisedMiner = &ValidMiner1
	cachedWhitelist = []AuthorisedMiner{
		a,
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