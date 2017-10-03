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

var validMiner1X, _ = new(big.Int).SetString("83627328701153660129122311979087170547012155418906152112136635125509300377318", 10)
var validMiner1Y, _ = new(big.Int).SetString("108196635521158057672584401627437779732742303084877413837400915130868400893055", 10)
var ValidMiner1 = ecdsa.PublicKey{
	crypto.S256(),
	validMiner1X,
	validMiner1Y,
}

// 0xea30250dd7263a4783c66463c236a2153d6b88b4
var validMiner2X, _ = new(big.Int).SetString("94396931332251919240193240529601179568888929373150616739295752130533619776103", 10)
var validMiner2Y, _ = new(big.Int).SetString("8610410070386006697862922879258586462856388890087040994978586938496691148169", 10)
var ValidMiner2 = ecdsa.PublicKey{
	crypto.S256(),
	validMiner2X,
	validMiner2Y,
}

// 0x46dfb921f8f7edbbd8100458b7c1beefeabf6e15
var validMiner3X, _ = new(big.Int).SetString("27820086715366380360262426024593605005780451323497016622845608346783317971002", 10)
var validMiner3Y, _ = new(big.Int).SetString("101278124478706218926016317218852431122700169021878314291476778072767207984433", 10)
var ValidMiner3 = ecdsa.PublicKey{
	crypto.S256(),
	validMiner3X,
	validMiner3Y,
}

// 0x6c80e492308f051eba48d03bcc04625682ae3e07
var validMiner4X, _ = new(big.Int).SetString("14872566346503487184640227613800942080708494540175539531745442872825374028117", 10)
var validMiner4Y, _ = new(big.Int).SetString("89556085484287306583832054099885771945426283070780435718832318280856846795692", 10)
var ValidMiner4 = ecdsa.PublicKey{
	crypto.S256(),
	validMiner4X,
	validMiner4Y,
}

// 0x30ff130a7d11ef9d1efbdf19d5309556acd129cf
var validMiner5X, _ = new(big.Int).SetString("55890638889347635983965127626863328706463524823559675385262348270781800469789", 10)
var validMiner5Y, _ = new(big.Int).SetString("88568072119687127585350342619706727400362465547502787818690210152295105984113", 10)
var ValidMiner5 = ecdsa.PublicKey{
	crypto.S256(),
	validMiner5X,
	validMiner5Y,
}

func RetrieveAuthorisedMiners() Whitelist {
	if cachedWhitelist == nil || len(cachedWhitelist) == 0 {

		cachedWhitelist = []AuthorisedMiner{
			&ValidMiner1,
			&ValidMiner2,
			&ValidMiner3,
			&ValidMiner4,
			&ValidMiner5,
		}

		return cachedWhitelist
	}
	return cachedWhitelist
}

func IsMinerInWhitelist(pubKey *ecdsa.PublicKey) bool {
	RetrieveAuthorisedMiners()
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
	RetrieveAuthorisedMiners()
	cachedWhitelist = append(cachedWhitelist, am)
}