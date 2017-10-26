package coterie

import (
	"testing"
	"crypto/ecdsa"
	"math/big"
	"github.com/ethereum/go-ethereum/crypto"
)

var validMinerX, _ = new(big.Int).SetString("83627328701153660129122311979087170547012155418906152112136635125509300377318", 10)
var validMinerY, _ = new(big.Int).SetString("108196635521158057672584401627437779732742303084877413837400915130868400893055", 10)

var MatchingMinerInWhitelist = ecdsa.PublicKey{
	crypto.S256(),
	validMinerX,
	validMinerY,
}


var MinerNotInWhitelist1 = ecdsa.PublicKey{
	crypto.S256(),
	big.NewInt(1),
	big.NewInt(1),
}

var MinerNotInWhitelist2 = ecdsa.PublicKey{
	crypto.S256(),
	big.NewInt(1),
	big.NewInt(0),
}

var MinerNotInWhitelist3 = ecdsa.PublicKey{
	crypto.S256(),
	big.NewInt(0),
	big.NewInt(0),
}

var MinerNotInWhitelist4 = ecdsa.PublicKey{
	crypto.S256(),
	big.NewInt(0),
	big.NewInt(2),
}

// Since currently we're exporting the hardcoded public keys; perform a sanity test that a public key known to be in the
// whitelist is considered valid.
func TestCanValidateMinerIsInWhitelist(t *testing.T) {
	pubKey := &ValidMiner1
	auth := IsMinerInWhitelist(pubKey)
	if !auth {
		t.Error("Expected that the public key would be in the whitelist")
	}
}

// Check to make sure that a matching public key - same X and Y coordinates on the expected curve are considered valid
// even though they are a pointer to a different object.
func TestCanValidateMatchingPublicKeyIsInWhitelist(t *testing.T) {
	pubKey := &MatchingMinerInWhitelist
	auth := IsMinerInWhitelist(pubKey)
	if !auth {
		t.Error("Expected that the public key matching a whitelisted miner would be considered to be in the whitelist")
	}
}

func TestCanNotValidateMinerThatIsNotInWhitelist(t *testing.T) {
	auth := IsMinerInWhitelist(&MinerNotInWhitelist1)
	if auth {
		t.Error("Expected that the public key (MinerNotInWhitelist1) would *not* be in the whitelist")
	}

	auth = IsMinerInWhitelist(&MinerNotInWhitelist2)
	if auth {
		t.Error("Expected that the public key (MinerNotInWhitelist2) would *not* be in the whitelist")
	}

	auth = IsMinerInWhitelist(&MinerNotInWhitelist3)
	if auth {
		t.Error("Expected that the public key (MinerNotInWhitelist3) would *not* be in the whitelist")
	}

	auth = IsMinerInWhitelist(&MinerNotInWhitelist4)
	if auth {
		t.Error("Expected that the public key (MinerNotInWhitelist4) would *not* be in the whitelist")
	}
}

func TestCanNotValidateNilMiner(t *testing.T) {
	auth := IsMinerInWhitelist(nil)
	if auth {
		t.Error("Expected that the public key would *not* be in the whitelist")
	}
}