package pokw

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasherComputeBlockProof(t *testing.T) {
	var hasher = newPoKWHasher()
	var out = make([]byte, hasher.OutputLen)
	var zero = hashEmpty[:]
	var data = common.Hash{}
	data[0] = 1

	require.Nil(t, hasher.ComputeBlockProof(data, 1, out))
	h1s := by2h(out)
	require.NotEqual(t, zero, out)
	require.Nil(t, hasher.ComputeBlockProof(data, 2, out))
	h2s := by2h(out)
	assert.NotEqual(t, zero, out)
	assert.NotEqual(t, h1s, h2s, "Hashesh should be different", "h1", h1s, "h2", h2s)
}

func TestSeedToBytes(t *testing.T) {
	var s = "0xd4e56740f876aef8c010b86a40d5f56745a118d0908a34e49aec8c0db1cb8fa3"
	b := common.FromHex(s)
	// assert.Nil(t, err, err)
	assert.Len(t, b, (len(s)-2)/2, "wrong length")
	assert.Equal(t, b[0], byte(212))
	s2 := "0x" + hex.EncodeToString(b)
	assert.Equal(t, s2, s)
}

func by2h(b []byte) string {
	return hex.EncodeToString(b)
}
