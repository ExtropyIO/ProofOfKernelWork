package main

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestCreateExtraData(t *testing.T) {
	require := require.New(t)
	var addrStrs = []string{
		"6bbc9092b4b21cf68d81cb4b5527965486a32434",
		"0xdcdc1a58c2666e230f8566ca350b8e6eded163e8",
	}
	const al = common.AddressLength * 2 // 1 byte = 2hex

	ed := createExtraData(addrStrs)
	require.Equal("0x", ed[:2], "should have 0x prefix")
	expectedLen := 2 + extraPrefix*2 + al*len(addrStrs)
	require.Len(ed, expectedLen)
	ed = ed[2+2*extraPrefix:]

	for i, s := range addrStrs {
		start := i * al
		s = remove0x(s)
		require.Equal(s, ed[start:start+al])
	}
}
