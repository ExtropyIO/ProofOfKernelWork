// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package pokw

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/influxdata/influxdb/pkg/testing/assert"
	"github.com/stretchr/testify/require"
)

var minerTesterConfig = MinerConfig{PowMode: ethash.ModeNormal, Log: log.Root()}

// NewMinerTester creates a small sized e PoW scheme useful only for testing
// purposes.
func NewMinerTester(notify []string, noverify bool) *Miner {
	pokw := New(new(params.PoKWConfig), minerTesterConfig, nil, notify, noverify)
	pokw.difficulty = 10
	return pokw.miner
}

// Tests that ethash works correctly in test mode.
func TestMining(t *testing.T) {
	require := require.New(t)
	hr := newPoKWHasher()
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(10)}
	headerH := MinerHash(hr, header)
	miner := NewMinerTester(nil, false)
	defer miner.Close()

	stop := make(chan struct{})
	params := MiningParams{1, headerH, 10}
	go func() { // let's stop mining if's too long
		<-time.NewTimer(time.Second).C
		t.Fatal("sealing result timeout")
		close(stop)
	}()

	nonce, ok := miner.Mine(params, stop)
	require.True(ok, "Mining should succeed")
	require.NotEqual(types.BlockNonce{}, nonce)

	header.Nonce = nonce
	err := miner.VerifySeal(nil, header)
	require.Nil(err, "unexpected verification error", err)
}

func TestHashRate(t *testing.T) {
	var (
	// hashrate = []hexutil.Uint64{100, 200, 300}
	// expect   uint64
	// ids      = []common.Hash{common.HexToHash("a"), common.HexToHash("b"), common.HexToHash("c")}
	)
	miner := NewMinerTester(nil, false)
	defer miner.Close()

	assert.Equal(t, float64(0), miner.Hashrate(), "Total hashrate should be zero")

	/* TODO: finish this test
	api := &API{miner}
	for i := 0; i < len(hashrate); i += 1 {
		if res := api.SubmitHashRate(hashrate[i], ids[i]); !res {
			t.Error("remote miner submit hashrate failed")
		}
		expect += uint64(hashrate[i])
	}
	assert.Equal(t, tot, float64(expected), "expect total hashrate should be same")
	*/
}

/*

func TestRemoteSealer(t *testing.T) {
	miner := NewMinerTester(nil, false)
	defer miner.Close()

	api := &API{miner}
	if _, err := api.GetWork(); err != errNoMiningWork {
		t.Error("expect to return an error indicate there is no mining work")
	}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(100)}
	block := types.NewBlockWithHeader(header)
	sealhash := miner.SealHash(header)

	// Push new work.
	results := make(chan *types.Block)
	miner.Seal(nil, block, results, nil)

	var (
		work [4]string
		err  error
	)
	if work, err = api.GetWork(); err != nil || work[0] != sealhash.Hex() {
		t.Error("expect to return a mining work has same hash")
	}

	if res := api.SubmitWork(types.BlockNonce{}, sealhash, common.Hash{}); res {
		t.Error("expect to return false when submit a fake solution")
	}
	// Push new block with same block number to replace the original one.
	header = &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(1000)}
	block = types.NewBlockWithHeader(header)
	sealhash = miner.SealHash(header)
	miner.Seal(nil, block, results, nil)

	if work, err = api.GetWork(); err != nil || work[0] != sealhash.Hex() {
		t.Error("expect to return the latest pushed work")
	}
}

func TestClosedRemoteSealer(t *testing.T) {
	miner := NewMinerTester(nil, false)
	time.Sleep(1 * time.Second) // ensure exit channel is listening
	miner.Close()

	api := &API{miner}
	if _, err := api.GetWork(); err != errMinerStopped {
		t.Error("expect to return an error to indicate miner is stopped")
	}

	if res := api.SubmitHashRate(hexutil.Uint64(100), common.HexToHash("a")); res {
		t.Error("expect to return false when submit hashrate to a stopped miner")
	}
}
*/

/* TODO: finish tests
// Tests whether stale solutions are correctly processed.
func TestStaleSubmission(t *testing.T) {
	miner := NewMinerTester(nil, true)
	defer miner.Close()
	api := &API{miner}

	fakeNonce, fakeDigest := types.BlockNonce{0x01, 0x02, 0x03}, common.HexToHash("deadbeef")

	testcases := []struct {
		headers     []*types.Header
		submitIndex int
		submitRes   bool
	}{
		// Case1: submit solution for the latest mining package
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xa}), Number: big.NewInt(1), Difficulty: big.NewInt(100000000)},
			},
			0,
			true,
		},
		// Case2: submit solution for the previous package but have same parent.
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xb}), Number: big.NewInt(2), Difficulty: big.NewInt(100000000)},
				{ParentHash: common.BytesToHash([]byte{0xb}), Number: big.NewInt(2), Difficulty: big.NewInt(100000001)},
			},
			0,
			true,
		},
		// Case3: submit stale but acceptable solution
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xc}), Number: big.NewInt(3), Difficulty: big.NewInt(100000000)},
				{ParentHash: common.BytesToHash([]byte{0xd}), Number: big.NewInt(9), Difficulty: big.NewInt(100000000)},
			},
			0,
			true,
		},
		// Case4: submit very old solution
		{
			[]*types.Header{
				{ParentHash: common.BytesToHash([]byte{0xe}), Number: big.NewInt(10), Difficulty: big.NewInt(100000000)},
				{ParentHash: common.BytesToHash([]byte{0xf}), Number: big.NewInt(17), Difficulty: big.NewInt(100000000)},
			},
			0,
			false,
		},
	}
	results := make(chan *types.Block, 16)

	for id, c := range testcases {
		for _, h := range c.headers {
			miner.Seal(nil, types.NewBlockWithHeader(h), results, nil)
		}
		if res := api.SubmitWork(fakeNonce, miner.SealHash(c.headers[c.submitIndex]), fakeDigest); res != c.submitRes {
			t.Errorf("case %d submit result mismatch, want %t, get %t", id+1, c.submitRes, res)
		}
		if !c.submitRes {
			continue
		}
		select {
		case res := <-results:
			if res.Header().Nonce != fakeNonce {
				t.Errorf("case %d block nonce mismatch, want %x, get %x", id+1, fakeNonce, res.Header().Nonce)
			}
			if res.Header().MixDigest != fakeDigest {
				t.Errorf("case %d block digest mismatch, want %x, get %x", id+1, fakeDigest, res.Header().MixDigest)
			}
			if res.Header().Difficulty.Uint64() != c.headers[c.submitIndex].Difficulty.Uint64() {
				t.Errorf("case %d block difficulty mismatch, want %d, get %d", id+1, c.headers[c.submitIndex].Difficulty, res.Header().Difficulty)
			}
			if res.Header().Number.Uint64() != c.headers[c.submitIndex].Number.Uint64() {
				t.Errorf("case %d block number mismatch, want %d, get %d", id+1, c.headers[c.submitIndex].Number.Uint64(), res.Header().Number.Uint64())
			}
			if res.Header().ParentHash != c.headers[c.submitIndex].ParentHash {
				t.Errorf("case %d block parent hash mismatch, want %s, get %s", id+1, c.headers[c.submitIndex].ParentHash.Hex(), res.Header().ParentHash.Hex())
			}
		case <-time.NewTimer(time.Second).C:
			t.Errorf("case %d fetch miner result timeout", id+1)
		}
	}
}
*/
