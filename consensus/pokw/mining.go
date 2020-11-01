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
	crand "crypto/rand"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"time"
	"hash"
	"encoding/binary"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// MinerConfig are the configuration parameters of the e.
type MinerConfig struct {
	PowMode ethash.Mode

	Log log.Logger `toml:"-"`
}
var lock sync.Mutex
// Miner is a consensus engine based on proof-of-work implementing the e
// algorithm.
type Miner struct {
	parent consensus.Engine
	config MinerConfig

	// Mining related fields
	rand     *rand.Rand    // Properly seeded random source for nonces
	threads  int           // Number of threads to mine on if mining
	update   chan struct{} // Notification channel to update mining parameters
	hashrate metrics.Meter // Meter tracking the average hashrate
	// TODO:pokw we removed remoteSealer functionality
	// remote   *remoteSealer

	// nonce verifier
	verifier hasher

	// The fields below are hooks for testing
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	lock      sync.Mutex // Ensures thread safety for the in-memory caches and mining fields
	closeOnce sync.Once  // Ensures exit channel will not be closed twice.
}
type hasher func(dest []byte, data []byte) 
func makeHasher(h hash.Hash) hasher {
	lock.Lock()
	defer lock.Unlock()
	// sha3.state supports Read to get the sum, use it to avoid the overhead of Sum.
	// Read alters the state but we reset the hash before every operation.
		type readerHash interface {
	hash.Hash
	Read([]byte) (int, error)
}
	rh, ok := h.(readerHash)
	if !ok {
		panic("can't find Read method on hash")
	}
	outputLen := rh.Size()
	return func(dest []byte, data []byte) {
		rh.Reset()
		rh.Write(data)
		rh.Read(dest[:outputLen])
	}
}
func ComputeBlockProof(headerH common.Hash, nonce uint64, dest []byte) error {
	
	data := make([]byte,40)
	
	for i, v := range headerH {
		data[i] = v
	}
	emptyNounce := make([]byte, 8)
	binary.LittleEndian.PutUint64(emptyNounce, nonce)
	sum := append(data, emptyNounce...)
	
	keccak512 := makeHasher(sha3.NewLegacyKeccak256())

	keccak512(dest[:32], sum)
	// hasher.Write(headerH[:])
	// hasher.Write(nonce)
	// h.Reset()
	// h.rh.Write(headerH[:])
	// binary.LittleEndian.PutUint64(h.nonce, nonce)
	// h.rh.Write(h.nonce)
	// _, err := h.rh.Read(dest[:h.OutputLen])
	
	return nil
}

// NewMiner creates a full sized e PoW scheme and starts a background thread for
// remote mining, also optionally notifying a batch of remote services of new work
// packages.
func NewMiner(config MinerConfig, parent consensus.Engine, threads int, notify []string, noverify bool) *Miner {
	if config.Log == nil {
		config.Log = log.Root()
	}
	e := &Miner{
		config:   config,
		threads:  threads,
		update:   make(chan struct{}),
		hashrate: metrics.NewMeterForced(),
		// verifier: hasher,
		parent:   parent,
		// remote: startRemoteSealer(e, notify, noverify), // TODO:pokw remoteSealer
	}
	return e
}

// Close closes the exit channel to notify all backend threads exiting.
func (m *Miner) Close() error {
	var err error
	m.closeOnce.Do(func() {
		// Short circuit if the exit channel is not allocated.
		/* TODO:pokw remoteSealer
		if m.remote == nil {
			return
		}
		close(m.remote.requestExit)
		<-e.remote.exitCh
		*/
	})
	return err
}

// Hashrate implements PoW, returning the measured rate of the search invocations
// per second over the last minute.
// Note the returned hashrate includes local hashrate, but also includes the total
// hashrate of all remote miner.
func (m *Miner) Hashrate() float64 {
	// Short circuit if we are run the e in normal/test mode.
	if m.config.PowMode != ethash.ModeNormal && m.config.PowMode != ethash.ModeTest {
		return m.hashrate.Rate1()
	}

	return m.hashrate.Rate1()
	/* TODO:pokw remoteSealer
	var res = make(chan uint64, 1)
	select {
	case m.remote.fetchRateCh <- res:
	case <-m.remote.exitCh:
		// Return local hashrate only if e is stopped.
		return m.hashrate.Rate1()
	}

	// Gather total submitted hash rate of remote sealers.
	return m.hashrate.Rate1() + float64(<-res)
	*/
}

// MiningParams is a set of parameters for solving the mining problems.
type MiningParams struct {
	Number     uint64
	HeaderH    common.Hash
	Difficulty uint64
}

// Mine attempts to find a nonce that satisfies the block's difficulty requirements.
// Returns: nonce, errror
func (m *Miner) Mine(params MiningParams, stop <-chan struct{}) (types.BlockNonce, bool) {
	// If we're running a fake PoW, simply return a 0 nonce immediately
	if m.config.PowMode == ethash.ModeFake || m.config.PowMode == ethash.ModeFullFake {
		return types.BlockNonce{}, true
	}

	// Create a runner and the multiple search threads it directs
	threads := m.threads
	if threads < 0 {
		logger.Debug("Spinning new block miners. THREADS<0", "number", params.Number, "threads", threads, "pre_sealing_hash", params.HeaderH)
		return types.BlockNonce{}, false
	}
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if !m.initRand() {
		return types.BlockNonce{}, false
	}
	// Push new work to remote sealer
	/* TODO:pokw remoteSealer
	if e.remote != nil {
		e.remote.workCh <- &sealTask{block: params.block, results: results}
	}*/
	var (
		pend   sync.WaitGroup
		locals = make(chan types.BlockNonce)
		abort  = make(chan struct{})
	)
	logger.Debug("Spinning new block miners", "number", params.Number, "difficulty", params.Difficulty, "threads", threads, "pre_sealing_hash", params.HeaderH)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go m.mine(params, i, uint64(m.rand.Int63()), locals, abort, &pend)
	}

	var nonce types.BlockNonce
	var ok = false
	select {
	case <-stop:
		logger.Debug("Stopping miners", "pre_sealing_hash", params.HeaderH)
	case nonce = <-locals:
		ok = true
	case <-m.update:
		// Thread count was changed on user request, restart
		close(abort)
		pend.Wait()
		return m.Mine(params, stop)
	}
	// Wait for all miners to terminate
	close(abort)
	pend.Wait()
	return nonce, ok
}

func (m *Miner) initRand() bool {
	m.lock.Lock()
	if m.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			m.lock.Unlock()
			log.Error("Can't initialize nonce seed for mining", "err", err)
			return false
		}
		m.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	m.lock.Unlock()
	return true
}

// mine is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (m *Miner) mine(params MiningParams, id int, seed uint64, found chan<- types.BlockNonce, abort <-chan struct{}, pend *sync.WaitGroup) {
	defer pend.Done()

	// Extract some data from the header
	var (
		// header.Difficulty is used for fork choice rule, not for mining.
		target   = computeMiningTarget(params.Difficulty)
		attempts = int64(0)
		nonce    = seed
		// hasher   = makeHasher(sha3.NewLegacyKeccak256())
		// result   = make([]byte, hasher.OutputLen)
		result   = make([]byte,32)
		logger   = m.config.Log.New("miner", id)
	)

	logger.Trace("Started e search for new nonces", "seed", seed, "target", b2h(target))
search:
	// Start generating random nonces until we abort or find a good one
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			logger.Trace("E nonce search aborted", "attempts", attempts)
			m.hashrate.Mark(attempts)
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				m.hashrate.Mark(attempts)
				attempts = 0
			}
			// Compute the PoW value of this nonce
			err := ComputeBlockProof(params.HeaderH, nonce, result)
			if err != nil {
				logger.Error("Can't compute hash", "attempt", attempts, "err", err)
				continue
			}
			resultN := new(big.Int).SetBytes(result)
			if resultN.Cmp(target) <= 0 {
				// Correct nonce found, create a new header with it
				select {
				case found <- types.EncodeNonce(nonce):
					logger.Trace("E nonce found and reported", "attempts", attempts, "nonce", nonce)
				case <-abort:
					logger.Trace("E nonce found but discarded", "attempts", attempts, "nonce", nonce)
				}
				break search
			}
			nonce++
		}
	}
}

// VerifySeal implements consensus.Engine, checking whether the given block satisfies
// the PoW difficulty requirements.
func (m *Miner) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	number := header.Number.Uint64()
	// If we're running a fake PoW, accept any seal as valid
	if m.config.PowMode == ethash.ModeFake || m.config.PowMode == ethash.ModeFullFake {
		time.Sleep(m.fakeDelay)
		if m.fakeFail == number {
			fmt.Fprintln(os.Stderr, "££££ModeFullFake : ")
			return errInvalidPoW
		}
		return nil
	}

	headerH := MinerHash(header)
	// var result = make([]byte, m.verifier.OutputLen)
	var result = make([]byte, 32)
	err := ComputeBlockProof(headerH, header.Nonce.Uint64(), result)
	if err != nil {
		fmt.Fprintln(os.Stderr, "££££ ComputeBlockProof: ",err)
		return err
	}

	// Note: parent is not needed to calculate pokw difficulty
	target := computeMiningTarget(m.parent.CalcDifficulty(chain, header.Time, nil).Uint64())
	if new(big.Int).SetBytes(result).Cmp(target) > 0 {
		fmt.Fprintln(os.Stderr, "££££ computeMiningTarget: ")
		return errInvalidPoW
	}
	return nil
}

func computeMiningTarget(difficulty uint64) *big.Int {
	return new(big.Int).Lsh(common.Big1, uint(256-difficulty))
}

func collectEthashIngerdientes(header *types.Header) []interface{} {
	return []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
		header.MixDigest,
		header.Seed,
		header.SigSortition,
	}
}

// MinerHash returns the hash of a block prior to mining a block.
// In PoKW sealing consist of 2 steps:
//   1. finding a nonce which will match block hash for mining
//   2. signing the block - here we will need to add a nonce to the hash.
// In this function creates a hash for step 1.
func MinerHash( header *types.Header) (h common.Hash) {
	// data := collectEthashIngerdientes(header)
	hasher := sha3.NewLegacyKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
		header.MixDigest,
		header.Seed,
		header.SigSortition,
	})
	hasher.Sum(h[:0])
	// if err := rlp.Encode(hr, data); err != nil {
	// 	panic("can't encode e data: " + err.Error())
	// }
	// hasher.Read(h[:])
	return
}

// b2h converts *big.Int to a hex string
func b2h(b *big.Int) string {
	return fmt.Sprintf("%x", b)
}
