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

// Package pokw implements the Proof of Kernel Work consensus engine.
package pokw

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	allowedFutureBlockTime = 600 * time.Millisecond // Max time from current time allowed for blocks, before they're considered future blocks
)

// PoKW protocol constants.
const (
	extraVoting = 33 // extra data length up to the voting byte (32bytes vanity + 1byte voting)
	votingByte  = 32

	voteYes byte = 1 // vote for adding / keeping a signer
	voteNo  byte = 0 // vote for removing a signer
)

var (
	hashEmpty      = common.Hash{}            // used for mining block mixDigest
	hash1          = common.Hash{1}           // used for empty, not-mined block
	emptyUncleHash = types.CalcUncleHash(nil) // we don't add uncles in PoKW. Keccak256(RLP([]))
	emptyNonce     = types.BlockNonce{}
)

// LoggerDefaultLevel for pokw internal logging
var LoggerDefaultLevel = log.LvlDebug
var logger = log.New("log", "pokw")
var loggerOutHandler = log.StreamHandler(os.Stderr, log.TerminalFormat(true))

func init() {
	logger.SetHandler(
		log.LvlFilterHandler(LoggerDefaultLevel, loggerOutHandler))
}

func UpdateLoggingLevel(maxLvl log.Lvl) {
	logger.SetHandler(
		log.LvlFilterHandler(maxLvl, loggerOutHandler))
}

// EngineWithAthorize is an extended Engine interface to set authority / signer wallet.
type EngineWithAthorize interface {
	Authorize(common.Address, clique.SignerFn)
}

// PoKW is the Proof of Kernel Work consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type PoKW struct {
	config params.PoKWConfig // Consensus engine configuration parameters

	db ethdb.Database // Database to store and retrieve snapshot checkpoints

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	proposals map[common.Address]bool // Current list of proposals we are pushing

	signer Signer
	lock   sync.RWMutex // Protects the signer fields

	miner      *Miner
	sealHasher hasher   // computes hash for sealing header
	sigHasher  hasher   // computes hash for signatures
	sigVHasher hasher   // computes hash for signature verifications
	difficulty *big.Int // proof of work difficulty
}

// New creates a PoKW consensus engine with the initial
// signers set to the ones provided by the user.
func New(cfg *params.PoKWConfig, cfgM MinerConfig, db ethdb.Database, notify []string, noverify bool) *PoKW {
	// Set any missing consensus parameters to their defaults
	conf := *cfg
	if conf.Epoch == 0 {
		conf.Epoch = 30000
	}
	if conf.Committee < 0 {
		logger.Warn("PoKW sorition disabled. All whitelisted miners are allowed to do PoW")
	} else if conf.Committee == 0 {
		logger.Warn("PoKW Committee is set to empty. Committe selection will be disabled and only empty non-pow blocks will be allowed")
	}

	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)

	c := &PoKW{
		config:     conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),
		sealHasher: newPoKWHasher(),
		sigHasher:  newPoKWHasher(),
		sigVHasher: newPoKWHasher(),
	}
	c.miner = NewMiner(cfgM, c, 0, notify, noverify)
	return c
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (c *PoKW) Author(header *types.Header) (common.Address, error) {
	return ecrecoverHeader(header, c.signatures, c.sigHasher)
}

// Threads returns the number of mining threads currently enabled. This doesn't
// necessarily mean that mining is running!
func (c *PoKW) Threads() int {
	c.miner.lock.Lock()
	t := c.miner.threads
	c.miner.lock.Unlock()

	return t
}

// SetThreads updates the number of mining threads currently enabled. Calling
// this method does not start mining, only sets the thread count. If zero is
// specified, the miner will use all cores of the machine. Setting a thread
// count below zero is allowed and will cause the miner to idle, without any
// work being done.
func (c *PoKW) SetThreads(threads int) {
	m := c.miner
	m.lock.Lock()

	// Update the threads and ping any running seal to pull in any changes
	m.threads = threads
	select {
	case m.update <- struct{}{}:
	default:
	}
	m.lock.Unlock()
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *PoKW) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	err := c.verifyHeader(chain, header, nil, false, seal)
	return err
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *PoKW) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i], false, seals[i])
			if err != nil {
				logger.Warn("Wrong header", "number", header.Number, "err", err)
			}
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules. The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *PoKW) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header, uncle, checkMiner bool) (err error) {
	logger.Info("verifying header", "number", header.Number, "hash", header.Hash())
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()
	// Short circuit if the header is known, or its parent not
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}

	// Don't waste time checking blocks from the future
	if !uncle {
		if header.Time > uint64(time.Now().Add(allowedFutureBlockTime).Unix()) {
			return consensus.ErrFutureBlock
		}
	}
	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % c.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return errInvalidCheckpointBeneficiary
	}
	if len(header.Extra) < extraVoting {
		return errMissingVote
	}
	if header.Extra[votingByte] != voteYes && header.Extra[votingByte] != voteNo {
		return errInvalidVote
	}
	// Ensure that the extra-data contains a signer whitelist list only on checkpoint
	whitelistLen := len(header.Extra) - extraVoting
	if !checkpoint && whitelistLen != 0 {
		return errExtraSigners
	}
	if checkpoint {
		if whitelistLen%common.AddressLength != 0 {
			return errInvalidCheckpointSigners
		}
		if whitelistLen == 0 || whitelistLen/common.AddressLength > int(c.config.MaxWhitelist) {
			return errExtraSignersLen
		}
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if !(header.MixDigest == hashEmpty || header.MixDigest == hash1) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != emptyUncleHash {
		return errInvalidUncleHash
	}
	// The genesis block is the always valid dead-end
	if number == 0 {
		return nil
	}
	if err = c.verifyCascadingFields(chain, header, parents); err != nil {
		return err
	}
	return c.verifySeal(chain, header, parents, checkMiner)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *PoKW) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	number := header.Number.Uint64()
	// Ensure that the block's timestamp isn't too close to its parent
	parent, err := getParent(parents, chain, number-1, header.ParentHash)
	if err != nil {
		return err
	}
	if header.Time < parent.Time+1 {
		return ErrInvalidTimestamp
	}
	if err := verifyGasLimit(header); err != nil {
		return err
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// If the block is a checkpoint block, verify the signer list
	if number%c.config.Epoch == 0 {
		signers := make([]byte, len(snap.Signers)*common.AddressLength)
		for i, signer := range snap.signers() {
			copy(signers[i*common.AddressLength:], signer[:])
		}
		if !bytes.Equal(header.Extra[extraVoting:], signers) {
			logger.Warn("Wrong checkpoint whitelist", "got", header.Extra[extraVoting:], "expected", signers)
			return errMismatchingCheckpointSigners
		}
	}
	return nil
}

// TODO:pokw - in PoKW we want to remove gas limit
func verifyGasLimit(current *types.Header) error {
	// Verify that the gas limit is <= 2^63-1
	cap := uint64(0x7fffffffffffffff)
	if current.GasLimit > cap || current.GasLimit < params.MinGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v, min %v",
			current.GasLimit, cap, params.MinGasLimit)
	}
	if current.GasUsed > current.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", current.GasUsed, current.GasLimit)
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *PoKW) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return c.verifySeal(chain, header, nil, true)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (c *PoKW) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header, checkMiner bool) error {
	isPoW := c.isPoWBlock(header)
	if isPoW && checkMiner {
		if err := c.miner.VerifySeal(chain, header); err != nil {
			return err
		}
	}
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// snapshot is use to verify signers
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// Resolve the authorization key and check against signers
	signer, err := c.Author(header)
	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	}
	parent, err := getParent(parents, chain, number-1, header.ParentHash)
	if err != nil {
		return err
	}
	var expectedDifficulty = powDifficultyBig
	if isPoW {
		if header.MixDigest != hashEmpty {
			return errInvalidMixDigest
		}
		err = verifySigInCommittee(header.SigSortition, c.config.Committee, uint32(len(snap.Signers)))
		if err != nil {
			logger.Error("can't signature not in a committee", "sig", header.Sig)
			return err
		}
	} else {
		if !(header.TxHash == types.EmptyRootHash && header.ReceiptHash == types.EmptyRootHash) {
			return errNoCommitteeTx
		}
		expectedDifficulty = bigUint(sigToDifficulty(header.SigSortition))
	}
	if header.Difficulty.Cmp(expectedDifficulty) != 0 {
		return errInvalidDifficulty
	}
	return verifySeed(signer, header.Seed, parent.Seed, header.Number, c.sigVHasher, isPoW)
}

func (c *PoKW) isPoWBlock(h *types.Header) bool {
	return h.MixDigest == hashEmpty
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (c *PoKW) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		logger.Trace("looking for a snapshot", "number", number, "hash", hash)
		// If an in-memory snapshot was found, use that
		if s, ok := c.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(&c.config, c.signatures, c.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				logger.Debug("found snapshot in DB (disk)", "number", s.Number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at the genesis, snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		if number == 0 || (number%c.config.Epoch == 0 && (len(headers) > params.ImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()
				logger.Debug("loading snapshot from chain", "number", number, "hash", hash)
				signers := make([]common.Address, (len(checkpoint.Extra)-extraVoting)/common.AddressLength)
				for i := 0; i < len(signers); i++ {
					copy(signers[i][:], checkpoint.Extra[extraVoting+i*common.AddressLength:])
				}
				snap = newSnapshot(&c.config, c.signatures, number, hash, signers)
				if err := snap.store(c.db); err != nil {
					logger.Error("Can't store snapshot in DB", "err", err)
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			pHash := header.Hash()
			if pHash != hash || header.Number.Uint64() != number {
				return nil, fmt.Errorf("Looking for snapshot... parent=(hash=%s, number=%s) block doesn't match his child=(parentHash=%s, number=%d) [%w]",
					pHash, header.Number, hash, number+1, consensus.ErrUnknownAncestor)
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, fmt.Errorf("Looking for snapshot... can't load parent=(hash=%s, number=%d) block [%w]", hash, number, consensus.ErrUnknownAncestor)
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	// this is a nice trick to revers the slice
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers, c.sigHasher)
	if err != nil {
		return nil, err
	}
	c.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *PoKW) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	// If we will need to support uncles, then copy VerifyUncles form consensus/ethash
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
// Prepare must set all fields required for SealHash.
func (c *PoKW) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// TODO:pokw: security parameter k should go here (as number-k)
	number, parent, snap, err := c.getParentAndSnapshot(chain, header)
	if err != nil {
		logger.Error("Preparing block... can't load a snapshot", "number", header.Number, "header_hash", header.Hash(), "err", err)
		return err
	}
	// The signer can change hence we need to copy him here.
	c.lock.RLock()
	signer := c.signer
	c.lock.RUnlock()

	logger.Debug("Preparing block... snapshot loaded", "number", number, "signer", signer.addr, "signers", snap.signersHex(), "block_timestamp", header.Time)

	// Check if we are in whitelist
	if _, authorized := snap.Signers[signer.addr]; !authorized {
		return errUnauthorizedSigner
	}

	var errCommittee error
	// when config.Committee < 0 we disable committee selection.
	header.SigSortition, errCommittee = assertInCommittee(
		signer, c.config.Committee, uint32(len(snap.Signers)), parent.Number, parent.Seed)
	if errCommittee != nil && errCommittee != ErrNotInCommittee {
		return errCommittee
	}
	var inCommittee = errCommittee == nil
	if inCommittee {
		header.Difficulty = powDifficultyBig
		header.MixDigest = hashEmpty
	} else {
		logger.Trace("PoKW sorition: miner not selected")
		header.Difficulty = new(big.Int).SetUint64(sigToDifficulty(header.SigSortition))
		header.MixDigest = hash1 // MixDigest can be used in the future for VDF.
	}
	header.Seed, err = deriveSeed(signer, parent.Seed, header.Number, inCommittee)
	if err != nil {
		logger.Error("Preparing block... can't derive new seed", "number", number, "hash", header.Hash(), "err", err)
		return err
	}

	//  TODO:pokw disable vote on empty block (but we still need to fill ExtraData correctly)
	c.vote(header, number, snap)

	return errCommittee
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (c *PoKW) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, _ []*types.Transaction, _ []*types.Header) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.UncleHash = emptyUncleHash
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}

// FinalizeAndAssemble implements consensus.Engine. It calls Finalize and returns the final block for sealing.
func (c *PoKW) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	c.Finalize(chain, header, state, txs, uncles)

	if c.isPoWBlock(header) {
		// TODO:pokw if we want to include uncles we will need to change nil to uncles
		return types.NewBlock(header, txs, nil, receipts), nil
	}
	// empty blocks (produced by no committee members) don't have transactions.
	return types.NewBlock(header, nil, nil, nil), nil
}

// Seal implements consensus.Engine, attempting to mine a sealed block using PoKW consensus
// protocol: PoA sortition + PoW
func (c *PoKW) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	c.sealHasher.Mutex.Lock()
	headerID := MinerHash(c.sealHasher, header)
	c.sealHasher.Mutex.Unlock()

	args := sealArgs{headerID, header, block, results, stop}
	if c.isPoWBlock(header) {
		miningP := MiningParams{number, headerID, c.CalcDifficulty(chain, header.Time, nil).Uint64()}
		go c.mine(miningP, args)
	} else {
		go c.mineNoPoW(args)
	}
	return nil
}

type sealArgs struct {
	id      common.Hash
	header  *types.Header
	block   *types.Block
	results chan<- *types.Block
	stop    <-chan struct{}
}

// mineNoPoW creates an empty, non-pow block and puts result into the @results channel
func (c *PoKW) mineNoPoW(a sealArgs) {
	logger.Trace("scheduling non-pow block mining", "number", a.header.Number)
	var delay = c.config.EmptyBlockDelay
	if a.header.Time > uint64(time.Now().Unix()) {
		delay++
	}
	select {
	case <-a.stop:
		logger.Trace("mining non-pow block interrupted", "number", a.header.Number)
	case <-time.After(time.Duration(delay) * time.Second):
		logger.Debug("mining non-pow block", "number", a.header.Number)
		c.sealFinalize(emptyNonce, a)
	}
}

// mineNoPoW creates a pow block and puts result into the @results channel
func (c *PoKW) mine(miningP MiningParams, a sealArgs) {
	if nonce, ok := c.miner.Mine(miningP, a.stop); ok {
		c.sealFinalize(nonce, a)
	}
}

// sealFinalize finishes the sealing process and puts result into the @results channel
func (c *PoKW) sealFinalize(nonce types.BlockNonce, a sealArgs) {
	a.header.Nonce = nonce
	seal, err := SealPoKWBytes(a.header) // we need to hash it - this is done in signFn
	if err != nil {
		log.Error("Can't seal header for PoWK signature", "err", err)
		return
	}

	// Sign all the things!
	c.lock.RLock()
	signer := c.signer
	c.lock.RUnlock()
	a.header.Sig, err = signer.Sign(seal)
	if err != nil {
		log.Error("Can't sign pokw seal", "err", err)
		return
	}
	select {
	case <-a.stop:
		return
	case a.results <- a.block.WithSeal(a.header):
	default:
		log.Warn("Sealing result is not read for the miner",
			"PoW.mode", c.miner.config.PowMode, "sealhash", a.id)
	}
}

// CalcDifficulty returns the difficulty for the mining puzzle.
// This does not necessary need to be the same as header.Difficulty - used for the for choice
// rule (heaviest chain).
func (c *PoKW) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return c.calcDifficulty(chain, parent)
}

func (c *PoKW) calcDifficulty(chain consensus.ChainReader, parent *types.Header) *big.Int {
	if c.difficulty == nil {
		if parent != nil && parent.Number.Cmp(common.Big0) == 0 { // genesis block
			c.difficulty = parent.Difficulty
		} else {
			h := chain.GetHeaderByNumber(0)
			c.difficulty = h.Difficulty
		}
	}
	return c.difficulty
}

// SealHash returns the hash of a block prior to it being signed. The mining should be run before
// constructing the final seal hash.
// This function is used only outside to detect same blocks heance it shouldn't include
// sealing fields in the hash (like Nonce or Signature)
// For the consensus we are using SealBytes - which prepares data for signature without double
// hashing (signFn hashes the data).
func (c *PoKW) SealHash(header *types.Header) common.Hash {
	c.sealHasher.Mutex.Lock()
	h := MinerHash(c.sealHasher, header)
	c.sealHasher.Mutex.Unlock()
	return h
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with. This method has same meaning as Clique, and is used as a special case by the
// Ethereum object.
func (c *PoKW) Authorize(signer common.Address, signFn clique.SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = Signer{signer, signFn}
}

// IsAuthorized checks if the engine has assigned a signer.
func (c *PoKW) IsAuthorized() bool {
	return c.signer.signFn != nil
}

// Close implements consensus.Engine. It's a noop for PoKW as there are no background threads.
func (c *PoKW) Close() error {
	return c.miner.Close()
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *PoKW) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "pokw",
		Version:   "1.0",
		Service:   &API{chain: chain, engine: c},
		Public:    false,
	}}
}

// vote fills the header.Extra data with vote and checkpoint information in header.Extra.
// The layout of of extra field is: `<32bytes vanity><1byte vote><checkpoint signers>`
// For the moment we cast cast a random vote - this is how Clique is doint this.
func (c *PoKW) vote(header *types.Header, number uint64, snap *Snapshot) {
	// Ensure the extra data has all its components
	if len(header.Extra) < extraVoting {
		diff := extraVoting - len(header.Extra)
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, diff)...)
	}
	// move the "end of a slice" to the end of extraVoting. Header.Extra doesn't have a required
	// value, but there is a common practice to reserve first 32 bytes for a miner information
	header.Extra = header.Extra[:extraVoting]

	// We cast a vote only when on none-checkpoint blocks
	if number%c.config.Epoch != 0 {
		c.lock.RLock()

		// Gather all the proposals that make sense voting on
		addresses := make([]common.Address, 0, len(c.proposals))
		for address, authorize := range c.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		if len(addresses) > 0 {
			header.Coinbase = addresses[rand.Intn(len(addresses))]
			if c.proposals[header.Coinbase] {
				header.Extra[votingByte] = voteYes
			} else {
				header.Extra[votingByte] = voteNo
			}
		}
		c.lock.RUnlock()
	} else { // on checkpoint add signers snapshot.
		for signer := range snap.Signers {
			header.Extra = append(header.Extra, signer[:]...)
		}
	}
}

// SealPoKWBytes computes header identifier to be signed after mining.
// This have all header fields except signature.
func SealPoKWBytes(header *types.Header) (seal []byte, err error) {
	data := append(collectEthashIngerdientes(header), header.Nonce)
	if seal, err = rlp.EncodeToBytes(data); err != nil {
		log.Crit("Can't RLP encode header for seal", err)
	}
	return
	// TODO:pokw - if we solve signing issue (having a way to sign data without letting the wallet hashing it) then we can merge this function with SealBytes. We also can't put a signer here because the return type (signature: bytes) will not match the required intereface (consensus.Engine)
	/*
		data := append(collectEthashIngerdientes(header), header.Nonce)
		hr := NewPoKWHasher()
		if err := rlp.Encode(hr, data); err != nil {
			panic("can't encode PoKW seal data: " + err.Error())
		}
		hr.Read(hash[:0])
		return */
}

func getParent(parents []*types.Header, chain consensus.ChainReader, parentNumber uint64, parentHash common.Hash) (*types.Header, error) {
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(parentHash, parentNumber)
	}
	if parent == nil {
		return nil, fmt.Errorf("Got nil parent=(hash=%s, number=%d) [%w]", parentHash, parentNumber, consensus.ErrUnknownAncestor)
	}
	n := parent.Number.Uint64()
	h := parent.Hash()
	if n != parentNumber || h != parentHash {
		return nil, fmt.Errorf("requested parent=(hash=%s, number=%d) doesn't match (parentHash=%s, parentNumber=%d) [%w]", h, n, parentHash, parentNumber, consensus.ErrUnknownAncestor)
	}
	return parent, nil
}

func (c *PoKW) getParentAndSnapshot(chain consensus.ChainReader, header *types.Header) (uint64, *types.Header, *Snapshot, error) {
	if !header.Number.IsUint64() {
		return 0, nil, nil, errInvalidBlockNumber
	}
	number := header.Number.Uint64()
	parent, err := getParent(nil, chain, number-1, header.ParentHash)
	if err != nil {
		return 0, nil, nil, err
	}
	snap, err := c.snapshot(chain, number-1, header.ParentHash, []*types.Header{parent})
	return number, parent, snap, err
}
