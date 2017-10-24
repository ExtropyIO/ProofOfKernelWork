// Package clique implements the coterie consensus engine - implementing the consensus interface.
package coterie

import (
	"errors"
	"sync"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/crypto/authentication"
)

// SignerFn is a signer callback function to request a hash to be signed by a
// backing account. Copied from the clique implementation.
type SignerFn func(accounts.Account, []byte) ([]byte, error)

type Coterie struct {
	db     ethdb.Database // Database to store and retrieve x
	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the coterie fields
}

func New(db ethdb.Database) *Coterie {
	return &Coterie{
		db:	db,
	}
}

// Consensus - Engine - interface implementation

// Author retrieves the Ethereum address of the account that minted the given
// block, which may be different from the header's coinbase if a consensus
// engine is based on signatures.
func (c *Coterie) Author(header *types.Header) (common.Address, error) {
	return authentication.RetrieveBlockAuthor(header)
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (c *Coterie) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	// TODO replace with proper validation
	// TODO check the seed value is correct
	return nil
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (c *Coterie) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	// TODO replace with proper validation
	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of a given engine.
func (c *Coterie) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	// Same as the Clique consensus - we don't expect there to be any uncles
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (c *Coterie) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	// TODO replace with proper validation
	return nil
}

// Prepare initializes the consensus fields of a block header according to the
// rules of a particular engine. The changes are executed inline.
func (c *Coterie) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// TODO implement proper logic
	return nil
}

// Finalize runs any post-transaction state modifications (e.g. block rewards)
// and assembles the final block.
// Note: The block header and state database might be updated to reflect any
// consensus rules that happen at finalization (e.g. block rewards).
func (c *Coterie) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// TODO implement proper logic
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Seal generates a new block for the given input block with the local miner's
// seal place on top.
func (c *Coterie) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	// TODO implement proper logic
	return block, nil
}

// APIs returns the RPC APIs this consensus engine provides.
func (c *Coterie) APIs(chain consensus.ChainReader) []rpc.API {
	// TODO implement proper logic
	return nil
}

// Coterie-specific functions / methods
// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Coterie) Authorize(signer common.Address, signFn SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
}