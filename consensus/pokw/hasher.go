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
	"encoding/binary"
	"hash"
	"math/big"
	"sync"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

type readerHash interface {
	hash.Hash
	Read([]byte) (int, error)
}

type hasher struct {
	Mutex     *sync.Mutex
	rh        readerHash
	OutputLen int
	nonce     []byte // used to store nonce value
}
var lock sync.Mutex

// newHasher creates an instance of Hash optimized for memory allocations.
// It is not thread safe!
func newHasher(h hash.Hash) hasher {
	// sha3.state supports Read to get the sum, use it to avoid the overhead of Sum.
	// Read alters the state but we reset the hash before every operation.

	rh, ok := h.(readerHash)
	if !ok {
		panic("can't find Read method on hash")
	}
	fmt.Fprintln(os.Stderr, "### Hasher size ",rh.Size())
	const uintSize = 8 // min bytes length to store uint64
	nounce := make([]byte, uintSize)
	fmt.Fprintln(os.Stderr, "### nounce ",nounce)
	return hasher{new(sync.Mutex), rh, rh.Size(),nounce }
}

// Compute calculates a hash of given data.
// Returned value is not thread safe and will be overwritten on next Compute call.
// The destination should be a slice of at least OutputLen length.
func (h hasher) ComputeBlockProof(headerH common.Hash, nonce uint64, dest []byte) error {
	h.rh.Reset()
	h.rh.Write(headerH[:])
	binary.LittleEndian.PutUint64(h.nonce, nonce)
	h.rh.Write(h.nonce)
	if h.OutputLen > len(dest){
		fmt.Fprintln(os.Stderr, "|||||len of outputLen is bigger then len of dest array")
	}
	_, err := h.rh.Read(dest[:h.OutputLen])
	return err
}

// Write computes digest given data. As other methods, this one is not thread safe.
// Subsequen writes will reset the previous states.
func (h hasher) Write(data []byte) (int, error) {
	h.rh.Reset()
	return h.rh.Write(data)
}

// Read sums current state into the given destination
func (h hasher) Read(dest []byte) {
	h.rh.Read(dest)
}

func (h hasher) Hash(data, dest []byte) {
	h.Write(data)
	h.Read(dest)
}

// newPoKWHasher creates an optimized, multi-use, not thread safe hasher.
// If you want to use this structure for the same hashing in PoW as for signatures,
// make sure that wallet is using same hashing algorithm (geth wallets usually hash
// messages internally before signing).
func newPoKWHasher() hasher {
	// TODO: use New256 instead of Keccak256 - but the signerFn interface hides the hash function.
	// so we can't do it here unless we expose other functions of the wallet.
	lock.Lock()
    defer lock.Unlock()
	return newHasher(sha3.NewLegacyKeccak256())
}

// HashToBig converts a hash into a big.Int that can be used to
// perform math comparisons. A Hash is in little-endian, but the big package
// wants the bytes in big-endian, so reverse them.
// It modifies the @hash layout.
func HashToBig(hash []byte) *big.Int {
	blen := len(hash)
	for i := 0; i < blen/2; i++ {
		hash[i], hash[blen-1-i] = hash[blen-1-i], hash[i]
	}

	return new(big.Int).SetBytes(hash[:])
}
