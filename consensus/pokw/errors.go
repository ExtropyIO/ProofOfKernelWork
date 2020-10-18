package pokw

import (
	"errors"
	"fmt"
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	errMissingVote      = errors.New("extra-data must be 33bytes: 32 vanity + voting byte")
	errMissingSignature = errors.New("header.sig must be defined")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	errInvalidVote     = errors.New("wrong vote: must be 0 or 1")
	errExtraSignersLen = errors.New("checkpoint block has wrong length of whitelist: must be between 1 and confg.pokw.maxWhitelist")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is not positive.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errInvalidBlockNumber is returned if the block height is out of the scope
	errInvalidBlockNumber = errors.New("invalid block number")

	// ErrNotInCommittee is returned when miner can't mine the block because the
	// lottery didn't selected him.
	ErrNotInCommittee = errors.New("miner not selected for the committee")
	errNoCommitteeTx  = errors.New("non-committee blocks must not contain any transactions")

	errInvalidMixDigest = errors.New("mix digest should be empty")

	errInvalidPoW  = errors.New("invalid proof-of-work(pokw)")
	errInvalidSeed = errors.New("invalid seed")
)

func wrapErr(msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(msg+" [%w]", err)
}
