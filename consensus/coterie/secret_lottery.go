package coterie

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/common"
)

func partOfCurrentCoterie(header *types.Header, signer common.Address) (bool, error) {
	// TODO implement the correct logic
	return true, nil
}