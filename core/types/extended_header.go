package types

import (
	"fmt"
	"github.com/ethereum/go-ethereum/log"
)

const (
	signatureLength = 65
)

// A Signature is a 65 byte ECDSA signature in the [R || S || V] format where V is 0 or 1.
type Signature [signatureLength]byte

// Extended Header is a simple data container for storing extra data - that makes up part of the extended protocol
type ExtendedHeader [signatureLength]byte

func (eh ExtendedHeader) String() string {
	return fmt.Sprintf(`
[
	Signature:		%v
]
`, string(eh[:]))
	//, eh.Signature)
}

func (b *Block) ExtendedHeader() ExtendedHeader            { return b.header.ExtendedHeader }

// SetExtendedHeader converts a byte slice to a ExtendedHeade.
// It panics if b is not of suitable size.
func (h *Header) SetExtendedHeader(sig []byte) {
	log.Debug("GOVERNED: HEADER BEFORE ADDING THE EXTENDED HEADER", "header", h.String())
	if len(sig) != signatureLength {
		panic(fmt.Sprintf("The signature to be used in the Extended Header is not the correct size: expected %d; got %d", signatureLength, len(sig)))
	}

	copy(h.ExtendedHeader[:], sig[:])
	log.Debug("GOVERNED: HEADER AFTER ADDING THE EXTENDED HEADER", "header", h.String())
}