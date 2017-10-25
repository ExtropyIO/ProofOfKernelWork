package coterie

import (
	"os"
	"io/ioutil"
	"strings"
	"github.com/ethereum/go-ethereum/core/types"
	"errors"
	"github.com/ethereum/go-ethereum/accounts"
)

const PASSWORD_FILE_NAME string = "coinbasepwd"

var (
	ErrIncorrectDataDir	= errors.New("invalid Ethereum data directory")
	ErrMissingHash		= errors.New("unable to authenticate a block with a missing parent hash")
)

func (c *Coterie) AuthoriseBlock(header *types.Header) (error) {
	c.lock.RLock()
	signer, signFn := c.signer, c.signFn
	c.lock.RUnlock()

	password, err := c.retrieveSignerUnlockingCredentials()
	if err != nil {
		return err
	}

	hashToBeSigned := retrieveHashToBeSigned(header)
	if hashToBeSigned == nil || len(hashToBeSigned) == 0 {
		return ErrMissingHash
	}

	if sig, err := signFn(accounts.Account{Address: signer}, password, hashToBeSigned); err != nil {
		return err
	} else {
		header.SetExtendedHeader(sig)
		return nil
	}
}

func (c *Coterie) retrieveSignerUnlockingCredentials() (string, error) {
	c.lock.RLock()
	dirLocFn := c.dirLocFun
	c.lock.RUnlock()

	dirLoc := dirLocFn()

	if dirLoc == "" {
		return "", ErrIncorrectDataDir
	}
	pwdFilePath := dirLoc + string(os.PathSeparator) + PASSWORD_FILE_NAME

	if coinbasePwd, err := readPasswordFromFile(pwdFilePath); err != nil {
		return "", err
	} else {
		return coinbasePwd, nil
	}
}

func readPasswordFromFile(filePath string) (string, error) {
	text, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	// Only expect that there will be one line / password in the file
	lines := strings.Split(string(text), "\n")
	return strings.TrimRight(lines[0], "\r"), nil
}

func retrieveHashToBeSigned(header *types.Header) []byte {
	return header.ParentHash[:]
}