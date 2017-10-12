package miner

import (
"os"
"io/ioutil"
"strings"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/crypto/authentication"
)

const PASSWORD_FILE_NAME string = "coinbasepwd"

func (self *Miner) SetAuthentication(auth string) {
	if auth == "" {
		return
	}
	pwdFilePath := auth + string(os.PathSeparator) + PASSWORD_FILE_NAME
	coinbasePwd, err := readPasswordFromFile(pwdFilePath)

	if coinbasePwd == "" || err != nil {
		self.worker.coinbasePwd = auth
	} else {
		self.worker.coinbasePwd = coinbasePwd
	}
}

func (self *Miner) GetAuthentication() (auth string) {
	return self.worker.coinbasePwd
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

func (self *Miner) InstantiateAuthorisedMinersWhitelist(contractBackend bind.ContractBackend) error {
	if whitelist, err := authentication.NewAuthorisedMinersWhitelist(contractBackend); err != nil {
		return err
	} else {
		self.worker.chain.SetAuthenticatedMinersWhitelist(whitelist)
		return nil
	}
}