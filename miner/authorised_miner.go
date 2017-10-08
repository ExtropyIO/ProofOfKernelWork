package miner

import (
"os"
"io/ioutil"
"strings"
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