package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	log15 "github.com/ethereum/go-ethereum/log"
)

var ()

var logger = log15.New()

const extraPrefix = 32 + 1 // `1` is for vote

func main() {
	logger.SetHandler(
		log15.LvlFilterHandler(log15.LvlDebug,
			log15.StreamHandler(os.Stdout, log15.TerminalFormat(true))))

	flag.Parse()

	// the addresses can be optionally prefixed with "0x"
	var addrStrs = []string{
		"0afca9ebd5cd5183e613ce681c34cc0a46656d95",
		"1aa173e9f8c063b54a2c1c587b1a70c0794f0499",
		"2e79dce3f60d40650dd4250e6fbc83c4aa1de247",
		"6f5fbe71bde511f81f3a3b9cd1bbede057816441",
		"a83a68e3088fb1667a380bf518b52448465fcf63",
		"be19524f32b8443cc4f3681852d8dfd547321649",
		"f5d305798fe7c6cae83ac154b4e2bb2fc2b460ac",
	}
	fmt.Println("extraData:", createExtraData(addrStrs))
}

func createExtraData(addrs []string) string {
	addrs = normalize(addrs)
	// we multiple by 2 because 1 byte is encoded using 2hex
	var extra = []string{"0x", strings.Repeat("0", 2*extraPrefix)}
	extra = append(extra, addrs...)
	return strings.Join(extra, "")
}

// normalize asserts that all addresses are valid and removes 0x prefix if needed
func normalize(ads []string) []string {
	var out = make([]string, len(ads))
	var ok = true
	for i, s := range ads {
		if !common.IsHexAddress(s) {
			ok = false
			logger.Error("Found invalid address", "addr_index", i, "value", s)
		} else {
			out[i] = remove0x(s)
		}
	}
	if !ok {
		logger.Crit("to continue fix invalid addresses")
	}
	return out
}

func remove0x(s string) string {
	return strings.TrimPrefix(s, "0x")
}
