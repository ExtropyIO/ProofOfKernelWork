package pokw

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckTreshold(t *testing.T) {
	type TC struct {
		input    []byte
		expected bool
	}
	var testCases = []TC{
		TC{[]byte{0}, false},
		TC{[]byte{255}, false},
		TC{bytes.Repeat([]byte{1}, 32), false},
		TC{bytes.Repeat([]byte{120}, 32), false},
		TC{bytes.Repeat([]byte{180}, 32), true}, // 180 > 256 * 2 / 3
		TC{bytes.Repeat([]byte{255}, 32), true},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("testcase: %x", tc.input), func(t *testing.T) {
			o := checkTreshold(tc.input, 2, 3)
			assert.Equal(t, tc.expected, o)
		})
	}
}

func TestSigToDifficulty(t *testing.T) {
	type TC struct {
		input    []byte
		expected uint64
	}
	var testCases = []TC{
		TC{[]byte{0}, 65536}, // 1 << 16
		TC{[]byte{0}, minDifficulty},
		TC{[]byte{1, 0, 0, 0, 0}, minDifficulty + 1},
		TC{[]byte{1, 0, 1, 0, 0}, minDifficulty + 1},
		TC{[]byte{0, 10}, 10<<8 + minDifficulty},
		TC{[]byte{255, 255}, powDifficulty - 1},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("testcase: %x", tc.input), func(t *testing.T) {
			o := sigToDifficulty(tc.input)
			assert.Equal(t, tc.expected, o)
		})
	}
}
