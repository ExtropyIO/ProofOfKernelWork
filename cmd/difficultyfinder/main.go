// This package benchmarks the mining algorithm and looks for the optimal difficulty set
// on given machine and expected mining time.
// Algorithm will iteratively increase / decrease the difficulty and run the mining puzzle
// @rounds amount of time. To find right defaults, set @rounds at least 10.
// Example use:
//   go run main.go -expected-duration 1000ms -starting-difficulty 16 -rounds 12
package main

import (
	"flag"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/pokw"
	"github.com/ethereum/go-ethereum/crypto"
	log15 "github.com/ethereum/go-ethereum/log"
)

var (
	expectedD = flag.Duration("expected-duration", 0, "Expected mining time [required]")
	startingD = flag.Int64("starting-difficulty", 0, "Starting difficulty [required]")
	rounds    = flag.Int("rounds", 16, "Number of rounds the algorithm will run to average the mining time")
	threads   = flag.Int("threads", 0, "Number of miner workers to run. 0 = amount of physical CPU threads")
)

var logger = log15.New()

func main() {
	logger.SetHandler(
		log15.LvlFilterHandler(log15.LvlDebug,
			log15.StreamHandler(os.Stdout, log15.TerminalFormat(true))))

	flag.Parse()
	if *expectedD <= 0 || *startingD <= 0 {
		logger.Crit("-expected-duration and -starting-difficulty runtime parameters are required and must be a positive integer")
	}
	if *threads < 0 {
		logger.Warn("mining disabled - amount of threads must be not negative to start mining (0=amount of CPU threads)")
		return
	}

	logger.Info("Parameters info", "expected-duration", *expectedD)

	var eh = pokw.NewMiner(pokw.MinerConfig{Log: logger}, nil, *threads, nil, false)
	var r = NewRunner(eh, *expectedD, uint64(*startingD))
	r.search(*rounds)

}

func generateRandomHash() common.Hash {
	var h common.Hash
	for i := 0; i < len(h); i++ {
		h[i] = byte(rand.Int31())
	}
	return h
}

type runner struct {
	eh       *pokw.Miner
	expected time.Duration
	seed     common.Hash
	dif      uint64
	// optimizatoin to stop mining when the attempt passes this treshold
	maxDuration time.Duration
}

// NewRunner initializes runner instance
func NewRunner(eh *pokw.Miner, expected time.Duration, startDifficulty uint64) runner {
	return runner{eh, expected, generateRandomHash(), startDifficulty, 0}
}

func (r runner) search(rounds int) {
	r.maxDuration = time.Duration(math.Round(float64(r.expected) * 1.3))
	var positiveMargin = time.Duration(math.Round(float64(r.expected) * 1.25))
	logger.Info("Setting mining tresholds",
		"max_duration", r.maxDuration, "positive_margin", positiveMargin)

	var prev, duration time.Duration
	for i := 0; ; i++ {
		prev, duration = duration, r.mine(i, rounds)
		logger.Debug("in main loop", "iter", i, "avg_duration", duration, "difficulty", r.dif)
		if duration > r.expected {
			if duration < positiveMargin || prev < r.expected {
				break
			}
			r.dif--
		} else {
			r.dif++
		}
	}
	logger.Info("FINISHED", "difficulty", r.dif)
}

func (r runner) mine(id, rounds int) time.Duration {
	start := time.Now()
	for i := 0; i < rounds; i++ {
		r.nextParams()
		stop := make(chan struct{})
		deadline := time.NewTicker(r.maxDuration)
		go func() {
			_, ok := r.eh.Mine(r.nextParams(), stop)
			if ok {
				close(stop)
			}
		}()
		select {
		case <-deadline.C:
			close(stop)
		case <-stop:
			deadline.Stop()
		}
	}
	duration := time.Since(start)
	return time.Duration(int(duration) / rounds)
}

func (r *runner) nextParams() pokw.MiningParams {
	r.seed = crypto.Keccak256Hash(r.seed[:])

	return pokw.MiningParams{
		HeaderH:    r.seed,
		Difficulty: r.dif}
}
