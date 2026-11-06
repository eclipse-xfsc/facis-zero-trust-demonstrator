package main

import (
	"context"
	"io"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"
)

// loadResult is the outcome of one measured run.
type loadResult struct {
	Requests    int         `json:"requests"`
	Concurrency int         `json:"concurrency"`
	Statuses    map[int]int `json:"statuses"`
	Errors      int         `json:"errors"`
	P50Ms       float64     `json:"p50_ms"`
	P95Ms       float64     `json:"p95_ms"`
	P99Ms       float64     `json:"p99_ms"`
	MaxMs       float64     `json:"max_ms"`
}

// runLoad sends n requests built by newReq, at most concurrency in flight, and measures each
// from Do to the end of the body. A request that fails counts as an error and no duration.
func runLoad(ctx context.Context, client *http.Client, newReq func() (*http.Request, error), n, concurrency int) loadResult {
	res := loadResult{Requests: n, Concurrency: max(concurrency, 1), Statuses: map[int]int{}}
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		durations []time.Duration
		jobs      = make(chan struct{})
	)
	for range res.Concurrency {
		wg.Go(func() {
			for range jobs {
				req, err := newReq()
				if err != nil {
					mu.Lock()
					res.Errors++
					mu.Unlock()
					continue
				}
				start := time.Now()
				resp, err := client.Do(req.WithContext(ctx))
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				d := time.Since(start)
				mu.Lock()
				if err != nil {
					res.Errors++
				} else {
					res.Statuses[resp.StatusCode]++
					durations = append(durations, d)
				}
				mu.Unlock()
			}
		})
	}
	for range n {
		select {
		case jobs <- struct{}{}:
		case <-ctx.Done():
			n = 0
		}
		if n == 0 {
			break
		}
	}
	close(jobs)
	wg.Wait()
	p50, p95, p99, maxD := percentiles(durations)
	res.P50Ms, res.P95Ms, res.P99Ms, res.MaxMs = millis(p50), millis(p95), millis(p99), millis(maxD)
	return res
}

// percentiles returns the nearest-rank p50, p95, p99 and the maximum of d; zeros for no data.
func percentiles(d []time.Duration) (p50, p95, p99, maxD time.Duration) {
	if len(d) == 0 {
		return 0, 0, 0, 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	rank := func(p float64) time.Duration { return s[max(int(math.Ceil(p*float64(len(s))))-1, 0)] }
	return rank(0.50), rank(0.95), rank(0.99), s[len(s)-1]
}

// millis is d in milliseconds with microsecond precision.
func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
