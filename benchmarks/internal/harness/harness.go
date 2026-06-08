// Copyright 2025 Juan Martín Pérez
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package harness provides common utilities for the labeling benchmark suite:
// deterministic dataset generation, per-phase timing and memory measurement,
// and CSV export of BenchmarkRun results.
//
// All benchmark binaries in benchmarks/ use this package as their sole
// measurement point; they must not call time.Now() or runtime.ReadMemStats()
// directly.
package harness

import (
	"encoding/csv"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// Dataset holds synthetic integer values for one benchmark experiment and the
// expected sum modulo PlaintextModulus, precomputed for validation.
type Dataset struct {
	Values          []uint64
	N               int
	ExpectedSum     uint64
	PlaintextModulus uint64
}

// GenerateDataset creates a deterministic dataset of n values in [1, 1000]
// using the given seed. Two calls with the same arguments always return the
// same Dataset. ExpectedSum is computed with modular arithmetic to match BGV
// plaintext arithmetic.
func GenerateDataset(n int, seed int64, plaintextModulus uint64) Dataset {
	values := make([]uint64, n)
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0xdeadbeefcafe))
	var sum uint64
	for i := range values {
		v := rng.Uint64N(1000) + 1 // [1, 1000]
		values[i] = v
		sum = (sum + v) % plaintextModulus
	}
	return Dataset{
		Values:          values,
		N:               n,
		ExpectedSum:     sum,
		PlaintextModulus: plaintextModulus,
	}
}

// PhaseResult holds timing and net heap allocation for one benchmark phase.
// HeapB is the net bytes allocated during the phase (HeapAlloc after minus
// before); it can be negative if the GC ran during the phase.
type PhaseResult struct {
	Name    string
	Elapsed time.Duration
	HeapB   int64
}

// Run executes fn, measures elapsed wall time and net heap allocation, and
// returns a PhaseResult labeled name. runtime.GC() is called before measurement
// to reduce noise from prior allocations.
func Run(name string, fn func()) PhaseResult {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	fn()
	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	return PhaseResult{
		Name:    name,
		Elapsed: elapsed,
		HeapB:   int64(after.HeapAlloc) - int64(before.HeapAlloc),
	}
}

// BenchmarkRun holds all metrics for one complete benchmark experiment run.
type BenchmarkRun struct {
	UseCase      string        // "UC1", "UC2", "UC3"
	Variant      string        // "std", "label"
	DBLabel      string        // "DB1", "DB2", "DB3"
	N            int           // total number of records
	RunID        int           // 1-based repetition index
	Phases       []PhaseResult
	CommBytes    int64         // total bytes exchanged in threshold decryption (simulated)
	Rounds       int           // number of threshold decryption rounds
	Correct      bool
	ParamProfile string        // "full", "tight", "min" — "" for benchmarks without param sweep
}

// TotalMs returns the sum of all phase durations in milliseconds.
func (r BenchmarkRun) TotalMs() float64 {
	var total time.Duration
	for _, p := range r.Phases {
		total += p.Elapsed
	}
	return total.Seconds() * 1000
}

// csvHeader is the ordered list of column names written to CSV files.
var csvHeader = []string{
	"use_case", "variant", "db_label", "n", "run_id",
	"phase", "elapsed_ms", "heap_b",
	"comm_bytes", "rounds", "correct", "param_profile",
}

// AppendCSV appends runs to the CSV file at path, writing the header row if the
// file does not exist. Creates parent directories with os.MkdirAll if needed.
// Each run produces one row per phase.
func AppendCSV(path string, runs []BenchmarkRun) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	_, statErr := os.Stat(path)
	writeHeader := os.IsNotExist(statErr)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if writeHeader {
		if err := w.Write(csvHeader); err != nil {
			return err
		}
	}

	for _, run := range runs {
		for _, phase := range run.Phases {
			commBytes := int64(0)
			rounds := 0
			correct := false
			if phase.Name == "decrypt" {
				commBytes = run.CommBytes
				rounds = run.Rounds
				correct = run.Correct
			}
			row := []string{
				run.UseCase,
				run.Variant,
				run.DBLabel,
				strconv.Itoa(run.N),
				strconv.Itoa(run.RunID),
				phase.Name,
				strconv.FormatFloat(phase.Elapsed.Seconds()*1000, 'f', 3, 64),
				strconv.FormatInt(phase.HeapB, 10),
				strconv.FormatInt(commBytes, 10),
				strconv.Itoa(rounds),
				strconv.FormatBool(correct),
				run.ParamProfile,
			}
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}
	w.Flush()
	return w.Error()
}
