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

package harness

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testModulus = uint64(0x3ee0001)

func TestGenerateDataset(t *testing.T) {
	t.Parallel()

	t.Run("values_in_range", func(t *testing.T) {
		t.Parallel()
		ds := GenerateDataset(1000, 42, testModulus)
		if ds.N != 1000 {
			t.Errorf("N = %d, want 1000", ds.N)
		}
		if len(ds.Values) != 1000 {
			t.Errorf("len(Values) = %d, want 1000", len(ds.Values))
		}
		for i, v := range ds.Values {
			if v < 1 || v > 1000 {
				t.Errorf("Values[%d] = %d outside [1, 1000]", i, v)
			}
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		a := GenerateDataset(200, 42, testModulus)
		b := GenerateDataset(200, 42, testModulus)
		for i := range a.Values {
			if a.Values[i] != b.Values[i] {
				t.Fatalf("Values[%d] differ (%d vs %d): not deterministic", i, a.Values[i], b.Values[i])
			}
		}
		if a.ExpectedSum != b.ExpectedSum {
			t.Errorf("ExpectedSum not deterministic: %d vs %d", a.ExpectedSum, b.ExpectedSum)
		}
	})

	t.Run("different_seeds_produce_different_values", func(t *testing.T) {
		t.Parallel()
		a := GenerateDataset(100, 42, testModulus)
		b := GenerateDataset(100, 99, testModulus)
		allSame := true
		for i := range a.Values {
			if a.Values[i] != b.Values[i] {
				allSame = false
				break
			}
		}
		if allSame {
			t.Error("different seeds produced identical values")
		}
	})

	t.Run("expected_sum_matches_manual_computation", func(t *testing.T) {
		t.Parallel()
		ds := GenerateDataset(50, 7, testModulus)
		var want uint64
		for _, v := range ds.Values {
			want = (want + v) % testModulus
		}
		if ds.ExpectedSum != want {
			t.Errorf("ExpectedSum = %d, want %d", ds.ExpectedSum, want)
		}
	})

	t.Run("n_zero", func(t *testing.T) {
		t.Parallel()
		ds := GenerateDataset(0, 42, testModulus)
		if ds.N != 0 {
			t.Errorf("N = %d, want 0", ds.N)
		}
		if len(ds.Values) != 0 {
			t.Errorf("len(Values) = %d, want 0", len(ds.Values))
		}
		if ds.ExpectedSum != 0 {
			t.Errorf("ExpectedSum = %d, want 0", ds.ExpectedSum)
		}
	})

	t.Run("plaintext_modulus_stored", func(t *testing.T) {
		t.Parallel()
		ds := GenerateDataset(10, 1, testModulus)
		if ds.PlaintextModulus != testModulus {
			t.Errorf("PlaintextModulus = %d, want %d", ds.PlaintextModulus, testModulus)
		}
	})

	t.Run("n_matches_len_values", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{1, 7, 512, 1000} {
			ds := GenerateDataset(n, 42, testModulus)
			if ds.N != n || len(ds.Values) != n {
				t.Errorf("n=%d: N=%d, len(Values)=%d", n, ds.N, len(ds.Values))
			}
		}
	})
}

func TestRun(t *testing.T) {
	t.Parallel()

	t.Run("name_preserved", func(t *testing.T) {
		t.Parallel()
		p := Run("my-phase", func() {})
		if p.Name != "my-phase" {
			t.Errorf("Name = %q, want %q", p.Name, "my-phase")
		}
	})

	t.Run("elapsed_non_negative", func(t *testing.T) {
		t.Parallel()
		p := Run("noop", func() {})
		if p.Elapsed < 0 {
			t.Errorf("Elapsed = %v, want >= 0", p.Elapsed)
		}
	})

	t.Run("elapsed_captures_work", func(t *testing.T) {
		t.Parallel()
		p := Run("sleep", func() { time.Sleep(5 * time.Millisecond) })
		if p.Elapsed < 1*time.Millisecond {
			t.Errorf("Elapsed = %v after 5ms sleep, expected > 1ms", p.Elapsed)
		}
	})
}

func TestBenchmarkRunTotalMs(t *testing.T) {
	t.Parallel()

	t.Run("empty_phases", func(t *testing.T) {
		t.Parallel()
		r := BenchmarkRun{}
		if got := r.TotalMs(); got != 0 {
			t.Errorf("TotalMs() = %f, want 0", got)
		}
	})

	t.Run("single_phase", func(t *testing.T) {
		t.Parallel()
		r := BenchmarkRun{
			Phases: []PhaseResult{{Name: "p1", Elapsed: 500 * time.Millisecond}},
		}
		if got := r.TotalMs(); got != 500.0 {
			t.Errorf("TotalMs() = %f, want 500.0", got)
		}
	})

	t.Run("multiple_phases_sum", func(t *testing.T) {
		t.Parallel()
		r := BenchmarkRun{
			Phases: []PhaseResult{
				{Name: "p1", Elapsed: 100 * time.Millisecond},
				{Name: "p2", Elapsed: 200 * time.Millisecond},
				{Name: "p3", Elapsed: 300 * time.Millisecond},
			},
		}
		if got := r.TotalMs(); got != 600.0 {
			t.Errorf("TotalMs() = %f, want 600.0", got)
		}
	})
}

func TestAppendCSV(t *testing.T) {
	t.Parallel()

	makeRun := func(id int) BenchmarkRun {
		return BenchmarkRun{
			UseCase: "UC1",
			Variant: "std",
			DBLabel: "DB1",
			N:       512,
			RunID:   id,
			Phases: []PhaseResult{
				{Name: "encrypt", Elapsed: 10 * time.Millisecond, HeapB: 1024},
				{Name: "decrypt", Elapsed: 5 * time.Millisecond, HeapB: 512},
			},
			CommBytes: 1680,
			Rounds:    1,
			Correct:   true,
		}
	}

	t.Run("creates_file_with_header", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "out.csv")
		if err := AppendCSV(path, []BenchmarkRun{makeRun(1)}); err != nil {
			t.Fatalf("AppendCSV: %v", err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer f.Close()
		rows, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatalf("csv.ReadAll: %v", err)
		}
		// 1 header + 2 phase rows
		if len(rows) != 3 {
			t.Errorf("rows = %d, want 3 (header + 2 phases)", len(rows))
		}
		if rows[0][0] != "use_case" {
			t.Errorf("header[0] = %q, want %q", rows[0][0], "use_case")
		}
	})

	t.Run("creates_parent_directories", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "a", "b", "c", "out.csv")
		if err := AppendCSV(path, []BenchmarkRun{makeRun(1)}); err != nil {
			t.Fatalf("AppendCSV: %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file not found after AppendCSV: %v", err)
		}
	})

	t.Run("no_duplicate_header_on_second_append", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "out.csv")
		if err := AppendCSV(path, []BenchmarkRun{makeRun(1)}); err != nil {
			t.Fatalf("first AppendCSV: %v", err)
		}
		if err := AppendCSV(path, []BenchmarkRun{makeRun(2)}); err != nil {
			t.Fatalf("second AppendCSV: %v", err)
		}
		f, _ := os.Open(path)
		defer f.Close()
		rows, _ := csv.NewReader(f).ReadAll()
		// 1 header + (2 phases × 2 runs) = 5 rows
		if len(rows) != 5 {
			t.Errorf("rows = %d, want 5", len(rows))
		}
		headerCount := 0
		for _, row := range rows {
			if len(row) > 0 && row[0] == "use_case" {
				headerCount++
			}
		}
		if headerCount != 1 {
			t.Errorf("header appears %d times, want 1", headerCount)
		}
	})

	t.Run("decrypt_phase_carries_comm_fields", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "out.csv")
		if err := AppendCSV(path, []BenchmarkRun{makeRun(1)}); err != nil {
			t.Fatalf("AppendCSV: %v", err)
		}
		f, _ := os.Open(path)
		defer f.Close()
		rows, _ := csv.NewReader(f).ReadAll()
		// rows[0]=header, rows[1]=encrypt, rows[2]=decrypt
		decRow := rows[2]
		if decRow[5] != "decrypt" {
			t.Fatalf("phase = %q, want decrypt", decRow[5])
		}
		if decRow[8] != "1680" {
			t.Errorf("comm_bytes = %q, want 1680", decRow[8])
		}
		if decRow[9] != "1" {
			t.Errorf("rounds = %q, want 1", decRow[9])
		}
		if decRow[10] != "true" {
			t.Errorf("correct = %q, want true", decRow[10])
		}
	})

	t.Run("non_decrypt_phase_has_zero_comm", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "out.csv")
		if err := AppendCSV(path, []BenchmarkRun{makeRun(1)}); err != nil {
			t.Fatalf("AppendCSV: %v", err)
		}
		f, _ := os.Open(path)
		defer f.Close()
		rows, _ := csv.NewReader(f).ReadAll()
		encRow := rows[1] // encrypt phase
		if encRow[5] != "encrypt" {
			t.Fatalf("phase = %q, want encrypt", encRow[5])
		}
		if encRow[8] != "0" {
			t.Errorf("encrypt comm_bytes = %q, want 0", encRow[8])
		}
		if encRow[9] != "0" {
			t.Errorf("encrypt rounds = %q, want 0", encRow[9])
		}
		if encRow[10] != "false" {
			t.Errorf("encrypt correct = %q, want false", encRow[10])
		}
	})

	t.Run("empty_runs_slice", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "out.csv")
		if err := AppendCSV(path, nil); err != nil {
			t.Fatalf("AppendCSV with nil: %v", err)
		}
		// File should exist and have only header
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("file not created: %v", err)
		}
		defer f.Close()
		rows, _ := csv.NewReader(f).ReadAll()
		if len(rows) != 1 {
			t.Errorf("rows = %d, want 1 (just header)", len(rows))
		}
	})
}
