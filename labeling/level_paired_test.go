package labeling

import (
	"testing"
)

// TestMultKeepLevel verifies that MultKeepLevel produces the same plaintext product as
// Mult but keeps β at the inputs' level (MaxLevel) instead of forcing level=1, and that
// rescaling the kept-level result back to level=1 reproduces the value at level=1. This is
// the core of the fixed-level honest comparison (spec 013).
func TestMultKeepLevel(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()
	maxLevel := params.MaxLevel()
	if maxLevel < 2 {
		t.Fatalf("test requires MaxLevel >= 2, got %d", maxLevel)
	}

	t.Run("KeepsMaxLevelAndValue", func(t *testing.T) {
		cases := []struct {
			name   string
			v1, v2 uint64
			want   uint64
		}{
			{name: "3x4=12", v1: 3, v2: 4, want: 12},
			{name: "7x8=56", v1: 7, v2: 8, want: 56},
			{name: "(PT-1)x2", v1: pt - 1, v2: 2, want: (pt - 1) * 2 % pt},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 2)
				lct1, err := EncryptLabeled(ctx, fillSlots(params, tc.v1))
				if err != nil {
					t.Fatalf("EncryptLabeled lct1: %v", err)
				}
				lct2, err := EncryptLabeled(ctx, fillSlots(params, tc.v2))
				if err != nil {
					t.Fatalf("EncryptLabeled lct2: %v", err)
				}

				prod, err := MultLabeledKeepLevel(ctx, rlk, lct1, lct2)
				if err != nil {
					t.Fatalf("MultLabeledKeepLevel: %v", err)
				}

				if gotLevel := prod.elementsB[0][0].Level(); gotLevel != maxLevel {
					t.Errorf("β level: got %d, want MaxLevel %d", gotLevel, maxLevel)
				}
				if gotDegree := prod.elementsB[0][0].Degree(); gotDegree != 1 {
					t.Errorf("β degree: got %d, want 1 (rotate-and-sum requires degree 1)", gotDegree)
				}

				got := decryptThreshold(t, ctx, shares, prod)
				for i, v := range got {
					if v != tc.want {
						t.Fatalf("slot %d: got %d, want %d", i, v, tc.want)
					}
				}
			})
		}
	})

	t.Run("MultForcesLevel1_KeepLevelDoesNot", func(t *testing.T) {
		ctx, _, _, rlk := buildMHESetupWithRLK(t, params, 2)
		lct1, _ := EncryptLabeled(ctx, fillSlots(params, 3))
		lct2, _ := EncryptLabeled(ctx, fillSlots(params, 4))

		std, err := MultLabeled(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultLabeled: %v", err)
		}
		if got := std.elementsB[0][0].Level(); got != 1 {
			t.Errorf("Mult β level: got %d, want 1", got)
		}

		kept, err := MultLabeledKeepLevel(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultLabeledKeepLevel: %v", err)
		}
		if got := kept.elementsB[0][0].Level(); got != maxLevel {
			t.Errorf("MultKeepLevel β level: got %d, want %d", got, maxLevel)
		}
	})

	t.Run("KeepLevelThenRescaleEqualsLevel1", func(t *testing.T) {
		ctx, shares, _, rlk := buildMHESetupWithRLK(t, params, 2)
		lct1, _ := EncryptLabeled(ctx, fillSlots(params, 5))
		lct2, _ := EncryptLabeled(ctx, fillSlots(params, 6))

		kept, err := MultLabeledKeepLevel(ctx, rlk, lct1, lct2)
		if err != nil {
			t.Fatalf("MultLabeledKeepLevel: %v", err)
		}

		rescaled, err := RescaleToLevel(params, &kept.elementsB[0][0], 1)
		if err != nil {
			t.Fatalf("RescaleToLevel: %v", err)
		}
		if got := rescaled.Level(); got != 1 {
			t.Fatalf("rescaled β level: got %d, want 1", got)
		}
		kept.elementsB[0][0] = *rescaled

		got := decryptThreshold(t, ctx, shares, kept)
		for i, v := range got {
			if v != 30 {
				t.Fatalf("slot %d after rescale: got %d, want 30", i, v)
			}
		}
	})
}

// TestSumKeepLevel verifies that SumKeepLevel keeps β at the inputs' level (MaxLevel)
// while Sum forces level=1, both decrypting to the same plaintext sum. This lets a label
// rotate-and-sum run entirely at MaxLevel (spec 013).
func TestSumKeepLevel(t *testing.T) {
	params := testParameters(t)
	maxLevel := params.MaxLevel()
	if maxLevel < 2 {
		t.Fatalf("test requires MaxLevel >= 2, got %d", maxLevel)
	}

	ctx, shares, _ := buildMHETestSetup(t, params, 2)
	lct1, err := EncryptLabeled(ctx, fillSlots(params, 11))
	if err != nil {
		t.Fatalf("EncryptLabeled lct1: %v", err)
	}
	lct2, err := EncryptLabeled(ctx, fillSlots(params, 31))
	if err != nil {
		t.Fatalf("EncryptLabeled lct2: %v", err)
	}

	std, err := SumLabeled(ctx, lct1, lct2)
	if err != nil {
		t.Fatalf("SumLabeled: %v", err)
	}
	if got := std.elementsB[0][0].Level(); got != 1 {
		t.Errorf("Sum β level: got %d, want 1", got)
	}

	kept, err := SumLabeledKeepLevel(ctx, lct1, lct2)
	if err != nil {
		t.Fatalf("SumLabeledKeepLevel: %v", err)
	}
	if got := kept.elementsB[0][0].Level(); got != maxLevel {
		t.Errorf("SumKeepLevel β level: got %d, want %d", got, maxLevel)
	}

	got := decryptThreshold(t, ctx, shares, kept)
	for i, v := range got {
		if v != 42 {
			t.Fatalf("slot %d: got %d, want 42", i, v)
		}
	}
}

// TestMultOverflowKeepLevel verifies that MultOverflowKeepLevel keeps α at the inputs'
// level (MaxLevel) while MultOverflow forces α to level=1, both decrypting to the same
// plaintext product (spec 013, UC4 fixed-level comparison).
func TestMultOverflowKeepLevel(t *testing.T) {
	params := testParameters(t)
	pt := params.PlaintextModulus()
	maxLevel := params.MaxLevel()
	if maxLevel < 2 {
		t.Fatalf("test requires MaxLevel >= 2, got %d", maxLevel)
	}

	cases := []struct {
		name   string
		m1, m2 uint64
		want   uint64
	}{
		{name: "3x4=12", m1: 3, m2: 4, want: 12},
		{name: "(PT-1)x2", m1: pt - 1, m2: 2, want: (pt - 1) * 2 % pt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _, skIdeal, _ := buildMHESetupWithRLK(t, params, 2)
			lct1, err := EncryptLabeled(ctx, fillSlots(params, tc.m1))
			if err != nil {
				t.Fatalf("EncryptLabeled lct1: %v", err)
			}
			lct2, err := EncryptLabeled(ctx, fillSlots(params, tc.m2))
			if err != nil {
				t.Fatalf("EncryptLabeled lct2: %v", err)
			}

			std, err := MultOverflowLabeledFree(ctx, lct1, lct2)
			if err != nil {
				t.Fatalf("MultOverflowLabeledFree: %v", err)
			}
			if got := AlphaLevel(std); got != 1 {
				t.Errorf("MultOverflow α level: got %d, want 1", got)
			}

			kept, err := MultOverflowLabeledFreeKeepLevel(ctx, lct1, lct2)
			if err != nil {
				t.Fatalf("MultOverflowLabeledFreeKeepLevel: %v", err)
			}
			if got := AlphaLevel(kept); got != maxLevel {
				t.Errorf("MultOverflowKeepLevel α level: got %d, want %d", got, maxLevel)
			}

			got := decryptOverflowOracle(t, params, skIdeal, kept)
			for i, v := range got {
				if v != tc.want {
					t.Fatalf("slot %d: got %d, want %d", i, v, tc.want)
				}
			}
		})
	}
}
