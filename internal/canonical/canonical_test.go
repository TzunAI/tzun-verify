package canonical

import (
	"math"
	"testing"
)

func TestFormatNumber(t *testing.T) {
	cases := map[float64]string{
		0: "0", math.Copysign(0, -1): "0", 1: "1", -1: "-1", 0.5: "0.5", 1e-6: "0.000001", 1e-7: "1e-7",
		1e20: "100000000000000000000", 1e21: "1e+21", 1.5e-7: "1.5e-7", 123456789012345680000: "123456789012345680000",
		0.30000000000000004: "0.30000000000000004", 5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308",
		9007199254740991: "9007199254740991", 123.456: "123.456", 1e300: "1e+300", 2.5e21: "2.5e+21",
	}
	for in, want := range cases {
		got, err := FormatNumber(in)
		if err != nil || got != want {
			t.Errorf("%v: %q, want %q", in, got, want)
		}
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := FormatNumber(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestLessUTF16(t *testing.T) {
	if !LessUTF16("\U0001F600", "！") || LessUTF16("！", "\U0001F600") {
		t.Errorf("an astral key sorts by its first code unit, 0xD83D")
	}
	if !LessUTF16("a", "ab") || LessUTF16("ab", "a") {
		t.Errorf("a proper prefix sorts first")
	}
}
