package walletapi

// R29 wallet-glue (B144): the walletapi copy of FormatMoneyPrecision computed the quotient at big.Float's default
// 64-bit precision, so large amounts printed wrong digits past the 5th decimal (the R28 globals defect, GG28-1). The
// copy now uses the globals implementation; these tests compare it with exact integer arithmetic.

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/deroproject/derohe/globals"
)

// exact_money is amount/100000 printed with precision >= 5 decimals, from integer arithmetic only
func exact_money(amount uint64, precision int) string {
	s := fmt.Sprintf("%d.%05d", amount/100000, amount%100000)
	return s + strings.Repeat("0", precision-5)
}

func TestR29WalletFormatMoneyExactAt12_8_5(t *testing.T) {
	r := rand.New(rand.NewSource(29))
	amounts := []uint64{0, 1, 99999, 100000, 1 << 40, 1 << 53, 1<<63 - 1, 1 << 63, ^uint64(0)}
	for i := 0; i < 20000; i++ {
		amounts = append(amounts, r.Uint64()>>uint(r.Intn(25)))
	}
	bad := 0
	for _, a := range amounts {
		for _, p := range []int{12, 8, 5} {
			if got, want := FormatMoneyPrecision(a, p), exact_money(a, p); got != want {
				if bad < 5 {
					t.Errorf("FormatMoneyPrecision(%d, %d) = %s, want %s", a, p, got, want)
				}
				bad++
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d (amount, precision) pairs wrong", bad, 3*len(amounts))
	}
}

func TestR29WalletFormatMoneyEqualsGlobals(t *testing.T) {
	r := rand.New(rand.NewSource(291))
	for i := 0; i < 5000; i++ {
		a := r.Uint64() >> uint(r.Intn(30))
		for _, p := range []int{0, 1, 2, 3, 4, 5, 8, 12} {
			if got, want := FormatMoneyPrecision(a, p), globals.FormatMoneyPrecision(a, p); got != want {
				t.Fatalf("walletapi %s != globals %s (amount %d, precision %d)", got, want, a, p)
			}
		}
	}
	if FormatMoney(123456789) != "1234.56789" {
		t.Fatalf("FormatMoney(123456789) = %s", FormatMoney(123456789))
	}
}
