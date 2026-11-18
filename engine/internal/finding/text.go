package finding

import (
	"fmt"
	"time"
)

var frenchMonths = [...]string{"janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
	"septembre", "octobre", "novembre", "décembre"}

// FrenchDate writes a date the French way, "17 novembre 2026" (UTC), for
// the French text of findings.
func FrenchDate(t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("%d %s %d", t.Day(), frenchMonths[t.Month()-1], t.Year())
}

// Plural returns suffix when n is more than one ("s" in French and English
// for most words).
func Plural(n int, suffix string) string {
	if n > 1 {
		return suffix
	}
	return ""
}
