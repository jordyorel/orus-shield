package account

import "testing"

func TestLangFrom(t *testing.T) {
	for h, want := range map[string]string{
		"en-GB,en;q=0.9,fr;q=0.8": "en",
		"en":                      "en",
		"fr-FR,fr;q=0.9":          "fr",
		"FR":                      "fr",
		"de-DE,en;q=0.5":          "", // only the first language counts
		"":                        "",
		"english":                 "",
	} {
		if got := langFrom(h); got != want {
			t.Errorf("langFrom(%q) = %q, want %q", h, got, want)
		}
	}
}
