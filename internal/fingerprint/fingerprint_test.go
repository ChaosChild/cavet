package fingerprint

import "testing"

func TestNormaliseMasksAndCollapses(t *testing.T) {
	src := []byte("line1\nquery = \"SELECT * FROM users WHERE id = 42\"\nline3\nline4\nline5")
	got, err := Normalise(src, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := "line1 query = «s» line3 line4 line5"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNormaliseContextWindowClamps(t *testing.T) {
	_, err := Normalise([]byte("x"), 0)
	if err == nil {
		t.Fatal("matchLine 0 must error")
	}
	got, err := Normalise([]byte("a"), 1)
	if err != nil || got != "a" {
		t.Fatalf(`got %q err %v`, got, err)
	}
}

func TestNormaliseCRLFAndInvalidUTF8(t *testing.T) {
	src := []byte{'a', 'b', '\r', '\n', 0xff, 'x'}
	got, err := Normalise(src, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ab \uFFFDx" {
		t.Fatalf("got %q", got)
	}
}

func TestOfMatchesKnownVector(t *testing.T) {
	// sha256("go" + \x00 + "ctx"), cross-checked against the platform SHA-256;
	// pins the byte layout of artefacts §5.
	want := "b8b212b890751fbd7f7688599fdf19c4c962b15009fc5e165c13624ecd07eb2a"
	if got := Of("go", "ctx"); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestKeysSeparateFields(t *testing.T) {
	if Of("ab", "") == Of("a", "b") {
		t.Fatal("Of must separate rule key from context")
	}
	if Secret("ab", "") == Secret("a", "b") {
		t.Fatal("Secret must separate span from path")
	}
	if RuleKey("CWE-89", "py.sql") != "CWE-89" || RuleKey("", "py.sql") != "py.sql" {
		t.Fatal("RuleKey must prefer CWE, fall back to rule id")
	}
}
