package web

import (
	"strings"
	"testing"
)

func TestScriptHashes(t *testing.T) {
	page := `<script id="app-config" type="application/json">{}</script><script>a()</script><script src="/x.js"></script><script>
b()
</script>`
	hashes := scriptHashes(page)
	// sha256("a()") in base64
	if len(hashes) != 2 || hashes[0] != "'sha256-qVpDBgj7bpq5hMAcGp3AOc79J3Y1Z4HvySTwKrWDoy4='" {
		t.Fatalf("%v", hashes)
	}
	if !strings.HasPrefix(hashes[1], "'sha256-") {
		t.Fatal(hashes[1])
	}
}
