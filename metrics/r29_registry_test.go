package metrics

// r29 (live-observability, dero-rft §7 B176): a family that writes its own "# HELP" but no "# TYPE" (live r28:
// dero_tip_age_seconds, cmd/derod/rpc/node_metrics.go) gets the registry TYPE before its first sample; a family with
// its own TYPE is never typed twice, and a vmhistogram is never typed.

import (
	"bytes"
	"strings"
	"testing"
)

var r29_reg = map[string]Family{
	"tip_age":  {Name: "tip_age", Type: "gauge", Help: "registry help"},
	"own_both": {Name: "own_both", Type: "gauge", Help: "registry help"},
	"vm_sec":   {Name: "vm_sec", Type: "vmhistogram", Help: "vm histogram"},
}

const r29_in = `# HELP tip_age written by the code
tip_age 3.5
# HELP own_both written by the code
# TYPE own_both gauge
own_both 1
# HELP vm_sec written by the code
vm_sec_bucket{vmrange="1.0e0...1.2e0"} 1
`

func TestR29OwnHelpWithoutTypeGetsRegistryType(t *testing.T) {
	var out bytes.Buffer
	annotate(&out, r29_reg, []byte(r29_in))
	got := out.String()
	if strip_comments(got) != strip_comments(r29_in) {
		t.Fatalf("sample lines changed:\n%s", got)
	}
	if !strings.Contains(got, "# HELP tip_age written by the code\n# TYPE tip_age gauge\ntip_age 3.5\n") {
		t.Fatalf("tip_age: no TYPE before its first sample:\n%s", got)
	}
	for fam, want := range map[string]int{"tip_age": 1, "own_both": 1, "vm_sec": 0} {
		if c := strings.Count(got, "# TYPE "+fam+" "); c != want {
			t.Fatalf("%s: %d TYPE lines, want %d:\n%s", fam, c, want, got)
		}
		if c := strings.Count(got, "# HELP "+fam+" "); c != 1 {
			t.Fatalf("%s: %d HELP lines:\n%s", fam, c, got)
		}
	}
}

// TestR29EveryTypedFamilyHasTypeOnThePage: on the annotated exposition of this binary's own registry, every family
// whose registry type has a Prometheus TYPE word and that has samples carries exactly one TYPE line before them.
func TestR29EveryTypedFamilyHasTypeOnThePage(t *testing.T) {
	text := `# HELP dero_tip_age_seconds wall clock minus the tip block's timestamp; GetInfo cannot show lag
dero_tip_age_seconds 1.250
`
	var out bytes.Buffer
	annotate(&out, registry, []byte(text))
	if f, ok := registry["dero_tip_age_seconds"]; !ok || f.Type != "gauge" {
		t.Fatalf("registry entry %+v", f)
	}
	if c := strings.Count(out.String(), "# TYPE dero_tip_age_seconds gauge\n"); c != 1 {
		t.Fatalf("%d TYPE lines for dero_tip_age_seconds:\n%s", c, out.String())
	}
}
