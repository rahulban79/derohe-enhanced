package metrics

// r28 (rpc-metrics, dero-rft §7 sweep gap "/metrics: 296 of 298 families carry no # HELP / # TYPE"): the metric
// registry. metric_registry.json (generated and checked by harness/intel/metric_registry.py) names every /metrics
// family derod exports with its type, unit, owning area and a help text. WritePrometheus now writes "# HELP" before
// the first sample of each registered family and "# TYPE" for the families whose samples follow the Prometheus type
// (counter, gauge, le-histogram, summary). VictoriaMetrics vmrange histograms get HELP only: their buckets are not
// Prometheus le-buckets, and a TYPE histogram line would make a strict parser refuse them. A family that already wrote
// its own metadata (KCP_*, dero_node_up, ...) keeps it: only a missing HELP (r29: or a missing TYPE) is added, never a
// second TYPE. Sample
// lines are copied byte for byte, so every reader that skips '#' lines reads exactly what it read before.
// DERO_METRICS_METADATA=0 turns the annotation off (the r27 exposition, byte for byte).

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"os"
	"strings"
)

//go:embed metric_registry.json
var registry_json []byte

// Family is one registry entry.
type Family struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Unit   string `json:"unit"`
	Area   string `json:"area"`
	Help   string `json:"help"`
	Source string `json:"source"`
}

var registry = func() map[string]Family {
	var r struct {
		Families []Family `json:"families"`
	}
	m := map[string]Family{}
	if err := json.Unmarshal(registry_json, &r); err != nil {
		return m // an unreadable registry annotates nothing; TestR28RegistryLoads fails the build's tests
	}
	for _, f := range r.Families {
		m[f.Name] = f
	}
	return m
}()

// Registry returns a copy of the registry (tests, tools).
func Registry() map[string]Family {
	out := make(map[string]Family, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}

// metadata_enabled: on unless DERO_METRICS_METADATA=0
func metadata_enabled() bool { return os.Getenv("DERO_METRICS_METADATA") != "0" }

// family_of maps a sample name to its registered family: the name itself, or for a histogram/summary sample
// (_bucket, _sum, _count) its base name. Pure on the registry.
func family_of(reg map[string]Family, sample string) (Family, bool) {
	if f, ok := reg[sample]; ok {
		return f, true
	}
	for _, suf := range []string{"_bucket", "_sum", "_count"} {
		if strings.HasSuffix(sample, suf) {
			if f, ok := reg[strings.TrimSuffix(sample, suf)]; ok && (f.Type == "histogram" || f.Type == "vmhistogram" || f.Type == "summary") {
				return f, true
			}
		}
	}
	return Family{}, false
}

// prom_type is the "# TYPE" word for a registry type, "" when no TYPE line is written (vmhistogram, untyped).
func prom_type(t string) string {
	switch t {
	case "counter", "gauge", "histogram", "summary":
		return t
	}
	return ""
}

// escape_help applies the text-format HELP escaping (backslash, newline).
func escape_help(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func sample_name(line string) string {
	i := strings.IndexAny(line, "{ ")
	if i < 0 {
		return line
	}
	return line[:i]
}

// annotate copies the exposition text to w with the registry's HELP/TYPE lines added. Pure on (reg, text).
func annotate(w io.Writer, reg map[string]Family, text []byte) (unregistered []string) {
	done := map[string]bool{}  // families whose HELP is written (or that brought their own)
	typed := map[string]bool{} // families whose TYPE is written (or that brought their own); r29 B176: a family with its
	// own HELP and no TYPE (dero_tip_age_seconds) gets the registry TYPE before its first sample
	seen_unreg := map[string]bool{}
	var out bytes.Buffer
	out.Grow(len(text) + len(text)/4)
	for len(text) > 0 {
		var line []byte
		if i := bytes.IndexByte(text, '\n'); i >= 0 {
			line, text = text[:i+1], text[i+1:]
		} else {
			line, text = text, nil
		}
		s := strings.TrimRight(string(line), "\n")
		switch {
		case strings.HasPrefix(s, "# HELP ") || strings.HasPrefix(s, "# TYPE "):
			fields := strings.Fields(s)
			if len(fields) >= 3 {
				if !done[fields[2]] {
					if f, ok := reg[fields[2]]; ok && strings.HasPrefix(s, "# TYPE ") {
						out.WriteString("# HELP " + f.Name + " " + escape_help(f.Help) + "\n")
					}
					done[fields[2]] = true
				}
				if strings.HasPrefix(s, "# TYPE ") {
					typed[fields[2]] = true
				}
			}
		case s == "" || s[0] == '#':
		default:
			name := sample_name(s)
			if f, ok := family_of(reg, name); ok {
				if !done[f.Name] {
					out.WriteString("# HELP " + f.Name + " " + escape_help(f.Help) + "\n")
					done[f.Name] = true
				}
				if !typed[f.Name] {
					if t := prom_type(f.Type); t != "" {
						out.WriteString("# TYPE " + f.Name + " " + t + "\n")
					}
					typed[f.Name] = true
				}
			} else if !seen_unreg[name] {
				seen_unreg[name] = true
				unregistered = append(unregistered, name)
			}
		}
		out.Write(line)
	}
	w.Write(out.Bytes())
	return
}

// WriteAnnotated writes an exposition with the registry's metadata (unless DERO_METRICS_METADATA=0) and returns the
// sample names no registry family covers (empty on a node whose registry is current).
func WriteAnnotated(w io.Writer, text []byte) []string {
	if !metadata_enabled() {
		w.Write(text)
		return nil
	}
	return annotate(w, registry, text)
}

// WritePrometheusRaw writes the exposition WritePrometheus serves, without the registry metadata (for a handler that
// appends its own block and annotates the whole page once).
func WritePrometheusRaw(w io.Writer) { writePrometheusMetrics(w) }
