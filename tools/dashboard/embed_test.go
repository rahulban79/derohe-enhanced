package dashboard

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// the page must stay self-contained: no script/style/font/image from anywhere, and it polls only same-origin "metrics"
func TestDashboardSelfContained(t *testing.T) {
	page := string(HTML)
	if ext := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`).FindString(page); ext != "" {
		t.Fatalf("external reference in dashboard.html: %q", ext)
	}
	if strings.Contains(page, "@import") || strings.Contains(page, "url(http") {
		t.Fatal("external stylesheet reference")
	}
	if !strings.Contains(page, `fetch("metrics"`) {
		t.Fatal("page no longer polls same-origin metrics")
	}
	w := httptest.NewRecorder()
	Handler(w, httptest.NewRequest("GET", "/dashboard", nil))
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("CSP %q", csp)
	}
	if w.Body.Len() != len(HTML) || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatal("page not served")
	}
}
