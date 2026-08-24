package panel

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/InazumaV/V2bX/conf"
)

func TestParseTLSMaxVersion(t *testing.T) {
	v, err := parseTLSMaxVersion("1.2")
	if err != nil || v != tls.VersionTLS12 {
		t.Fatalf("1.2: ver=%d err=%v", v, err)
	}
	v, err = parseTLSMaxVersion("")
	if err != nil || v != 0 {
		t.Fatalf("empty: ver=%d err=%v", v, err)
	}
	if _, err := parseTLSMaxVersion("1.1"); err == nil {
		t.Fatal("expected error for 1.1")
	}
}

func TestNew_TLSMaxVersion12(t *testing.T) {
	c, err := New(&conf.ApiConfig{
		APIHost:       "https://panel.example.com",
		Key:           "token",
		NodeType:      "anytls",
		NodeID:        223,
		TlsMaxVersion: "1.2",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr, ok := c.client.GetClient().Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MaxVersion != tls.VersionTLS12 {
		t.Fatalf("TLS MaxVersion: %+v", tr.TLSClientConfig)
	}
	if tr.ForceAttemptHTTP2 || tr.DisableKeepAlives != true {
		t.Fatalf("expected HTTP/1.1 without keep-alive, ForceAttemptHTTP2=%v DisableKeepAlives=%v", tr.ForceAttemptHTTP2, tr.DisableKeepAlives)
	}
}
