package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestTrustedSourcePublicIPv4RequiresAgreement(t *testing.T) {
	server := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
	}
	a := server("192.0.2.8\n")
	b := server("192.0.2.8\n")
	defer a.Close()
	defer b.Close()
	m := &trustedSourceManager{ipv4URLs: []string{a.URL, b.URL}, httpClient: a.Client()}
	got, err := m.discoverPublicIPv4(context.Background())
	if err != nil || !slices.Equal(got, []string{"192.0.2.8/32"}) {
		t.Fatalf("discover = %v, %v", got, err)
	}

	c := server("198.51.100.9\n")
	defer c.Close()
	m.ipv4URLs = []string{a.URL, c.URL}
	if _, err := m.discoverPublicIPv4(context.Background()); err == nil {
		t.Fatal("disagreeing reflectors were accepted")
	}
}

func TestTrustedSourceDNSLeaseExpires(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	m := &trustedSourceManager{
		leases: make(map[string]trustedSourceLease), grace: 5 * time.Minute,
		now: func() time.Time { return now },
		lookupIP: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("198.51.100.7"), net.ParseIP("2001:db8::7")}, nil
		},
	}
	ranges, err := m.resolveName(context.Background(), "dynamic.example")
	if err != nil {
		t.Fatal(err)
	}
	m.update("dns:dynamic.example", ranges, nil)
	if got := m.Snapshot(); !slices.Equal(got, []string{"198.51.100.7/32", "2001:db8::7/128"}) {
		t.Fatalf("snapshot = %v", got)
	}
	now = now.Add(5 * time.Minute)
	if got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("expired snapshot = %v", got)
	}
}
