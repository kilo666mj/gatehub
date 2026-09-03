package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type trustedSourceLease struct {
	ranges    []string
	expiresAt time.Time
}

// trustedSourceManager discovers short-lived source bypasses. Failed refreshes
// retain the last good value only until its lease expires.
type trustedSourceManager struct {
	mu         sync.Mutex
	leases     map[string]trustedSourceLease
	ipv4URLs   []string
	dnsNames   []string
	ipv6Bits   int
	refresh    time.Duration
	grace      time.Duration
	httpClient *http.Client
	lookupIP   func(context.Context, string, string) ([]net.IP, error)
	interfaces func() ([]net.Interface, error)
	now        func() time.Time
}

func newTrustedSourceManager(cfg config) *trustedSourceManager {
	if strings.TrimSpace(cfg.TrustedHomeIPv4URLs) == "" && strings.TrimSpace(cfg.TrustedDNSNames) == "" && cfg.TrustedHomeIPv6Prefix == 0 {
		return nil
	}
	return &trustedSourceManager{
		leases:     make(map[string]trustedSourceLease),
		ipv4URLs:   splitCSV(cfg.TrustedHomeIPv4URLs),
		dnsNames:   splitCSV(cfg.TrustedDNSNames),
		ipv6Bits:   cfg.TrustedHomeIPv6Prefix,
		refresh:    cfg.TrustedSourceRefresh,
		grace:      cfg.TrustedSourceGrace,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		lookupIP:   net.DefaultResolver.LookupIP,
		interfaces: net.Interfaces,
		now:        time.Now,
	}
}

func splitCSV(raw string) []string {
	var out []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (m *trustedSourceManager) Start(ctx context.Context) {
	m.refreshAll(ctx)
	go func() {
		ticker := time.NewTicker(m.refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.refreshAll(ctx)
			}
		}
	}()
}

func (m *trustedSourceManager) refreshAll(ctx context.Context) {
	if len(m.ipv4URLs) > 0 {
		ranges, err := m.discoverPublicIPv4(ctx)
		m.update("home-ipv4", ranges, err)
	}
	if m.ipv6Bits > 0 {
		ranges, err := m.discoverInterfaceIPv6()
		m.update("home-ipv6", ranges, err)
	}
	for _, name := range m.dnsNames {
		ranges, err := m.resolveName(ctx, name)
		m.update("dns:"+name, ranges, err)
	}
}

func (m *trustedSourceManager) update(source string, ranges []string, err error) {
	if err != nil {
		log.Printf("trusted source refresh %s: %v", source, err)
		return
	}
	sort.Strings(ranges)
	m.mu.Lock()
	previous := strings.Join(m.leases[source].ranges, ",")
	m.leases[source] = trustedSourceLease{ranges: ranges, expiresAt: m.now().Add(m.grace)}
	m.mu.Unlock()
	if current := strings.Join(ranges, ","); current != previous {
		log.Printf("trusted source %s updated: %s", source, current)
	}
}

func (m *trustedSourceManager) Snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	unique := make(map[string]struct{})
	for source, lease := range m.leases {
		if !now.Before(lease.expiresAt) {
			delete(m.leases, source)
			log.Printf("trusted source %s expired", source)
			continue
		}
		for _, prefix := range lease.ranges {
			unique[prefix] = struct{}{}
		}
	}
	out := make([]string, 0, len(unique))
	for prefix := range unique {
		out = append(out, prefix)
	}
	sort.Strings(out)
	return out
}

func (m *trustedSourceManager) discoverPublicIPv4(ctx context.Context) ([]string, error) {
	votes := make(map[netip.Addr]int)
	for _, endpoint := range m.ipv4URLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		resp, err := m.httpClient.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(string(body)))
		if readErr == nil && parseErr == nil && resp.StatusCode/100 == 2 && addr.Is4() && addr.IsGlobalUnicast() && !addr.IsPrivate() {
			votes[addr]++
		}
	}
	required := 1
	if len(m.ipv4URLs) > 1 {
		required = 2
	}
	for addr, count := range votes {
		if count >= required {
			return []string{netip.PrefixFrom(addr, 32).String()}, nil
		}
	}
	return nil, fmt.Errorf("public IPv4 reflectors did not reach agreement")
}

func (m *trustedSourceManager) discoverInterfaceIPv6() ([]string, error) {
	interfaces, err := m.interfaces()
	if err != nil {
		return nil, err
	}
	unique := make(map[string]struct{})
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			addr, err := netip.ParsePrefix(raw.String())
			if err != nil || !addr.Addr().Is6() || !addr.Addr().IsGlobalUnicast() || addr.Addr().IsPrivate() {
				continue
			}
			unique[netip.PrefixFrom(addr.Addr(), m.ipv6Bits).Masked().String()] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("no public IPv6 interface address found")
	}
	return mapKeys(unique), nil
}

func (m *trustedSourceManager) resolveName(ctx context.Context, name string) ([]string, error) {
	addresses, err := m.lookupIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	unique := make(map[string]struct{})
	for _, raw := range addresses {
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsPrivate() {
			continue
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		unique[netip.PrefixFrom(addr, bits).String()] = struct{}{}
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("no public addresses returned")
	}
	return mapKeys(unique), nil
}

func mapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
