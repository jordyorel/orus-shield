package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jordyorel/orus-shield/engine/internal/module"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestAddresses(t *testing.T) {
	a := newAgent(newClient("http://x", "t"), quiet())
	ranges, addrs, err := a.addresses([]string{"10.0.0.0/30", "192.168.1.7/32"})
	if err != nil || len(ranges) != 2 {
		t.Fatal(err)
	}
	var got []string
	for _, ip := range addrs {
		got = append(got, ip.String())
	}
	if strings.Join(got, ",") != "10.0.0.1,10.0.0.2,192.168.1.7" {
		t.Errorf("addresses = %v", got)
	}
	if _, _, err := a.addresses([]string{"8.8.8.0/30"}); err == nil {
		t.Error("a public range was accepted")
	}
	_, many, _ := a.addresses([]string{"10.1.0.0/20"})
	if len(many) != module.MaxAddresses {
		t.Errorf("%d addresses, want the cap %d", len(many), module.MaxAddresses)
	}
}

type allowAll struct{}

func (allowAll) Allow(context.Context, module.Destination) error { return nil }

func TestRangeGate(t *testing.T) {
	g := rangeGate{inner: allowAll{}, ranges: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, allow: func(a netip.Addr) bool { return a.IsPrivate() }}
	if err := g.Allow(context.Background(), module.Destination{IP: netip.MustParseAddr("10.0.0.9"), Port: 22}); err != nil {
		t.Errorf("in range = %v", err)
	}
	for _, ip := range []string{"10.0.1.9", "8.8.8.8"} {
		if err := g.Allow(context.Background(), module.Destination{IP: netip.MustParseAddr(ip), Port: 22}); !errors.Is(err, module.ErrExcluded) {
			t.Errorf("%s = %v, want excluded", ip, err)
		}
	}
}

// A full round against a fake API: claim, scan a local open port, send.
func TestAgentRound(t *testing.T) {
	// A port of the ports module's catalog that is free here.
	var ln net.Listener
	var err error
	for _, p := range []string{"15672", "11211", "9042", "27017", "2379"} {
		if ln, err = net.Listen("tcp", "127.0.0.1:"+p); err == nil {
			break
		}
	}
	if ln == nil {
		t.Skip("no free catalog port to listen on")
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	var mu sync.Mutex
	var sent map[string]json.RawMessage
	claimed := false
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/agent/claim":
			mu.Lock()
			defer mu.Unlock()
			if claimed {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			claimed = true
			_ = json.NewEncoder(w).Encode(job{ScanID: "s1", Attempt: 1, Modules: []string{"ports", "tls"}, Domain: "agent-1.internal",
				Ranges: []string{"127.0.0.1/32"}, Exclusions: json.RawMessage(`{}`), RatePerSec: 100, LeaseSecs: 600})
		case "/api/v1/agent/scans/s1/result":
			mu.Lock()
			defer mu.Unlock()
			_ = json.NewDecoder(r.Body).Decode(&sent)
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()

	a := newAgent(newClient(api.URL, "tok"), quiet())
	a.allowAddr = func(ip netip.Addr) bool { return ip.IsPrivate() || ip.IsLoopback() } // the test's "network"
	worked, err := a.once(context.Background())
	if err != nil || !worked {
		t.Fatalf("once = %v, %v", worked, err)
	}
	if worked, _ := a.once(context.Background()); worked {
		t.Error("worked with nothing to do")
	}
	var results map[string]module.Result
	var failed map[string]string
	_ = json.Unmarshal(sent["results"], &results)
	_ = json.Unmarshal(sent["failed"], &failed)
	if failed["tls"] != "not supported by the agent yet" {
		t.Errorf("failed = %v", failed)
	}
	found := false
	for _, f := range results["ports"].Findings {
		if f.Asset == "127.0.0.1:"+port {
			found = true
		}
	}
	if !found {
		t.Errorf("the open port %s is not in the ports result: %+v", port, results["ports"].Findings)
	}
	if a.api.token != "tok" {
		t.Fatal("token lost")
	}
	// A revoked agent stops.
	a.api.token = "revoked"
	if err := a.loop(context.Background()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("revoked loop = %v", err)
	}
}
