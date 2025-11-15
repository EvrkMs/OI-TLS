package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    "github.com/miekg/dns"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
)

func main() {
    var (
        entryHost    = flag.String("entry-host", getenv("ENTRY_HOST", "entry.example.internal"), "entry node hostname")
        backendHost  = flag.String("backend-host", getenv("BACKEND_HOST", "backend.example.internal"), "backend hostname")
        backendURL   = flag.String("backend-url", getenv("BACKEND_URL", "https://backend.example.internal/healthz"), "backend URL")
        dnsAddr      = flag.String("dns", getenv("DNS_ADDR", "172.40.0.53:53"), "DNS server")
        gateway      = flag.String("gateway", getenv("GATEWAY", "172.40.0.254"), "default gw")
    )
    flag.Parse()

    if err := setDefaultRoute(*gateway); err != nil {
        log.Fatalf("route setup: %v", err)
    }

    entryAddr, err := resolveHost(*entryHost, *dnsAddr)
    if err != nil {
        log.Fatalf("resolve entry host: %v", err)
    }

    if err := probeTXT(*dnsAddr); err != nil {
        log.Printf("dns probe warn: %v", err)
    }

    if err := runRequest(entryAddr+":443", *backendHost, *backendURL); err != nil {
        log.Fatalf("request failed: %v", err)
    }
}

func runRequest(entryAddrPort, backendHost, backendURL string) error {
    outerCfg := &tls.Config{
        InsecureSkipVerify: true,
    }
    log.Printf("[client] dialing OuterTLS %s", entryAddrPort)
    outerConn, err := tls.Dial("tcp", entryAddrPort, outerCfg)
    if err != nil {
        return fmt.Errorf("outer dial: %w", err)
    }
    defer outerConn.Close()

    innerCfg := &tls.Config{
        InsecureSkipVerify: true,
        ServerName:         backendHost,
    }
    innerConn := tls.Client(outerConn, innerCfg)
    if err := innerConn.Handshake(); err != nil {
        return fmt.Errorf("inner handshake: %w", err)
    }
    defer innerConn.Close()

    req, _ := http.NewRequest("GET", backendURL, nil)
    req.Header.Set("User-Agent", "OI-TLS-Client/0.1")
    if err := req.Write(innerConn); err != nil {
        return fmt.Errorf("write request: %w", err)
    }

    resp, err := http.ReadResponse(bufio.NewReader(innerConn), req)
    if err != nil {
        return fmt.Errorf("read response: %w", err)
    }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    log.Printf("[client] response %s: %s", resp.Status, string(body))
    return nil
}

func resolveHost(host, server string) (string, error) {
    c := new(dns.Client)
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(host), dns.TypeA)
    log.Printf("[client] A lookup %s via UDP %s", host, server)
    r, _, err := c.Exchange(m, server)
    if err != nil {
        return "", err
    }
    if r.Rcode != dns.RcodeSuccess {
        return "", fmt.Errorf("dns error %d", r.Rcode)
    }
    for _, ans := range r.Answer {
        if a, ok := ans.(*dns.A); ok {
            log.Printf("[client] resolved %s -> %s", host, a.A.String())
            return a.A.String(), nil
        }
    }
    return "", fmt.Errorf("no A record for %s", host)
}

func probeTXT(server string) error {
    c := new(dns.Client)
    m := new(dns.Msg)
    m.SetQuestion("_oitls.example.internal.", dns.TypeTXT)
    log.Printf("[client] querying TXT via UDP %s", server)
    r, _, err := c.Exchange(m, server)
    if err != nil {
        return err
    }
    if r.Rcode != dns.RcodeSuccess {
        return fmt.Errorf("dns error %d", r.Rcode)
    }
    for _, ans := range r.Answer {
        if txt, ok := ans.(*dns.TXT); ok {
            log.Printf("[client] TXT: %v", txt.Txt)
        }
    }
    return nil
}

func setDefaultRoute(gw string) error {
    log.Printf("[client] ip route replace default via %s", gw)
    cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("ip route replace default via %s", gw))
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}

func getenv(key, fallback string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return fallback
}
