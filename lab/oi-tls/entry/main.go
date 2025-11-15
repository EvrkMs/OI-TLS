package main

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "net"
    "os"
)

const (
    tlsRecordHeaderLen = 5
)

func main() {
    backendAddr := getenv("BACKEND_ADDR", "172.41.0.20:8443")
    certFile := getenv("ENTRY_CERT", "certs/entry.crt")
    keyFile := getenv("ENTRY_KEY", "certs/entry.key")

    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        log.Fatalf("failed to load cert: %v", err)
    }

    tlsCfg := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion: tls.VersionTLS12,
        ClientAuth: tls.NoClientCert,
    }

    ln, err := tls.Listen("tcp", ":443", tlsCfg)
    if err != nil {
        log.Fatalf("listen failed: %v", err)
    }
    log.Printf("Entry listening on %s, forwarding to %s", ln.Addr(), backendAddr)

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("accept error: %v", err)
            continue
        }
        go handle(conn, backendAddr)
    }
}

func handle(c net.Conn, backendAddr string) {
    defer c.Close()
    br := bufio.NewReader(c)

    firstRecord, err := readTLSRecord(br)
    if err != nil {
        log.Printf("failed to read ClientHello: %v")
        return
    }

    sni, err := extractSNI(firstRecord)
    if err != nil {
        log.Printf("failed to parse SNI: %v")
        return
    }
    log.Printf("InnerTLS SNI=%s", sni)

    backendConn, err := net.Dial("tcp", backendAddr)
    if err != nil {
        log.Printf("backend dial error: %v", err)
        return
    }
    defer backendConn.Close()

    if _, err := backendConn.Write(firstRecord); err != nil {
        log.Printf("write initial record failed: %v", err)
        return
    }

    // proxy remaining data
    clientToBackend := io.MultiReader(br)

    errCh := make(chan error, 2)

    go func() {
        _, err := io.Copy(backendConn, clientToBackend)
        errCh <- err
    }()

    go func() {
        _, err := io.Copy(c, backendConn)
        errCh <- err
    }()

    if err := <-errCh; err != nil && err != io.EOF {
        log.Printf("proxy error: %v", err)
    }
}

func readTLSRecord(br *bufio.Reader) ([]byte, error) {
    header := make([]byte, tlsRecordHeaderLen)
    if _, err := io.ReadFull(br, header); err != nil {
        return nil, err
    }
    length := int(header[3])<<8 | int(header[4])
    payload := make([]byte, length)
    if _, err := io.ReadFull(br, payload); err != nil {
        return nil, err
    }
    return append(header, payload...), nil
}

func extractSNI(record []byte) (string, error) {
    if len(record) <= tlsRecordHeaderLen {
        return "", fmt.Errorf("record too short")
    }
    data := record[tlsRecordHeaderLen:]
    if len(data) < 4 || data[0] != 0x01 { // ClientHello
        return "", fmt.Errorf("not clienthello")
    }
    hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
    if hsLen+4 > len(data) {
        return "", fmt.Errorf("invalid length")
    }
    body := data[4 : 4+hsLen]
    if len(body) < 34 {
        return "", fmt.Errorf("body too short")
    }
    idx := 34
    if len(body) < idx+1 {
        return "", fmt.Errorf("no session id length")
    }
    sidLen := int(body[idx])
    idx += 1 + sidLen
    if len(body) < idx+2 {
        return "", fmt.Errorf("missing cipher suites len")
    }
    csLen := int(body[idx])<<8 | int(body[idx+1])
    idx += 2 + csLen
    if len(body) < idx+1 {
        return "", fmt.Errorf("missing compression len")
    }
    compLen := int(body[idx])
    idx += 1 + compLen
    if len(body) < idx+2 {
        return "", fmt.Errorf("missing extensions len")
    }
    extLen := int(body[idx])<<8 | int(body[idx+1])
    idx += 2
    if len(body) < idx+extLen {
        return "", fmt.Errorf("extensions truncated")
    }
    exts := body[idx : idx+extLen]
    for len(exts) >= 4 {
        extType := int(exts[0])<<8 | int(exts[1])
        extSize := int(exts[2])<<8 | int(exts[3])
        exts = exts[4:]
        if extSize > len(exts) {
            break
        }
        extData := exts[:extSize]
        exts = exts[extSize:]
        if extType == 0 { // server_name
            if len(extData) < 5 {
                return "", fmt.Errorf("sni ext too short")
            }
            listLen := int(extData[0])<<8 | int(extData[1])
            if listLen+2 > len(extData) {
                return "", fmt.Errorf("sni list truncated")
            }
            sn := extData[2 : 2+listLen]
            if len(sn) < 3 {
                return "", fmt.Errorf("sni entry too short")
            }
            nameType := sn[0]
            if nameType != 0 {
                continue
            }
            nameLen := int(sn[1])<<8 | int(sn[2])
            if 3+nameLen > len(sn) {
                return "", fmt.Errorf("sni name truncated")
            }
            return string(sn[3 : 3+nameLen]), nil
        }
    }
    return "", fmt.Errorf("sni not found")
}

func getenv(key, fallback string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return fallback
}
