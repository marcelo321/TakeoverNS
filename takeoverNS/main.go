package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	inFile      = flag.String("i", "", "Input file (one host per line). If empty, reads stdin.")
	concurrency = flag.Int("c", 25, "Concurrency")
	timeoutMS   = flag.Int("timeout", 2500, "DNS timeout in ms (per query)")
)

var (
	// Your 3 regex signals
	reAWS   = regexp.MustCompile(`awsdns-`)
	reGCP   = regexp.MustCompile(`googledomains\.com`)
	reAzure = regexp.MustCompile(`azure-dns`)

	// Parse NS hostnames from dig +trace output lines like:
	// example.com.  172800  IN  NS  ns-123.awsdns-45.net.
	reTraceNSLine = regexp.MustCompile(`\sIN\s+NS\s+([A-Za-z0-9._-]+)\.?$`)
)

type provider int

const (
	provUnknown provider = iota
	provRoute53
	provGoogleDomains
	provAzureDNS
)

func main() {
	flag.Parse()

	hosts, err := readLines(*inFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading input:", err)
		os.Exit(1)
	}

	tmo := time.Duration(*timeoutMS) * time.Millisecond

	jobs := make(chan string)
	alerts := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				host = strings.TrimSpace(host)
				if host == "" || strings.HasPrefix(host, "#") {
					continue
				}

				ok, _ := isServfailEitherResolver(host, tmo)
				if !ok {
					continue
				}

				// dig host +trace @1.1.1.1 and extract provider NS records
				nsByProv, err := traceFindProviderNS(host, tmo)
				if err != nil {
					continue
				}

				// For any provider NS found, run dig host @NS and count REFUSED
				// If any provider gets REFUSED>0, alert (and alert only once per provider).
				for p, nsList := range nsByProv {
					if len(nsList) == 0 {
						continue
					}
					refusedCount := 0
					for _, ns := range nsList {
						if digStatusRefused(host, ns, tmo) {
							refusedCount++
						}
					}
					if refusedCount > 0 {
						alerts <- fmt.Sprintf("[%s] DNS Zone takeover - %s", providerLabel(p), host)
					}
				}
			}
		}()
	}

	go func() {
		for _, h := range hosts {
			h = strings.TrimSpace(h)
			if h == "" || strings.HasPrefix(h, "#") {
				continue
			}
			jobs <- h
		}
		close(jobs)
		wg.Wait()
		close(alerts)
	}()

	for a := range alerts {
		fmt.Println(a)
	}
}

func readLines(path string) ([]string, error) {
	var sc *bufio.Scanner
	if path == "" {
		sc = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	}

	// allow long lines
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	var out []string
	for sc.Scan() {
		out = append(out, strings.TrimSpace(sc.Text()))
	}
	return out, sc.Err()
}

func isServfailEitherResolver(host string, tmo time.Duration) (bool, string) {
	// Must use either 1.1.1.1 or 8.8.8.8 (use both, no flag)
	r1 := net.JoinHostPort("1.1.1.1", "53")
	r2 := net.JoinHostPort("8.8.8.8", "53")

	sf1 := isServfailWithResolver(host, r1, tmo)
	if sf1 {
		return true, "1.1.1.1"
	}
	sf2 := isServfailWithResolver(host, r2, tmo)
	if sf2 {
		return true, "8.8.8.8"
	}
	return false, ""
}

func isServfailWithResolver(host, resolver string, tmo time.Duration) bool {
	fqdn := dns.Fqdn(strings.TrimSpace(host))

	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Timeout = tmo
	c.Net = "udp"

	in, _, err := c.Exchange(m, resolver)
	if err != nil {
		// fallback to TCP
		c2 := new(dns.Client)
		c2.Timeout = tmo
		c2.Net = "tcp"
		in, _, err2 := c2.Exchange(m, resolver)
		if err2 != nil {
			return false
		}
		return in.Rcode == dns.RcodeServerFailure
	}

	return in.Rcode == dns.RcodeServerFailure
}

func traceFindProviderNS(host string, tmo time.Duration) (map[provider][]string, error) {
	// dig host +trace @1.1.1.1
	// Extract NS lines that match our 3 regex patterns.
	out, err := runDig(tmo, host, "+trace", "@1.1.1.1")
	if err != nil {
		return nil, err
	}

	nsByProv := map[provider][]string{
		provRoute53:       {},
		provGoogleDomains: {},
		provAzureDNS:      {},
	}

	seen := make(map[string]struct{})

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// quick prefilter for our provider regex
		lower := strings.ToLower(line)
		if !(reAWS.MatchString(lower) || reGCP.MatchString(lower) || reAzure.MatchString(lower)) {
			continue
		}

		// try to parse NS hostname from trace line
		m := reTraceNSLine.FindStringSubmatch(line)
		if len(m) != 2 {
			continue
		}

		ns := strings.ToLower(strings.TrimSuffix(m[1], "."))
		if ns == "" {
			continue
		}
		if _, ok := seen[ns]; ok {
			continue
		}
		seen[ns] = struct{}{}

		p := classifyProvider(ns)
		if p == provUnknown {
			continue
		}
		nsByProv[p] = append(nsByProv[p], ns)
	}

	return nsByProv, nil
}

func classifyProvider(ns string) provider {
	ns = strings.ToLower(ns)
	switch {
	case reAWS.MatchString(ns):
		return provRoute53
	case reGCP.MatchString(ns):
		return provGoogleDomains
	case reAzure.MatchString(ns):
		return provAzureDNS
	default:
		return provUnknown
	}
}

func providerLabel(p provider) string {
	switch p {
	case provRoute53:
		return "Route53"
	case provGoogleDomains:
		return "GoogleDomains"
	case provAzureDNS:
		return "AzureDNS"
	default:
		return "Unknown"
	}
}

func digStatusRefused(host, ns string, tmo time.Duration) bool {
	// dig host @ns and grep REFUSED (we match dig header "status: REFUSED")
	out, err := runDig(tmo, host, "@"+ns)
	if err != nil {
		return false
	}
	// dig output has: ";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: ..."
	return strings.Contains(out, "status: REFUSED")
}

func runDig(tmo time.Duration, args ...string) (string, error) {
	// Make dig a bit deterministic and fast
	// +time / +tries applied so it doesn’t hang per NS.
	base := []string{"+time=2", "+tries=1", "+retry=0"}
	all := append(base, args...)

	cmd := exec.Command("dig", all...)
	// Hard kill if it runs too long (slightly above our tmo)
	killAfter := tmo + (500 * time.Millisecond)
	timer := time.AfterFunc(killAfter, func() {
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()

	b, err := cmd.CombinedOutput()
	if err != nil {
		// still return output for debugging if needed, but caller uses error to skip
		return "", err
	}
	return string(b), nil
}
