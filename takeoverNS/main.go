package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type NSProbe struct {
	NS       string `json:"ns"`
	Rcode    string `json:"rcode"`
	Duration int64  `json:"duration_ms"`
	Error    string `json:"error,omitempty"`
}

type Result struct {
	Subdomain     string    `json:"subdomain"`
	Resolver      string    `json:"resolver"`
	Servfail      bool      `json:"servfail"`
	ServfailRcode string    `json:"servfail_rcode"`
	NSRecords     []string  `json:"ns_records,omitempty"`
	Provider      string    `json:"provider,omitempty"`
	RefusedChecks []NSProbe `json:"refused_checks,omitempty"`
	Vulnerable    bool      `json:"vulnerable"`
	Notes         []string  `json:"notes,omitempty"`
}

var (
	inFile      = flag.String("i", "", "Input file (one subdomain per line). If empty, reads stdin.")
	resolverIP  = flag.String("resolver", "1.1.1.1", "Resolver to use for SERVFAIL check and NS lookup: 1.1.1.1 or 8.8.8.8")
	concurrency = flag.Int("c", 25, "Concurrency")
	timeoutMS   = flag.Int("timeout", 2500, "DNS timeout in ms (per query)")
	jsonOut     = flag.Bool("json", false, "Output JSON lines")
	verbose     = flag.Bool("v", false, "Verbose stderr logging")
)

var (
	reAWS   = regexp.MustCompile(`awsdns-`)
	reGCP   = regexp.MustCompile(`googledomains\.com`)
	reAzure = regexp.MustCompile(`azure-dns`)
)

func main() {
	flag.Parse()

	resolver := normalizeResolver(*resolverIP)
	if resolver == "" {
		fmt.Fprintln(os.Stderr, "Invalid -resolver. Use 1.1.1.1 or 8.8.8.8")
		os.Exit(2)
	}

	subdomains, err := readLines(*inFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading input:", err)
		os.Exit(1)
	}

	tmo := time.Duration(*timeoutMS) * time.Millisecond

	jobs := make(chan string)
	results := make(chan Result)

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				r := checkSubdomain(sub, resolver, tmo)
				results <- r
			}
		}()
	}

	go func() {
		for _, s := range subdomains {
			s = strings.TrimSpace(s)
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			jobs <- s
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if *jsonOut {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		} else {
			printHuman(r)
		}
	}
}

func normalizeResolver(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "1.1.1.1" || ip == "8.8.8.8" {
		return net.JoinHostPort(ip, "53")
	}
	// allow user to pass "1.1.1.1:53"
	host, port, err := net.SplitHostPort(ip)
	if err == nil {
		if (host == "1.1.1.1" || host == "8.8.8.8") && port == "53" {
			return ip
		}
	}
	return ""
}

func checkSubdomain(sub, resolver string, tmo time.Duration) Result {
	sub = strings.TrimSpace(sub)
	subFQDN := dns.Fqdn(sub)

	res := Result{
		Subdomain: sub,
		Resolver:  resolver,
	}

	// 1) Check SERVFAIL via resolver (A query)
	rcode, _, err := dnsQuery(subFQDN, dns.TypeA, resolver, true, tmo)
	res.ServfailRcode = dns.RcodeToString[rcode]
	if err != nil {
		// If resolver query fails due to timeout/network, do not treat as SERVFAIL
		res.Notes = append(res.Notes, "resolver_query_error:"+err.Error())
		if *verbose {
			fmt.Fprintln(os.Stderr, "[resolver-error]", sub, err)
		}
		return res
	}

	if rcode == dns.RcodeServerFailure {
		res.Servfail = true
	} else {
		// Not servfail, stop here per your logic
		return res
	}

	// 2) Fetch NS records of the subdomain via resolver
	ns, nserr := fetchNS(subFQDN, resolver, tmo)
	if nserr != nil {
		res.Notes = append(res.Notes, "ns_lookup_error:"+nserr.Error())
		if *verbose {
			fmt.Fprintln(os.Stderr, "[ns-error]", sub, nserr)
		}
		return res
	}
	res.NSRecords = ns

	// 3) Provider detection by your regex signals
	provider := detectProvider(ns)
	if provider == "" {
		res.Notes = append(res.Notes, "no_provider_ns_match")
		return res
	}
	res.Provider = provider

	// 4) dig subdomain @nsrecord and check REFUSED (A query direct to NS)
	// We test only NS records that match the provider regex (per your intent).
	var probes []NSProbe
	refusedAny := false
	for _, n := range ns {
		if !nsMatchesProvider(n, provider) {
			continue
		}
		p := probeAuthoritative(subFQDN, n, tmo)
		probes = append(probes, p)
		if p.Error == "" && p.Rcode == "REFUSED" {
			refusedAny = true
		}
	}
	res.RefusedChecks = probes

	// 5) Flag vulnerable if SERVFAIL + provider NS + REFUSED from at least one NS
	if refusedAny {
		res.Vulnerable = true
	}
	return res
}

func fetchNS(nameFQDN, resolver string, tmo time.Duration) ([]string, error) {
	rcode, msg, err := dnsQuery(nameFQDN, dns.TypeNS, resolver, true, tmo)
	if err != nil {
		return nil, err
	}
	if rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("NS lookup rcode=%s", dns.RcodeToString[rcode])
	}

	var out []string
	seen := make(map[string]struct{})
	for _, rr := range msg.Answer {
		if nsrr, ok := rr.(*dns.NS); ok {
			target := strings.TrimSuffix(nsrr.Ns, ".")
			target = strings.ToLower(strings.TrimSpace(target))
			if target == "" {
				continue
			}
			if _, ok := seen[target]; ok {
				continue
			}
			seen[target] = struct{}{}
			out = append(out, target)
		}
	}
	return out, nil
}

func detectProvider(ns []string) string {
	for _, n := range ns {
		n = strings.ToLower(n)
		switch {
		case reAWS.MatchString(n):
			return "route53"
		case reGCP.MatchString(n):
			return "googledomains"
		case reAzure.MatchString(n):
			return "azure"
		}
	}
	return ""
}

func nsMatchesProvider(ns, provider string) bool {
	ns = strings.ToLower(ns)
	switch provider {
	case "route53":
		return reAWS.MatchString(ns)
	case "googledomains":
		return reGCP.MatchString(ns)
	case "azure":
		return reAzure.MatchString(ns)
	default:
		return false
	}
}

func probeAuthoritative(nameFQDN, nsHost string, tmo time.Duration) NSProbe {
	start := time.Now()

	nsHost = strings.TrimSpace(nsHost)
	nsHost = strings.TrimSuffix(nsHost, ".")
	nsHostFQDN := dns.Fqdn(nsHost)

	// Resolve NS hostname to an IP using system resolver (not 1.1.1.1/8.8.8.8 requirement).
	// Your requirement applies to the SERVFAIL check; this step is needed to talk to the NS.
	ips, err := net.LookupIP(nsHost)
	if err != nil || len(ips) == 0 {
		return NSProbe{
			NS:       nsHost,
			Rcode:    "",
			Duration: time.Since(start).Milliseconds(),
			Error:    fmt.Sprintf("ns_ip_lookup_failed:%v", err),
		}
	}

	// Prefer IPv4 if present
	var ipStr string
	for _, ip := range ips {
		if ip.To4() != nil {
			ipStr = ip.String()
			break
		}
	}
	if ipStr == "" {
		ipStr = ips[0].String()
	}

	server := net.JoinHostPort(ipStr, "53")

	// Equivalent to: dig A name @ns (RD=0)
	rcode, _, qerr := dnsQuery(nameFQDN, dns.TypeA, server, false, tmo)
	rcodeStr := dns.RcodeToString[rcode]

	p := NSProbe{
		NS:       nsHost,
		Rcode:    rcodeStr,
		Duration: time.Since(start).Milliseconds(),
	}
	if qerr != nil {
		p.Error = qerr.Error()
	}
	return p
}

func dnsQuery(name string, qtype uint16, server string, rd bool, tmo time.Duration) (int, *dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = rd

	c := new(dns.Client)
	c.Timeout = tmo
	c.Net = "udp"

	in, _, err := c.Exchange(m, server)
	if err != nil {
		// Fallback to TCP for truncation or UDP issues
		c2 := new(dns.Client)
		c2.Timeout = tmo
		c2.Net = "tcp"
		in, _, err2 := c2.Exchange(m, server)
		if err2 != nil {
			return dns.RcodeServerFailure, nil, err
		}
		return in.Rcode, in, nil
	}
	return in.Rcode, in, nil
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

func printHuman(r Result) {
	status := "OK"
	if r.Servfail {
		status = "SERVFAIL"
	}
	if r.Vulnerable {
		status = "VULNERABLE"
	}

	fmt.Printf("%s\t%s\tresolver=%s", r.Subdomain, status, r.Resolver)
	if r.Provider != "" {
		fmt.Printf("\tprovider=%s", r.Provider)
	}
	if r.Servfail {
		fmt.Printf("\tns=%d", len(r.NSRecords))
		refusedCount := 0
		for _, p := range r.RefusedChecks {
			if p.Rcode == "REFUSED" && p.Error == "" {
				refusedCount++
			}
		}
		if len(r.RefusedChecks) > 0 {
			fmt.Printf("\trefused=%d/%d", refusedCount, len(r.RefusedChecks))
		}
	}
	if r.ServfailRcode != "" {
		fmt.Printf("\trcode=%s", r.ServfailRcode)
	}
	fmt.Println()

	if *verbose {
		if len(r.NSRecords) > 0 {
			fmt.Fprintf(os.Stderr, "  NS: %s\n", strings.Join(r.NSRecords, ", "))
		}
		for _, p := range r.RefusedChecks {
			fmt.Fprintf(os.Stderr, "  @%s rcode=%s err=%s\n", p.NS, p.Rcode, p.Error)
		}
		for _, n := range r.Notes {
			fmt.Fprintf(os.Stderr, "  note: %s\n", n)
		}
	}
}
