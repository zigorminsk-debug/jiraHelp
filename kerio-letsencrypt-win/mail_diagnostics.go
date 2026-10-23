package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type MailAuditRequest struct {
	Domain       string `json:"domain"`
	MailHost     string `json:"mailHost"`
	PublicIP     string `json:"publicIp"`
	ServerIP     string `json:"serverIp"` // Optional LAN/VPN IP override for TCP port checks
	DKIMSelector string `json:"dkimSelector"`
}

type CopySnippet struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type MailRemediationGuide struct {
	CheckID      string        `json:"checkId,omitempty"`
	Severity     string        `json:"severity"` // "critical" | "warning" | "info"
	Category     string        `json:"category"`
	Title        string        `json:"title"`
	WhyItMatters string        `json:"whyItMatters"`
	Steps        []string      `json:"steps"`
	VerifyCmd    string        `json:"verifyCmd,omitempty"`
	CopyItems    []CopySnippet `json:"copyItems,omitempty"`
	QuickAction  string        `json:"quickAction,omitempty"`
}

type MailCheckItem struct {
	ID       string                `json:"id"`
	Category string                `json:"category"`
	Title    string                `json:"title"`
	Status   string                `json:"status"` // "ok" | "warning" | "error" | "info"
	Summary  string                `json:"summary"`
	Details  []string              `json:"details"`
	Solution *MailRemediationGuide `json:"solution,omitempty"`
}

type PortProbeResult struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	Open        bool   `json:"open"`
	LatencyMs   int64  `json:"latencyMs"`
	TLSOK       bool   `json:"tlsOk"`
	TLSTrusted  bool   `json:"tlsTrusted"`
	TLSVersion  string `json:"tlsVersion,omitempty"`
	CertSubject string `json:"certSubject,omitempty"`
	CertIssuer  string `json:"certIssuer,omitempty"`
	CertExpiry  string `json:"certExpiry,omitempty"`
	CertDays    int    `json:"certDays"`
	Banner      string `json:"banner,omitempty"`
	Error       string `json:"error,omitempty"`
}

type RBLCheckEntry struct {
	Provider   string `json:"provider"`
	Zone       string `json:"zone"`
	Listed     bool   `json:"listed"`
	ReturnCode string `json:"returnCode,omitempty"`
	DelistURL  string `json:"delistUrl,omitempty"`
}

type MailAuditReport struct {
	CheckedAt        string                 `json:"checkedAt"`
	MailDomain       string                 `json:"mailDomain"`
	MailHost         string                 `json:"mailHost"`
	ServerIP         string                 `json:"serverIp"`
	ServerIPSource   string                 `json:"serverIpSource,omitempty"`
	CurrentWANIP     string                 `json:"currentWanIp,omitempty"`
	ProbeTargetUsed  string                 `json:"probeTargetUsed,omitempty"`
	Score            int                    `json:"score"`
	Grade            string                 `json:"grade"`
	Verdict          string                 `json:"verdict"`
	CriticalCount    int                    `json:"criticalCount"`
	WarningCount     int                    `json:"warningCount"`
	PassedCount      int                    `json:"passedCount"`
	Checks           []MailCheckItem        `json:"checks"`
	Ports            []PortProbeResult      `json:"ports"`
	Blacklists       []RBLCheckEntry        `json:"blacklists"`
	DomainBlacklists []RBLCheckEntry        `json:"domainBlacklists"`
	DelistCenter     DelistCenterData       `json:"delistCenter"`
	Delta            AuditDeltaComparison   `json:"delta"`
	Remediations     []MailRemediationGuide `json:"remediations"`
}

func isGloballyRoutableIPv4(raw string) bool {
	p := net.ParseIP(strings.TrimSpace(raw))
	if p == nil {
		return false
	}
	v4 := p.To4()
	if v4 == nil || p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast() || p.IsUnspecified() {
		return false
	}
	// Exclude CGNAT 100.64.0.0/10
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}

// DetectPublicIPFast races multiple global echo endpoints in parallel over a pooled HTTP/2 transport with 90s RAM caching.
func DetectPublicIPFast() string {
	if cached := getCachedWANIP(); cached != "" {
		return cached
	}
	type res struct {
		ip string
	}
	ch := make(chan res, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 2000*time.Millisecond)
	defer cancel()

	endpoints := []string{
		"https://1.1.1.1/cdn-cgi/trace",
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://checkip.amazonaws.com",
		"https://ifconfig.me/ip",
	}

	var wg sync.WaitGroup
	for _, ep := range endpoints {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "KerioCertManager/4.0")
			resp, err := sharedFastHTTPClient.Do(req)
			if err != nil {
				return
			}
			b, err := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 {
				return
			}
			body := string(b)
			if strings.Contains(u, "/cdn-cgi/trace") {
				for _, line := range strings.Split(body, "\n") {
					if strings.HasPrefix(line, "ip=") {
						cand := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
						if isGloballyRoutableIPv4(cand) {
							select {
							case ch <- res{ip: cand}:
							default:
							}
							return
						}
					}
				}
				return
			}
			cand := strings.TrimSpace(body)
			if isGloballyRoutableIPv4(cand) {
				select {
				case ch <- res{ip: cand}:
				default:
				}
			}
		}(ep)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case r := <-ch:
		setCachedWANIP(r.ip)
		return r.ip
	case <-done:
		return ""
	case <-ctx.Done():
		return ""
	}
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

// queryDoH queries Google & Cloudflare encrypted DNS-over-HTTPS over pooled HTTP/2 with in-run deduplication cache!
func queryDoH(name, qtype string) ([]dohAnswer, int, error) {
	cacheKey := strings.ToLower(strings.TrimSpace(name)) + "|" + strings.ToUpper(strings.TrimSpace(qtype))
	if ans, st, ok := getCachedDoH(cacheKey); ok {
		return ans, st, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
	defer cancel()

	urls := []string{
		"https://cloudflare-dns.com/dns-query?name=" + url.QueryEscape(name) + "&type=" + url.QueryEscape(qtype),
		"https://dns.google/resolve?name=" + url.QueryEscape(name) + "&type=" + url.QueryEscape(qtype),
	}

	type dohRes struct {
		ans    []dohAnswer
		status int
		err    error
	}
	ch := make(chan dohRes, len(urls))

	for _, u := range urls {
		go func(endpoint string) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				ch <- dohRes{err: err}
				return
			}
			req.Header.Set("Accept", "application/dns-json")
			resp, err := sharedFastHTTPClient.Do(req)
			if err != nil {
				ch <- dohRes{err: err}
				return
			}
			raw, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 {
				ch <- dohRes{err: fmt.Errorf("doh http %d", resp.StatusCode)}
				return
			}
			var parsed dohResponse
			if err := json.Unmarshal(raw, &parsed); err != nil {
				ch <- dohRes{err: err}
				return
			}
			ch <- dohRes{ans: parsed.Answer, status: parsed.Status}
		}(u)
	}

	var lastErr error
	for i := 0; i < len(urls); i++ {
		r := <-ch
		if r.err == nil {
			if len(r.ans) > 0 || r.status == 3 || r.status == 0 {
				setCachedDoH(cacheKey, r.ans, r.status, 45*time.Second)
				return r.ans, r.status, nil
			}
		} else {
			lastErr = r.err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("doh no response")
	}
	return nil, -1, lastErr
}

// makePublicResolvers queries external public DNS servers FIRST before falling back to OS resolver!
func makePublicResolvers() []*net.Resolver {
	out := []*net.Resolver{}
	for _, srv := range []string{"8.8.8.8:53", "1.1.1.1:53"} {
		target := srv
		out = append(out, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 1500 * time.Millisecond}
				return d.DialContext(ctx, "udp", target)
			},
		})
	}
	out = append(out, net.DefaultResolver)
	return out
}

func isDNSDefinitiveNotFound(err error) bool {
	if err == nil {
		return false
	}
	if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound && !dnsErr.IsTimeout {
		return true
	}
	return false
}

// lookupPublicIPv4sExternal finds ONLY globally routable public IPv4s via encrypted DoH + public DNS (immune to Split-DNS 10.x.x.x!).
func lookupPublicIPv4sExternal(host string) []string {
	seen := map[string]bool{}
	var out []string
	if ans, _, err := queryDoH(host, "A"); err == nil {
		for _, a := range ans {
			if a.Type == 1 && isGloballyRoutableIPv4(a.Data) && !seen[a.Data] {
				seen[a.Data] = true
				out = append(out, a.Data)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		ips, err := r.LookupIPAddr(ctx, host)
		cancel()
		if err == nil {
			for _, ip := range ips {
				s := ip.IP.String()
				if isGloballyRoutableIPv4(s) && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return out
}

// lookupLocalSplitDNSIPv4 detects internal LAN/VPN IP (e.g. 10.146.100.14) if local Split-DNS is active on this PC!
func lookupLocalSplitDNSIPv4(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil && ip.IP.IsPrivate() {
			return v4.String()
		}
	}
	return ""
}

func cleanDoHTXTData(raw string) string {
	// DoH JSON wraps TXT strings in quotes, e.g. "\"v=spf1 mx ~all\"" or split chunks "\"part1\" \"part2\""
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") && len(s) >= 2 {
		s = s[1 : len(s)-1]
		s = strings.ReplaceAll(s, "\" \"", "")
		s = strings.ReplaceAll(s, "\\\"", "\"")
	}
	return strings.TrimSpace(s)
}

func lookupTXTQuick(fqdn string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	if ans, status, err := queryDoH(fqdn, "TXT"); err == nil {
		for _, a := range ans {
			if a.Type == 16 {
				val := cleanDoHTXTData(a.Data)
				if val != "" && !seen[val] {
					seen[val] = true
					out = append(out, val)
				}
			}
		}
		if len(out) > 0 || status == 3 || status == 0 {
			return out, nil
		}
	}

	var lastErr error
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		txts, err := r.LookupTXT(ctx, fqdn)
		cancel()
		if err == nil && len(txts) > 0 {
			for _, t := range txts {
				if !seen[t] {
					seen[t] = true
					out = append(out, t)
				}
			}
			break
		} else if err != nil {
			lastErr = err
			if isDNSDefinitiveNotFound(err) {
				break
			}
		}
	}
	return out, lastErr
}

func lookupMXMulti(domain string) ([]*net.MX, error) {
	seen := map[string]*net.MX{}
	if ans, status, err := queryDoH(domain, "MX"); err == nil {
		for _, a := range ans {
			if a.Type == 15 {
				var pref uint16
				var target string
				if n, _ := fmt.Sscanf(strings.TrimSpace(a.Data), "%d %s", &pref, &target); n == 2 {
					host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
					if host != "" {
						seen[host] = &net.MX{Host: host, Pref: pref}
					}
				}
			}
		}
		if len(seen) == 0 && status == 3 {
			return nil, fmt.Errorf("MX-записи для %s не найдены", domain)
		}
	}
	if len(seen) == 0 {
		for _, r := range makePublicResolvers() {
			ctx, cancel := context.WithTimeout(context.Background(), 1600*time.Millisecond)
			mxs, err := r.LookupMX(ctx, domain)
			cancel()
			if err == nil && len(mxs) > 0 {
				for _, mx := range mxs {
					host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(mx.Host)), ".")
					if host != "" {
						if _, ok := seen[host]; !ok {
							seen[host] = &net.MX{Host: host, Pref: mx.Pref}
						}
					}
				}
				if len(seen) > 0 {
					break
				}
			} else if isDNSDefinitiveNotFound(err) {
				break
			}
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("MX-записи для %s не найдены", domain)
	}
	var list []*net.MX
	for _, v := range seen {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Pref != list[j].Pref {
			return list[i].Pref < list[j].Pref
		}
		return list[i].Host < list[j].Host
	})
	return list, nil
}

func lookupPTRMulti(ipStr string) []string {
	seen := map[string]bool{}
	var names []string
	if parsed := net.ParseIP(ipStr); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			ptrName := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
			if ans, status, err := queryDoH(ptrName, "PTR"); err == nil {
				for _, a := range ans {
					if a.Type == 12 {
						clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a.Data)), ".")
						if clean != "" && !seen[clean] {
							seen[clean] = true
							names = append(names, clean)
						}
					}
				}
				if len(names) > 0 || status == 3 {
					return names
				}
			}
		}
	}
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 1600*time.Millisecond)
		ptrs, err := r.LookupAddr(ctx, ipStr)
		cancel()
		if err == nil {
			for _, p := range ptrs {
				clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
				if clean != "" && !seen[clean] {
					seen[clean] = true
					names = append(names, clean)
				}
			}
			if len(names) > 0 {
				break
			}
		} else if isDNSDefinitiveNotFound(err) {
			break
		}
	}
	return names
}

func lookupSRVAutodiscover(domain string) []string {
	var found []string
	seen := map[string]bool{}
	if ans, _, err := queryDoH("_autodiscover._tcp."+domain, "SRV"); err == nil {
		for _, a := range ans {
			if a.Type == 33 {
				var prio, weight, port int
				var target string
				if n, _ := fmt.Sscanf(strings.TrimSpace(a.Data), "%d %d %d %s", &prio, &weight, &port, &target); n == 4 {
					h := fmt.Sprintf("%s:%d (приоритет %d)", strings.TrimSuffix(target, "."), port, prio)
					if !seen[h] {
						seen[h] = true
						found = append(found, h)
					}
				}
			}
		}
		if len(found) > 0 {
			return found
		}
	}
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		_, srvs, err := r.LookupSRV(ctx, "autodiscover", "tcp", domain)
		cancel()
		if err == nil && len(srvs) > 0 {
			for _, s := range srvs {
				h := fmt.Sprintf("%s:%d (приоритет %d)", strings.TrimSuffix(s.Target, "."), s.Port, s.Priority)
				if !seen[h] {
					seen[h] = true
					found = append(found, h)
				}
			}
			break
		} else if isDNSDefinitiveNotFound(err) {
			break
		}
	}
	return found
}

func cleanInputHost(raw string) string {
	s := strings.TrimSpace(raw)
	if idx := strings.Index(s, "@"); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.TrimPrefix(strings.ToLower(s), "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(s, ". ")
}

func isKnownMailHostPrefix(label string) bool {
	switch strings.ToLower(label) {
	case "mail", "smtp", "mx", "mx1", "mx2", "relay", "webmail", "imap", "pop", "pop3", "kerio", "exchange", "pochta", "post":
		return true
	}
	return false
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1 (устарел!)"
	case tls.VersionTLS10:
		return "TLS 1.0 (устарел!)"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}

type smtpLiveDetails struct {
	Reachable       bool
	LatencyMs       int64
	BannerLine      string
	BannerHost      string
	SupportsSTARTTLS bool
	SupportsAuth    bool
	TLSState        *tls.ConnectionState
	TLSVerified     bool
	TLSVerifyErr    string
	OpenRelay       bool
	RelayTestLog    string
	DialErr         string
}

func readSMTPReply(r *bufio.Reader) (int, string, error) {
	var lines []string
	code := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return code, strings.Join(lines, " | "), err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if len(line) >= 3 {
			_, _ = fmt.Sscanf(line[:3], "%d", &code)
		}
		if len(line) < 4 || line[3] == ' ' {
			break
		}
	}
	return code, strings.Join(lines, " | "), nil
}

func inspectSMTPPort(targetAddr, sniHost string, checkRelay bool) smtpLiveDetails {
	var res smtpLiveDetails
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", targetAddr, 4200*time.Millisecond)
	if err != nil {
		res.DialErr = err.Error()
		return res
	}
	res.Reachable = true
	res.LatencyMs = time.Since(t0).Milliseconds()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(7 * time.Second))

	br := bufio.NewReader(conn)
	code, banner, err := readSMTPReply(br)
	if err != nil || code == 0 {
		res.DialErr = fmt.Sprintf("не получен SMTP-баннер: %v", err)
		return res
	}
	res.BannerLine = banner
	fields := strings.Fields(banner)
	if len(fields) >= 2 {
		res.BannerHost = strings.Trim(fields[1], ".,;<>[]()")
	}

	_, _ = fmt.Fprintf(conn, "EHLO audit-check.kerio-diagnostic.invalid\r\n")
	_, ehloLines, _ := readSMTPReply(br)
	if ehloLines == "" {
		_, _ = fmt.Fprintf(conn, "HELO kerio-check.local\r\n")
		_, ehloLines, _ = readSMTPReply(br)
	}
	upEhlo := strings.ToUpper(ehloLines)
	if strings.Contains(upEhlo, "STARTTLS") {
		res.SupportsSTARTTLS = true
	}
	if strings.Contains(upEhlo, "AUTH") {
		res.SupportsAuth = true
	}

	// Non-intrusive Open Relay probe BEFORE STARTTLS (always aborts with RSET, zero email data sent!)
	if checkRelay {
		_, _ = fmt.Fprintf(conn, "MAIL FROM:<check-noreply@example.org>\r\n")
		mCode, mResp, mErr := readSMTPReply(br)
		if mErr == nil && mCode >= 200 && mCode < 300 {
			_, _ = fmt.Fprintf(conn, "RCPT TO:<relay-audit-test@gmail.com>\r\n")
			rCode, rResp, rErr := readSMTPReply(br)
			res.RelayTestLog = fmt.Sprintf("MAIL=%d (%s) → RCPT=%d (%s)", mCode, mResp, rCode, rResp)
			if rErr == nil && rCode >= 200 && rCode < 300 {
				res.OpenRelay = true
			}
		} else {
			res.RelayTestLog = fmt.Sprintf("MAIL=%d (%s)", mCode, mResp)
		}
		_, _ = fmt.Fprintf(conn, "RSET\r\n")
		_, _, _ = readSMTPReply(br)
	}

	// Upgrade to STARTTLS if offered
	if res.SupportsSTARTTLS {
		_, _ = fmt.Fprintf(conn, "STARTTLS\r\n")
		stCode, _, stErr := readSMTPReply(br)
		if stErr == nil && stCode == 220 {
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: true,
			})
			if herr := tlsConn.Handshake(); herr == nil {
				st := tlsConn.ConnectionState()
				res.TLSState = &st
				verifyTrustedChain(&st, sniHost, &res.TLSVerified, &res.TLSVerifyErr)
				_, _ = fmt.Fprintf(tlsConn, "QUIT\r\n")
				return res
			}
		}
	}

	_, _ = fmt.Fprintf(conn, "QUIT\r\n")
	return res
}

func verifyTrustedChain(st *tls.ConnectionState, sniHost string, okOut *bool, errOut *string) {
	if len(st.PeerCertificates) == 0 {
		*okOut = false
		*errOut = "сервер не отдал ни одного SSL-сертификата"
		return
	}
	leaf := st.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, verr := leaf.Verify(x509.VerifyOptions{
		DNSName:       sniHost,
		Intermediates: inter,
	}); verr != nil {
		*okOut = false
		*errOut = verr.Error()
		return
	}
	*okOut = true
}

func probeImplicitTLSPort(host string, port int, protoLabel string) PortProbeResult {
	p := PortProbeResult{
		Port:     port,
		Protocol: protoLabel,
	}
	sniHost := host
	t0 := time.Now()
	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 4000*time.Millisecond)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Open = true
	p.LatencyMs = time.Since(t0).Milliseconds()
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	return finishImplicitTLSOnConn(rawConn, p, sniHost)
}

func probeImplicitTLSPortSNI(connectHost, sniHost string, port int, protoLabel string) PortProbeResult {
	p := PortProbeResult{
		Port:     port,
		Protocol: protoLabel,
	}
	t0 := time.Now()
	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(connectHost, fmt.Sprintf("%d", port)), 4000*time.Millisecond)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Open = true
	p.LatencyMs = time.Since(t0).Milliseconds()
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	return finishImplicitTLSOnConn(rawConn, p, sniHost)
}

func finishImplicitTLSOnConn(rawConn net.Conn, p PortProbeResult, sniHost string) PortProbeResult {
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         sniHost,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		p.TLSOK = false
		p.Error = "ошибка TLS-рукопожатия: " + err.Error()
		return p
	}
	st := tlsConn.ConnectionState()
	p.TLSOK = true
	p.TLSVersion = tlsVersionName(st.Version)
	var vErr string
	verifyTrustedChain(&st, sniHost, &p.TLSTrusted, &vErr)
	if !p.TLSTrusted {
		p.Error = vErr
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		p.CertSubject = leaf.Subject.CommonName
		p.CertIssuer = leaf.Issuer.CommonName
		p.CertExpiry = leaf.NotAfter.Format("02.01.2006")
		p.CertDays = int(time.Until(leaf.NotAfter).Hours() / 24)
	}
	return p
}

func checkDNSBLLists(ip net.IP) []RBLCheckEntry {
	ip4 := ip.To4()
	if ip4 == nil || ip.IsPrivate() || ip.IsLoopback() {
		return nil
	}
	rev := fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])

	providers := []struct {
		name string
		zone string
		url  string
	}{
		{"Spamhaus ZEN", "zen.spamhaus.org", "https://check.spamhaus.org/"},
		{"Barracuda Reputation", "b.barracudacentral.org", "https://www.barracudacentral.org/rbl/removal-request"},
		{"SpamCop Blocking List", "bl.spamcop.net", "https://www.spamcop.net/bl.shtml"},
		{"SORBS DNSBL", "dnsbl.sorbs.net", "http://www.sorbs.net/lookup.shtml"},
		{"UCEPROTECT Level 1", "dnsbl-1.uceprotect.net", "https://www.uceprotect.net/en/rblcheck.php"},
		{"PSBL (Passive Spam Block)", "psbl.surriel.com", "https://psbl.org/"},
		{"WPBL (Weighted Private)", "db.wpbl.info", "http://wpbl.info/cgi-bin/detail.cgi"},
		{"Mailspike BL", "bl.mailspike.net", "https://mailspike.org/iplookup.html"},
		{"NiX Spam (Heise)", "ix.dnsbl.manitu.net", "https://www.dnsbl.manitu.net/"},
		{"SpamRATS All", "all.spamrats.com", "https://www.spamrats.com/lookup.php"},
		{"0SPAM Project", "bl.0spam.org", "https://0spam.org/check"},
	}

	out := make([]RBLCheckEntry, len(providers))
	var wg sync.WaitGroup
	// Use system resolver / direct authoritative lookup where possible (8.8.8.8 triggers 127.255.255.254 on Spamhaus)
	sysRes := net.DefaultResolver
	for i, prv := range providers {
		wg.Add(1)
		go func(idx int, name, zone, delist string) {
			defer wg.Done()
			entry := RBLCheckEntry{
				Provider:  name,
				Zone:      zone,
				DelistURL: delist,
			}
			q := rev + "." + zone
			ctx, cancel := context.WithTimeout(context.Background(), 2200*time.Millisecond)
			ips, err := sysRes.LookupIPAddr(ctx, q)
			cancel()
			if err == nil && len(ips) > 0 {
				for _, hit := range ips {
					h4 := hit.IP.To4()
					// Filter 127.255.255.x open-resolver rate-limit / policy codes (NOT actual spam listings!)
					if h4 != nil && h4[0] == 127 && !(h4[1] == 255 && h4[2] == 255) {
						entry.Listed = true
						entry.ReturnCode = h4.String()
						break
					}
				}
			}
			out[idx] = entry
		}(i, prv.name, prv.zone, prv.url)
	}
	wg.Wait()
	return out
}

func parseDKIMPublicKeyBits(txt string) (algo string, bits int) {
	algo = "rsa"
	var pB64 string
	for _, part := range strings.Split(txt, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		if k == "k" && v != "" {
			algo = strings.ToLower(v)
		}
		if k == "p" {
			pB64 = strings.ReplaceAll(v, " ", "")
		}
	}
	if pB64 == "" {
		return algo, 0
	}
	der, err := base64.StdEncoding.DecodeString(pB64)
	if err != nil {
		return algo, 0
	}
	if algo == "ed25519" {
		return "ed25519", 256
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := pub.(*rsa.PublicKey); ok {
			return "rsa", rk.N.BitLen()
		}
	}
	if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return "rsa", rk.N.BitLen()
	}
	return algo, len(der) * 8
}

func RunMailDeliverabilityAudit(req MailAuditRequest, log LogFunc) (*MailAuditReport, error) {
	rawInput := cleanInputHost(req.Domain)
	rawMailHost := cleanInputHost(req.MailHost)
	if rawInput == "" && rawMailHost == "" {
		return nil, fmt.Errorf("введите почтовый домен (например, leend.by или csl.by) или адрес почтового сервера (mail.leend.by)")
	}
	if rawInput == "" {
		rawInput = rawMailHost
	}

	asciiInput, _, err := NormalizeDomain(rawInput)
	if err != nil {
		return nil, err
	}

	mailDomain := asciiInput
	mailHost := rawMailHost
	if mailHost != "" {
		if aHost, _, herr := NormalizeDomain(mailHost); herr == nil {
			mailHost = aHost
		}
	}

	// Smart separation of corporate email domain (@leend.by) vs mail server hostname (mail.leend.by)!
	// Crucial real-world case: user leaves "mail.leend.by" in Domain input AND/OR accidentally created MX/_dmarc on "mail.leend.by" in DNS!
	var straySubdomainMX []*net.MX
	var straySubdomainDMARC []string
	parts := strings.Split(asciiInput, ".")
	if len(parts) >= 3 && isKnownMailHostPrefix(parts[0]) {
		parentDomain := strings.Join(parts[1:], ".")
		if mailHost == "" {
			mailHost = asciiInput
		}
		// Check if user accidentally put stray records on mail.<domain> in their DNS panel!
		if smx, serr := lookupMXMulti(asciiInput); serr == nil && len(smx) > 0 {
			straySubdomainMX = smx
		}
		if sdt, sderr := lookupTXTQuick("_dmarc." + asciiInput); sderr == nil {
			for _, t := range sdt {
				if strings.Contains(strings.ToLower(t), "v=dmarc1") {
					straySubdomainDMARC = append(straySubdomainDMARC, strings.TrimSpace(t))
				}
			}
		}
		mailDomain = parentDomain
		log("info", fmt.Sprintf("Распознан адрес сервера %s → проверяем основной почтовый домен @%s и сервер %s", asciiInput, mailDomain, mailHost))
	}

	mxs, mxErr := lookupMXMulti(mailDomain)
	if mxErr != nil && len(parts) >= 3 && mailDomain == asciiInput {
		parentCandidate := strings.Join(parts[1:], ".")
		if parentMXs, perr := lookupMXMulti(parentCandidate); perr == nil && len(parentMXs) > 0 {
			if mailHost == "" {
				mailHost = asciiInput
			}
			mailDomain = parentCandidate
			mxs = parentMXs
			mxErr = nil
		} else if mailHost == "" {
			mailHost = asciiInput
			mailDomain = parentCandidate
		}
	}

	// Start live outbound WAN IP detection immediately in background (~60-120ms)
	var currentWANIP string
	var wanWG sync.WaitGroup
	wanWG.Add(1)
	go func() {
		defer wanWG.Done()
		currentWANIP = DetectPublicIPFast()
	}()

	if mailHost == "" {
		if len(mxs) > 0 {
			// Prefer MX host if it resolves to an EXTERNAL PUBLIC IP; otherwise prefer mail.<domain>!
			mxPrimary := mxs[0].Host
			if pubIPs := lookupPublicIPv4sExternal(mxPrimary); len(pubIPs) > 0 {
				mailHost = mxPrimary
			} else if mailPubIPs := lookupPublicIPv4sExternal("mail." + mailDomain); len(mailPubIPs) > 0 {
				mailHost = "mail." + mailDomain
			} else {
				mailHost = mxPrimary
			}
		} else {
			mailHost = "mail." + mailDomain
		}
	}

	// Also check if stray _dmarc.mail.<domain> exists even when user entered bare domain "leend.by"!
	if len(straySubdomainDMARC) == 0 {
		if sdt, sderr := lookupTXTQuick("_dmarc.mail." + mailDomain); sderr == nil {
			for _, t := range sdt {
				if strings.Contains(strings.ToLower(t), "v=dmarc1") {
					straySubdomainDMARC = append(straySubdomainDMARC, strings.TrimSpace(t))
				}
			}
		}
	}
	if len(straySubdomainMX) == 0 {
		if smx, serr := lookupMXMulti("mail." + mailDomain); serr == nil && len(smx) > 0 {
			straySubdomainMX = smx
		}
	}

	log("info", fmt.Sprintf("Запуск полного аудита почтового сервера: домен @%s, хост %s...", mailDomain, mailHost))

	report := &MailAuditReport{
		CheckedAt:  time.Now().Format("02.01.2006 15:04:05"),
		MailDomain: mailDomain,
		MailHost:   mailHost,
		Score:      100,
	}

	deduct := func(pts int) {
		report.Score -= pts
		if report.Score < 0 {
			report.Score = 0
		}
	}

	addIssue := func(chk MailCheckItem, rem MailRemediationGuide) {
		rem.CheckID = chk.ID
		remCopy := rem
		chk.Solution = &remCopy
		report.Checks = append(report.Checks, chk)
		report.Remediations = append(report.Remediations, remCopy)
	}

	// =========================================================================
	// 5-STAGE AUTOMATIC EXTERNAL PUBLIC IP DETECTION (FOR PTR / RBL / SPF / MX)
	// =========================================================================
	var serverIP string
	var serverIPSource string

	explicitPub := strings.TrimSpace(req.PublicIP)
	userOverrideHost := strings.TrimSpace(req.ServerIP)

	// Stage 0: Explicit public IP provided by user
	if explicitPub != "" && isGloballyRoutableIPv4(explicitPub) {
		serverIP = explicitPub
		serverIPSource = "указан вручную"
	} else if userOverrideHost != "" && isGloballyRoutableIPv4(userOverrideHost) {
		serverIP = userOverrideHost
		serverIPSource = "указан в параметрах проверки"
	}

	// Stage 1: Authoritative external public A record of mailHost (via DoH + 8.8.8.8/1.1.1.1 — bypasses Split-DNS!)
	if serverIP == "" {
		if pubIPs := lookupPublicIPv4sExternal(mailHost); len(pubIPs) > 0 {
			serverIP = pubIPs[0]
			serverIPSource = "автоопределён из внешней A-записи " + mailHost
		}
	}

	// Stage 2: Check candidate hosts in external DNS (mail.<domain>, MX hosts, smtp.<domain>, webmail.<domain>, root <domain>)
	if serverIP == "" {
		candidates := []string{"mail." + mailDomain}
		for _, m := range mxs {
			candidates = append(candidates, m.Host)
		}
		candidates = append(candidates, "smtp."+mailDomain, "webmail."+mailDomain, mailDomain)
		for _, cand := range candidates {
			if cand == "" || cand == mailHost {
				continue
			}
			if pubIPs := lookupPublicIPv4sExternal(cand); len(pubIPs) > 0 {
				serverIP = pubIPs[0]
				serverIPSource = "автоопределён из внешней A-записи " + cand
				break
			}
		}
	}

	// Stage 3: Extract public ip4:X.X.X.X from existing SPF TXT record if present
	if serverIP == "" {
		if txts, terr := lookupTXTQuick(mailDomain); terr == nil {
			for _, t := range txts {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
					for _, tok := range strings.Fields(t) {
						lowTok := strings.ToLower(tok)
						if strings.HasPrefix(lowTok, "ip4:") {
							ipPart := strings.Split(strings.TrimPrefix(lowTok, "ip4:"), "/")[0]
							if isGloballyRoutableIPv4(ipPart) {
								serverIP = ipPart
								serverIPSource = "автоопределён из SPF-записи домена (" + tok + ")"
								break
							}
						}
					}
				}
			}
		}
	}

	// Wait for fast background outbound WAN IP detection
	wanWG.Wait()
	report.CurrentWANIP = currentWANIP

	// Stage 4: Live outbound WAN IP auto-detection (works even if NO DNS A-records exist yet at all!)
	if serverIP == "" && isGloballyRoutableIPv4(currentWANIP) {
		serverIP = currentWANIP
		serverIPSource = "автоопределён по текущему внешнему выходу в Интернет (WAN IP)"
	}

	report.ServerIP = serverIP
	report.ServerIPSource = serverIPSource
	if serverIP != "" {
		log("info", fmt.Sprintf("🌐 Внешний белый IP для проверок PTR / RBL / SPF: %s (%s)", serverIP, serverIPSource))
	}

	var (
		ptrs              []string
		rbls              []RBLCheckEntry
		domRBLs           []RBLCheckEntry
		exposedAdmin      []string
		caaRecs           []string
		caaBlocksLE       bool
		mtaStsPolicy      string
		bimiRecs          []string
		smtp25            smtpLiveDetails
		smtp587           smtpLiveDetails
		port465           PortProbeResult
		port993           PortProbeResult
		port995           PortProbeResult
		port443           PortProbeResult
		dkimFoundSelector string
		dkimFoundRecord   string
		spfRecords        []string
		strayMailSPF      []string
		dmarcRecords      []string
		mtaStsRecords     []string
		tlsRptRecords     []string
		autodiscoverIPs   []string
		autodiscoverSRVs  []string
	)

	// Detect local Split-DNS LAN/VPN IP automatically (e.g. 10.146.100.14) so if external Hairpin NAT or ISP blocks port 25, we seamlessly check ports internally too!
	localSplitIP := lookupLocalSplitDNSIPv4(mailHost)
	if localSplitIP == "" && mailHost != "mail."+mailDomain {
		localSplitIP = lookupLocalSplitDNSIPv4("mail." + mailDomain)
	}

	probeTargetHost := mailHost
	if userOverrideHost != "" {
		probeTargetHost = userOverrideHost
	} else if serverIP != "" {
		probeTargetHost = serverIP
	}
	report.ProbeTargetUsed = probeTargetHost

	var wg sync.WaitGroup
	wg.Add(13)

	go func() {
		defer wg.Done()
		domRBLs = checkDomainBlacklists(mailDomain)
	}()

	go func() {
		defer wg.Done()
		exposedAdmin = checkExposedAdminPorts(serverIP)
	}()

	go func() {
		defer wg.Done()
		caaRecs, caaBlocksLE, mtaStsPolicy, bimiRecs = checkAdvancedDomainStandards(mailDomain)
	}()

	go func() {
		defer wg.Done()
		if serverIP != "" {
			ptrs = lookupPTRMulti(serverIP)
		}
	}()

	go func() {
		defer wg.Done()
		if parsed := net.ParseIP(serverIP); parsed != nil {
			rbls = checkExpandedDNSBLLists(parsed)
		}
	}()

	go func() {
		defer wg.Done()
		smtp25 = inspectSMTPPort(net.JoinHostPort(probeTargetHost, "25"), mailHost, true)
	}()

	go func() {
		defer wg.Done()
		smtp587 = inspectSMTPPort(net.JoinHostPort(probeTargetHost, "587"), mailHost, false)
	}()

	go func() {
		defer wg.Done()
		port465 = probeImplicitTLSPortSNI(probeTargetHost, mailHost, 465, "SMTPS (SSL отправка)")
	}()

	go func() {
		defer wg.Done()
		port993 = probeImplicitTLSPortSNI(probeTargetHost, mailHost, 993, "IMAPS (SSL почта)")
	}()

	go func() {
		defer wg.Done()
		port995 = probeImplicitTLSPortSNI(probeTargetHost, mailHost, 995, "POP3S (SSL сбор)")
	}()

	go func() {
		defer wg.Done()
		port443 = probeImplicitTLSPortSNI(probeTargetHost, mailHost, 443, "HTTPS (Kerio WebMail)")
	}()

	go func() {
		defer wg.Done()
		var txtWG sync.WaitGroup
		txtWG.Add(7)
		go func() {
			defer txtWG.Done()
			if txts, terr := lookupTXTQuick(mailDomain); terr == nil {
				for _, t := range txts {
					if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
						spfRecords = append(spfRecords, strings.TrimSpace(t))
					}
				}
			}
		}()
		go func() {
			defer txtWG.Done()
			if mtxts, mterr := lookupTXTQuick("mail." + mailDomain); mterr == nil {
				for _, t := range mtxts {
					if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
						strayMailSPF = append(strayMailSPF, strings.TrimSpace(t))
					}
				}
			}
		}()
		go func() {
			defer txtWG.Done()
			if dtxts, derr := lookupTXTQuick("_dmarc." + mailDomain); derr == nil {
				for _, t := range dtxts {
					if strings.Contains(strings.ToLower(t), "v=dmarc1") {
						dmarcRecords = append(dmarcRecords, strings.TrimSpace(t))
					}
				}
			}
		}()
		go func() {
			defer txtWG.Done()
			if stxts, serr := lookupTXTQuick("_mta-sts." + mailDomain); serr == nil {
				mtaStsRecords = stxts
			}
		}()
		go func() {
			defer txtWG.Done()
			if rtxts, rerr := lookupTXTQuick("_smtp._tls." + mailDomain); rerr == nil {
				tlsRptRecords = rtxts
			}
		}()
		go func() {
			defer txtWG.Done()
			if aips := lookupPublicIPv4sExternal("autodiscover." + mailDomain); len(aips) > 0 {
				autodiscoverIPs = aips
			}
		}()
		go func() {
			defer txtWG.Done()
			autodiscoverSRVs = lookupSRVAutodiscover(mailDomain)
		}()
		txtWG.Wait()
	}()

	go func() {
		defer wg.Done()
		selectors := []string{}
		if custom := strings.TrimSpace(req.DKIMSelector); custom != "" {
			custom = strings.TrimSuffix(custom, "._domainkey")
			selectors = append(selectors, custom)
		}
		for _, s := range []string{"mail", "default", "dkim", "kerio", "k1", "s1", "selector1", "selector2", "google", "yandex", "mailru", "smtp"} {
			exists := false
			for _, ex := range selectors {
				if strings.EqualFold(ex, s) {
					exists = true
				}
			}
			if !exists {
				selectors = append(selectors, s)
			}
		}
		var dmu sync.Mutex
		var dwg sync.WaitGroup
		for _, sel := range selectors {
			dwg.Add(1)
			go func(selector string) {
				defer dwg.Done()
				fqdn := selector + "._domainkey." + mailDomain
				if txts, err := lookupTXTQuick(fqdn); err == nil {
					for _, t := range txts {
						if strings.Contains(strings.ToLower(t), "p=") || strings.Contains(strings.ToLower(t), "v=dkim1") {
							dmu.Lock()
							if dkimFoundRecord == "" || strings.EqualFold(selector, req.DKIMSelector) || selector == "mail" {
								dkimFoundSelector = selector
								dkimFoundRecord = t
							}
							dmu.Unlock()
						}
					}
				}
			}(sel)
		}
		dwg.Wait()
	}()

	wg.Wait()

	// Smart Hairpin-NAT / ISP port-25 bypass: if probing via public IP could not connect on TCP :25 AND local Split-DNS resolved an internal LAN IP (e.g. 10.146.100.14), automatically re-probe ports against the internal IP!
	if !smtp25.Reachable && userOverrideHost == "" && localSplitIP != "" && localSplitIP != probeTargetHost {
		log("info", fmt.Sprintf("🔌 Внешний порт %s:25 недоступен из вашей сети (Hairpin NAT / фильтр провайдера) — автопереключение проверки портов на локальный Split-DNS IP %s...", probeTargetHost, localSplitIP))
		var rwg sync.WaitGroup
		rwg.Add(6)
		go func() {
			defer rwg.Done()
			smtp25 = inspectSMTPPort(net.JoinHostPort(localSplitIP, "25"), mailHost, true)
		}()
		go func() {
			defer rwg.Done()
			smtp587 = inspectSMTPPort(net.JoinHostPort(localSplitIP, "587"), mailHost, false)
		}()
		go func() {
			defer rwg.Done()
			if !port465.Open {
				port465 = probeImplicitTLSPortSNI(localSplitIP, mailHost, 465, "SMTPS (SSL отправка)")
			}
		}()
		go func() {
			defer rwg.Done()
			if !port993.Open {
				port993 = probeImplicitTLSPortSNI(localSplitIP, mailHost, 993, "IMAPS (SSL почта)")
			}
		}()
		go func() {
			defer rwg.Done()
			if !port995.Open {
				port995 = probeImplicitTLSPortSNI(localSplitIP, mailHost, 995, "POP3S (SSL сбор)")
			}
		}()
		go func() {
			defer rwg.Done()
			if !port443.Open {
				port443 = probeImplicitTLSPortSNI(localSplitIP, mailHost, 443, "HTTPS (Kerio WebMail)")
			}
		}()
		rwg.Wait()
		probeTargetHost = localSplitIP
		report.ProbeTargetUsed = localSplitIP + " (автоопределён из локального Split-DNS)"
	}

	// Build port summary slice
	p25 := PortProbeResult{
		Port:      25,
		Protocol:  "SMTP (приём писем + STARTTLS)",
		Open:      smtp25.Reachable,
		LatencyMs: smtp25.LatencyMs,
		Banner:    smtp25.BannerLine,
		Error:     smtp25.DialErr,
	}
	if smtp25.TLSState != nil {
		p25.TLSOK = true
		p25.TLSTrusted = smtp25.TLSVerified
		p25.TLSVersion = tlsVersionName(smtp25.TLSState.Version)
		if !smtp25.TLSVerified {
			p25.Error = smtp25.TLSVerifyErr
		}
		if len(smtp25.TLSState.PeerCertificates) > 0 {
			leaf := smtp25.TLSState.PeerCertificates[0]
			p25.CertSubject = leaf.Subject.CommonName
			p25.CertIssuer = leaf.Issuer.CommonName
			p25.CertExpiry = leaf.NotAfter.Format("02.01.2006")
			p25.CertDays = int(time.Until(leaf.NotAfter).Hours() / 24)
		}
	}

	p587 := PortProbeResult{
		Port:      587,
		Protocol:  "Submission (отправка STARTTLS)",
		Open:      smtp587.Reachable,
		LatencyMs: smtp587.LatencyMs,
		Banner:    smtp587.BannerLine,
		Error:     smtp587.DialErr,
	}
	if smtp587.TLSState != nil {
		p587.TLSOK = true
		p587.TLSTrusted = smtp587.TLSVerified
		p587.TLSVersion = tlsVersionName(smtp587.TLSState.Version)
		if !smtp587.TLSVerified {
			p587.Error = smtp587.TLSVerifyErr
		}
		if len(smtp587.TLSState.PeerCertificates) > 0 {
			leaf := smtp587.TLSState.PeerCertificates[0]
			p587.CertSubject = leaf.Subject.CommonName
			p587.CertIssuer = leaf.Issuer.CommonName
			p587.CertExpiry = leaf.NotAfter.Format("02.01.2006")
			p587.CertDays = int(time.Until(leaf.NotAfter).Hours() / 24)
		}
	}

	report.Ports = []PortProbeResult{p25, port465, p587, port993, port995, port443}
	report.Blacklists = rbls

	recommendedHost := "mail." + mailDomain
	if mailHost != "" && mailHost != mailDomain {
		recommendedHost = mailHost
	}
	ipDisplay := nonEmptyOr(serverIP, "<ВАШ_БЕЛЫЙ_IP>")

	// =========================================================================
	// CHECK 1: MX RECORDS & A-RECORD RESOLUTION (WITH STRAY SUBDOMAIN DETECTION!)
	// =========================================================================
	if len(mxs) == 0 {
		deduct(20)
		details := []string{"У корневого почтового домена @" + mailDomain + " в DNS нет записи типа MX."}
		if len(straySubdomainMX) > 0 {
			details = append(details, fmt.Sprintf("⚠️ НАЙДЕНА ТИПИЧНАЯ ОШИБКА В ПАНЕЛИ DNS: MX-запись сейчас ошибочно висит на поддомене mail.%s (указывает на %s) вместо корневого домена %s!", mailDomain, straySubdomainMX[0].Host, mailDomain))
		}
		addIssue(
			MailCheckItem{
				ID:       "mx",
				Category: "DNS Маршрутизация входящей почты",
				Title:    "Записи приёма почты (DNS MX и A-запись сервера)",
				Status:   "error",
				Summary:  fmt.Sprintf("У домена @%s отсутствует корректная MX-запись — внешние отправители не знают, на какой сервер доставлять вам письма!", mailDomain),
				Details:  details,
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "DNS Маршрутизация (MX + A)",
				Title:        fmt.Sprintf("Настройте связку A + MX записей для домена %s в панели управления DNS", mailDomain),
				WhyItMatters: fmt.Sprintf("Когда клиент пишет письмо на info@%s, почтовые серверы Gmail/Yandex/Mail.ru ищут MX-запись именно у корневого домена «%s» (НЕ у mail.%s!). Если в панели hoster.by / Cloudflare в поле «Имя / Хост» у MX-записи случайно написано «mail» вместо «@», входящая почта на @%s не доставляется!", mailDomain, mailDomain, mailDomain, mailDomain),
				Steps: []string{
					fmt.Sprintf("Войдите в личный кабинет вашего регистратора / DNS-хостинга домена %s (hoster.by, active.by, Cloudflare, ISPmanager, reg.ru) → раздел «Управление DNS-записями / Редактор DNS-зоны».", mailDomain),
					fmt.Sprintf("Проверьте наличие записи типа A для почтового хоста: Тип = A, Имя (Субдомен/Хост) = mail, Значение (IPv4) = %s, TTL = 3600.", ipDisplay),
					fmt.Sprintf("Если в списке есть ошибочная запись MX с именем «mail» или «mail.%s» — удалите её или исправьте поле «Имя».", mailDomain),
					fmt.Sprintf("Создайте (или отредактируйте) корневую запись MX: Тип = MX, Имя (Хост) = @ (в некоторых панелях оставляется пустым или пишется %s. с точкой на конце), Приоритет = 10, Значение (Сервер почты) = %s (в ISPmanager / BIND — обязательно с точкой на конце: %s.).", mailDomain, recommendedHost, recommendedHost),
					"Сохраните изменения DNS-зоны и подождите 5–15 минут обновления кэша.",
				},
				VerifyCmd: fmt.Sprintf("nslookup -type=mx %s 8.8.8.8", mailDomain),
				CopyItems: []CopySnippet{
					{Label: "1. Запись A — Поле «Имя»", Value: "mail"},
					{Label: "1. Запись A — Поле «Значение (IP)»", Value: ipDisplay},
					{Label: "2. Запись MX — Поле «Имя (Хост)»", Value: "@"},
					{Label: "2. Запись MX — Поле «Значение (Сервер, приоритет 10)»", Value: recommendedHost},
				},
			},
		)
	} else {
		var mxDetails []string
		mxPointsToIP := false
		mxUnresolvableHost := ""
		for _, m := range mxs {
			ips := lookupPublicIPv4sExternal(m.Host)
			if net.ParseIP(m.Host) != nil {
				mxPointsToIP = true
			}
			if len(ips) == 0 && mxUnresolvableHost == "" {
				mxUnresolvableHost = m.Host
			}
			ipText := strings.Join(ips, ", ")
			if ipText == "" {
				ipText = "❌ НЕТ A-ЗАПИСИ (no such host)!"
			}
			mxDetails = append(mxDetails, fmt.Sprintf("Приоритет %d → %s (%s)", m.Pref, m.Host, ipText))
		}
		if len(straySubdomainMX) > 0 {
			mxDetails = append(mxDetails, fmt.Sprintf("Примечание: на поддомене mail.%s также обнаружена лишняя MX-запись → %s (её лучше удалить, чтобы не путать DNS).", mailDomain, straySubdomainMX[0].Host))
		}

		if mxUnresolvableHost != "" {
			deduct(20)
			addIssue(
				MailCheckItem{
					ID:       "mx",
					Category: "DNS Маршрутизация входящей почты",
					Title:    "Записи приёма почты (DNS MX и A-запись сервера)",
					Status:   "error",
					Summary:  fmt.Sprintf("КРИТИЧЕСКАЯ ОШИБКА DNS: MX-запись указывает на хост «%s», у которого НЕТ A-записи (не резолвится в IP)! Входящие письма не могут быть доставлены!", mxUnresolvableHost),
					Details:  mxDetails,
				},
				MailRemediationGuide{
					Severity:     "critical",
					Category:     "DNS Маршрутизация (MX → A)",
					Title:        fmt.Sprintf("Исправьте MX-запись домена %s: укажите %s (или добавьте A-запись %s)", mailDomain, recommendedHost, ipDisplay),
					WhyItMatters: fmt.Sprintf("Сейчас MX-запись домена %s отправляет всю входящую почту на адрес «%s», но у «%s» нет IP-адреса в DNS (lookup %s: no such host), тогда как реальный сервер работает на %s (%s)! Из-за этого внешние отправители получают отказ доставки.", mailDomain, mxUnresolvableHost, mxUnresolvableHost, mxUnresolvableHost, recommendedHost, ipDisplay),
					Steps: []string{
						fmt.Sprintf("Откройте панель управления DNS домена %s (hoster.by / active.by / Cloudflare / ISPmanager).", mailDomain),
						fmt.Sprintf("Найдите запись типа MX для @ (%s) и измените её значение с «%s» на «%s» (Приоритет = 10).", mailDomain, mxUnresolvableHost, recommendedHost),
						fmt.Sprintf("Убедитесь, что запись типа A с именем «mail» указывает на белый IP вашего Kerio Connect: %s (и по желанию добавьте также корневую A-запись: Имя = @, Значение = %s).", ipDisplay, ipDisplay),
						fmt.Sprintf("Если в панели есть перевёрнутая запись MX (где Имя = mail, а Значение = %s) — удалите её!", mailDomain),
					},
					VerifyCmd: fmt.Sprintf("nslookup -type=mx %s 8.8.8.8", mailDomain),
					CopyItems: []CopySnippet{
						{Label: "Исправленная запись MX (Имя = @, Приоритет = 10)", Value: recommendedHost},
						{Label: "Запись A для сервера (Имя = mail)", Value: ipDisplay},
					},
				},
			)
		} else if mxPointsToIP {
			deduct(10)
			addIssue(
				MailCheckItem{
					ID:       "mx",
					Category: "DNS Маршрутизация входящей почты",
					Title:    "Записи приёма почты (DNS MX и A-запись сервера)",
					Status:   "warning",
					Summary:  "MX-запись указывает напрямую на цифровой IP-адрес вместо доменного имени mail." + mailDomain + " (нарушение RFC 5321)!",
					Details:  mxDetails,
				},
				MailRemediationGuide{
					Severity:     "warning",
					Category:     "DNS Маршрутизация (MX)",
					Title:        fmt.Sprintf("Замените IP-адрес в MX-записи на доменное имя %s", recommendedHost),
					WhyItMatters: "По стандарту RFC 5321 в значении MX запрещено указывать цифры IP-адреса — многие корпоративные почтовые шлюзы и антиспам-системы отклоняют такие домены.",
					Steps: []string{
						fmt.Sprintf("В панели DNS создайте запись типа A: Имя = mail, Значение = %s.", ipDisplay),
						fmt.Sprintf("Откройте запись MX (Имя = @, Приоритет = 10) и замените IP-адрес на доменное имя: %s.", recommendedHost),
					},
					VerifyCmd: fmt.Sprintf("nslookup -type=mx %s 8.8.8.8", mailDomain),
					CopyItems: []CopySnippet{
						{Label: "Правильное значение MX (Имя = @, Приоритет = 10)", Value: recommendedHost},
					},
				},
			)
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "mx",
				Category: "DNS Маршрутизация входящей почты",
				Title:    "Записи приёма почты (DNS MX и A-запись сервера)",
				Status:   "ok",
				Summary:  fmt.Sprintf("Отлично! Найдено %d MX-записей (основной сервер: %s → %s)", len(mxs), mxs[0].Host, ipDisplay),
				Details:  mxDetails,
			})
		}
	}

	// =========================================================================
	// CHECK 2: REVERSE DNS (PTR) & FCrDNS — #1 SPAM / 550 REJECT CAUSE!
	// =========================================================================
	if serverIP == "" || net.ParseIP(serverIP) == nil || net.ParseIP(serverIP).IsPrivate() || net.ParseIP(serverIP).IsLoopback() {
		deduct(18)
		addIssue(
			MailCheckItem{
				ID:       "ptr",
				Category: "Обратная зона интернет-провайдера (PTR / rDNS)",
				Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
				Status:   "error",
				Summary:  fmt.Sprintf("Не удалось определить внешний белый IP-адрес для %s — невозможно проверить обратную запись PTR у провайдера!", recommendedHost),
				Details: []string{
					fmt.Sprintf("Проверенный хост почтового сервера: %s", recommendedHost),
					"Сначала добавьте в DNS запись типа A (mail." + mailDomain + " → внешний статический IP вашего роутера/сервера), чтобы публичный интернет видел IP почтового сервера.",
				},
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Обратная зона провайдера (A + PTR / rDNS)",
				Title:        fmt.Sprintf("Шаг 1: Пропишите A-запись %s → белый IP, затем закажите PTR у интернет-провайдера", recommendedHost),
				WhyItMatters: "Любой почтовый сервер в мире (Gmail, Mail.ru, Yandex, Outlook) при приёме письма от вашего Kerio Connect проверяет две вещи: 1) Прямую A-запись (mail." + mailDomain + " → ваш белый IP) в вашей панели домена, и 2) Обратную PTR-запись (ваш белый IP → mail." + mailDomain + ") на оборудовании вашего интернет-провайдера! Без этой связки письма блокируются с кодом 550 5.7.1 Client host rejected: cannot find your reverse hostname.",
				Steps: []string{
					"Узнайте точный внешний статический (белый) IP-адрес, через который Kerio Connect выходит в интернет (посмотрите WAN-интерфейс в Kerio Control / MikroTik или откройте https://ifconfig.me с самого почтового сервера).",
					fmt.Sprintf("В панели управления доменом %s (hoster.by / Cloudflare / active.by) добавьте запись: Тип = A, Имя = mail, Значение = ваш белый IP.", mailDomain),
					fmt.Sprintf("Напишите заявку вашему интернет-провайдеру (Белтелеком / A1 / МТС / Деловая сеть / хостер VPS) — ВНИМАНИЕ: запись PTR прописывается ТОЛЬКО интернет-провайдером (владельцем подсети IP), в панели hoster.by её создать нельзя!", ),
					fmt.Sprintf("Попросите провайдера прописать PTR-запись для вашего белого IP на имя %s, после чего нажмите «Проверить почтовый сервер» ещё раз!", recommendedHost),
				},
				VerifyCmd: fmt.Sprintf("nslookup %s 8.8.8.8", recommendedHost),
				CopyItems: []CopySnippet{
					{
						Label: "Готовый шаблон письма в техподдержку интернет-провайдера (вставьте ваш белый IP)",
						Value: fmt.Sprintf("Здравствуйте! Просим прописать обратную DNS-запись (PTR / rDNS) для нашего статического внешнего IP-адреса [ВСТАВЬТЕ_БЕЛЫЙ_IP] на доменное имя нашего почтового сервера: %s. Прямая A-запись %s -> [ВСТАВЬТЕ_БЕЛЫЙ_IP] в DNS настроена. Спасибо!", recommendedHost, recommendedHost),
					},
				},
			},
		)
	} else if len(ptrs) == 0 {
		deduct(22)
		addIssue(
			MailCheckItem{
				ID:       "ptr",
				Category: "Обратная зона интернет-провайдера (PTR / rDNS)",
				Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
				Status:   "error",
				Summary:  fmt.Sprintf("У внешнего IP-адреса %s НЕТ обратной записи PTR! Письма на Gmail, Mail.ru, Yandex и корпоративные серверы отклоняются с ошибкой 550 5.7.1 или падают в СПАМ!", serverIP),
				Details: []string{
					"Внешний белый IP вашего сервера: " + serverIP,
					"Должна возвращаться PTR-запись: " + recommendedHost,
					"Текущий ответ обратного DNS: ПУСТО (NXDOMAIN)",
				},
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Обратная зона интернет-провайдера (PTR / rDNS)",
				Title:        fmt.Sprintf("Закажите бесплатное добавление записи PTR у интернет-провайдера: %s → %s", serverIP, recommendedHost),
				WhyItMatters: fmt.Sprintf("Отсутствие PTR — ПРИЧИНА №1 в Беларуси и СНГ, по которой почта с нового сервера Kerio Connect не доходит или попадает в СПАМ! ВАЖНО ЗНАТЬ: запись PTR хранится НЕ у регистратора домена (НЕ в hoster.by / Cloudflare), а на DNS-серверах интернет-провайдера, который выдал вам статический IP %s (Белтелеком / ByFly Бизнес, A1, МТС, Деловая сеть или VPS-хостер)!", serverIP),
				Steps: []string{
					fmt.Sprintf("Убедитесь, что прямая A-запись уже работает: %s → %s (многие провайдеры проверяют наличие A-записи перед прописыванием PTR).", recommendedHost, serverIP),
					"Скопируйте готовый текст заявки кнопкой «Копировать» ниже (в него уже подставлены ваш IP и имя сервера!).",
					"Отправьте заявку вашему интернет-провайдеру: • Для Белтелеком (юрлица): через кабинет юрлица или на email техподдержки вашего филиала (support@belpak.by / support@mgts.by, указав номер договора и лицевой счёт). • Для A1 / МТС / Деловая сеть: на email корпоративной техподдержки с указанием договора. • Для облачного VPS: прямо в панели управления виртуальным сервером в разделе «Сеть / IP-адреса → Обратная запись (rDNS / PTR)».",
					"После ответа провайдера (обычно от 15 минут до 2–4 часов) нажмите «Проверить почтовый сервер» на этой вкладке — пункт загорится зелёным!",
				},
				VerifyCmd: fmt.Sprintf("nslookup %s 8.8.8.8", serverIP),
				CopyItems: []CopySnippet{
					{
						Label: "Готовый текст письма провайдеру интернета (Белтелеком / A1 / МТС)",
						Value: fmt.Sprintf("Здравствуйте! Договор № [УКАЖИТЕ_НОМЕР_ДОГОВОРА]. Просим прописать обратную DNS-запись (PTR / rDNS) для нашего статического IP-адреса %s на доменное имя почтового сервера: %s. Прямая A-запись %s -> %s настроена. Заранее спасибо!", serverIP, recommendedHost, recommendedHost, serverIP),
					},
					{
						Label: "Точное значение PTR (если заполняете в панели VPS сами)",
						Value: recommendedHost,
					},
				},
			},
		)
	} else {
		exactMatch := false
		fcrdnsOK := false
		genericISP := false
		for _, p := range ptrs {
			if strings.EqualFold(p, recommendedHost) {
				exactMatch = true
			}
			low := strings.ToLower(p)
			for _, bad := range []string{"pool", "dynamic", "dhcp", "pppoe", "broadband", "dsl", "cable", "nat"} {
				if strings.Contains(low, bad) {
					genericISP = true
				}
			}
			if fwdIPs := lookupPublicIPv4sExternal(p); len(fwdIPs) > 0 {
				for _, fip := range fwdIPs {
					if fip == serverIP {
						fcrdnsOK = true
					}
				}
			}
		}
		if exactMatch && fcrdnsOK {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "ptr",
				Category: "Обратная зона интернет-провайдера (PTR / rDNS)",
				Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
				Status:   "ok",
				Summary:  fmt.Sprintf("Идеально! IP %s имеет PTR-запись %s, полностью совпадающую с прямой A-записью (FCrDNS OK)", serverIP, ptrs[0]),
				Details:  []string{fmt.Sprintf("%s ↔ %s (двусторонняя проверка FCrDNS пройдена)", serverIP, strings.Join(ptrs, ", "))},
			})
		} else {
			deduct(10)
			addIssue(
				MailCheckItem{
					ID:       "ptr",
					Category: "Обратная зона интернет-провайдера (PTR / rDNS)",
					Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
					Status:   "warning",
					Summary:  fmt.Sprintf("PTR-запись у IP %s есть («%s»), но НЕ совпадает с именем почтового сервера «%s»!", serverIP, strings.Join(ptrs, ", "), recommendedHost),
					Details: []string{
						"Текущая PTR-запись провайдера: " + strings.Join(ptrs, ", "),
						"Ожидаемое имя почтового сервера: " + recommendedHost,
						fmt.Sprintf("Проверка FCrDNS (PTR → A → %s): %v | Похоже на дефолтный пул провайдера: %v", serverIP, fcrdnsOK, genericISP),
					},
				},
				MailRemediationGuide{
					Severity:     "warning",
					Category:     "Обратная зона интернет-провайдера (PTR / rDNS)",
					Title:        fmt.Sprintf("Попросите провайдера изменить PTR-запись IP %s с «%s» на «%s»", serverIP, ptrs[0], recommendedHost),
					WhyItMatters: fmt.Sprintf("Сейчас обратная запись вашего IP выглядит как технический адрес провайдера («%s»), особенно если в ней есть слова pool / dynamic / static / byfly. Антиспам-фильтры Gmail, Outlook и SpamAssassin начисляют за это штрафные баллы RDNS_DYNAMIC / FCrDNS mismatch.", ptrs[0]),
					Steps: []string{
						fmt.Sprintf("Убедитесь, что в вашей панели DNS есть прямая A-запись: %s → %s.", recommendedHost, serverIP),
						fmt.Sprintf("Отправьте интернет-провайдеру (или измените в панели VPS) заявку на смену PTR для IP %s на %s (готовый текст ниже):", serverIP, recommendedHost),
					},
					VerifyCmd: fmt.Sprintf("nslookup %s 8.8.8.8", serverIP),
					CopyItems: []CopySnippet{
						{
							Label: "Готовый текст заявки провайдеру на замену PTR",
							Value: fmt.Sprintf("Здравствуйте! Просим изменить обратную запись PTR (rDNS) для нашего статического IP-адреса %s с текущего значения %s на имя нашего почтового сервера: %s. Прямая A-запись %s -> %s настроена. Спасибо!", serverIP, ptrs[0], recommendedHost, recommendedHost, serverIP),
						},
					},
				},
			)
		}
	}

	// =========================================================================
	// CHECK 3: SPF RECORD (v=spf1)
	// =========================================================================
	recommendedSPF := fmt.Sprintf("v=spf1 mx a:%s ~all", recommendedHost)
	if serverIP != "" && net.ParseIP(serverIP) != nil && !net.ParseIP(serverIP).IsPrivate() {
		recommendedSPF = fmt.Sprintf("v=spf1 mx a:%s ip4:%s ~all", recommendedHost, serverIP)
	}
	if len(spfRecords) == 0 {
		deduct(18)
		spfDetails := []string{
			"Проверенный домен отправителя (после @ в email): " + mailDomain,
			"Рекомендуемая готовая запись: " + recommendedSPF,
		}
		if len(strayMailSPF) > 0 {
			spfDetails = append(spfDetails, fmt.Sprintf("⚠️ ВНИМАНИЕ: Обнаружена SPF-запись на поддомене mail.%s (%s) вместо корневого домена %s! Её нужно перенести на @ (%s)!", mailDomain, strayMailSPF[0], mailDomain, mailDomain))
		}
		addIssue(
			MailCheckItem{
				ID:       "spf",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Запись SPF (разрешённые серверы отправки для @" + mailDomain + ")",
				Status:   "error",
				Summary:  fmt.Sprintf("У домена %s НЕТ SPF-записи! Письма на Gmail, Yahoo, Outlook и Mail.ru попадают в СПАМ или отклоняются с ошибкой 550 5.7.26!", mailDomain),
				Details:  spfDetails,
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Аутентификация отправителя (DNS TXT — SPF)",
				Title:        fmt.Sprintf("Добавьте готовую TXT-запись SPF для домена %s (займёт 1 минуту)", mailDomain),
				WhyItMatters: fmt.Sprintf("Запись SPF официально сообщает всем почтовым сервисам мира, что отправлять письма от имени @%s имеет право именно ваш сервер %s (%s). Без SPF Google Gmail и Mail.ru с 2024 года блокируют письма с ошибкой «550-5.7.26 This mail has been blocked because the sender is unauthenticated».", mailDomain, recommendedHost, ipDisplay),
				Steps: []string{
					fmt.Sprintf("Войдите в панель управления DNS домена %s (hoster.by, active.by, Cloudflare, ISPmanager).", mailDomain),
					"Нажмите «Добавить запись» → выберите Тип записи: TXT.",
					fmt.Sprintf("В поле «Имя / Субдомен / Хост» укажите символ @ (или оставьте поле пустым, если в вашей панели корень домена %s обозначается пустым полем; НЕ пишите слово mail!).", mailDomain),
					"Скопируйте кнопкой ниже готовую строку SPF и вставьте её в поле «Значение / Текст» (без лишних кавычек по краям — панель добавит их сама).",
					"Примечание: если ваш корпоративный сайт на хостинге (например, Bitrix / WordPress) тоже отправляет уведомления о заказах от имени @" + mailDomain + ", добавьте перед ~all также ip4:IP_САЙТА (например: " + strings.Replace(recommendedSPF, "~all", "ip4:IP_ВАШЕГО_САЙТА ~all", 1) + ").",
					"Нажмите «Сохранить» — запись начнёт действовать в течение 5–10 минут!",
				},
				VerifyCmd: fmt.Sprintf("nslookup -type=txt %s 8.8.8.8", mailDomain),
				CopyItems: []CopySnippet{
					{Label: "Тип записи: TXT  |  Поле «Имя / Хост»", Value: "@"},
					{Label: "Поле «Значение TXT» (готовая строка под ваш сервер)", Value: recommendedSPF},
				},
			},
		)
	} else if len(spfRecords) > 1 {
		deduct(16)
		addIssue(
			MailCheckItem{
				ID:       "spf",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Запись SPF (разрешённые серверы отправки для @" + mailDomain + ")",
				Status:   "error",
				Summary:  fmt.Sprintf("КРИТИЧЕСКАЯ ОШИБКА: у домена %s найдено сразу %d разных SPF-записей! По стандарту RFC 7208 это аннулирует обе записи (SPF PermError)!", mailDomain, len(spfRecords)),
				Details:  spfRecords,
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Аутентификация отправителя (DNS TXT — SPF)",
				Title:        fmt.Sprintf("Объедините %d записи v=spf1 в ОДНУ запись TXT в панели DNS", len(spfRecords)),
				WhyItMatters: "По стандарту RFC 7208 у домена может существовать строго ОДНА запись, начинающаяся с v=spf1. Когда админы добавляют вторую строку v=spf1 (например, одну для хостинга сайта и вторую для Kerio), все почтовые серверы возвращают статус PermError (постоянная ошибка SPF)!",
				Steps: []string{
					fmt.Sprintf("Откройте панель DNS домена %s и найдите все TXT-записи, начинающиеся с v=spf1.", mailDomain),
					"Удалите дубликаты и оставьте только ОДНУ запись TXT (Имя = @), объединив в ней все ваши серверы (ip4:... и include:...) перед завершающим ~all.",
				},
				VerifyCmd: fmt.Sprintf("nslookup -type=txt %s 8.8.8.8", mailDomain),
				CopyItems: []CopySnippet{
					{Label: "Единая базовая запись SPF для вашего Kerio Connect", Value: recommendedSPF},
				},
			},
		)
	} else {
		spf := spfRecords[0]
		lowSPF := strings.ToLower(spf)
		hasPlusAll := strings.Contains(lowSPF, "+all")
		coversServer := strings.Contains(lowSPF, "mx") ||
			(serverIP != "" && strings.Contains(lowSPF, serverIP)) ||
			strings.Contains(lowSPF, recommendedHost)
		if hasPlusAll {
			deduct(20)
			addIssue(
				MailCheckItem{
					ID:       "spf",
					Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
					Title:    "Запись SPF (разрешённые серверы отправки для @" + mailDomain + ")",
					Status:   "error",
					Summary:  "ОПАСНО: в SPF-записи стоит '+all' — вы официально разрешили ЛЮБОМУ спамеру мира слать поддельные письма от @" + mailDomain + "!",
					Details:  []string{"Текущая опасная запись: " + spf},
				},
				MailRemediationGuide{
					Severity:     "critical",
					Category:     "Аутентификация отправителя (DNS TXT — SPF)",
					Title:        "Срочно замените '+all' на '~all' в вашей TXT-записи SPF",
					WhyItMatters: "Знак '+all' в конце SPF означает «разрешить отправку с любого IP-адреса в интернете». Большинство спам-фильтров отправляют домены с +all прямиком в Спам.",
					Steps: []string{
						fmt.Sprintf("В панели DNS домена %s откройте TXT-запись «%s» и замените её на безопасную строку ниже:", mailDomain, spf),
					},
					VerifyCmd: fmt.Sprintf("nslookup -type=txt %s 8.8.8.8", mailDomain),
					CopyItems: []CopySnippet{
						{Label: "Исправленное значение TXT (SPF)", Value: recommendedSPF},
					},
				},
			)
		} else if !coversServer {
			deduct(14)
			mergedSPF := strings.TrimSpace(strings.Replace(spf, "~all", "", 1))
			mergedSPF = strings.TrimSpace(strings.Replace(mergedSPF, "-all", "", 1))
			mergedSPF = strings.TrimSpace(strings.Replace(mergedSPF, "?all", "", 1)) + fmt.Sprintf(" mx a:%s ip4:%s ~all", recommendedHost, ipDisplay)
			addIssue(
				MailCheckItem{
					ID:       "spf",
					Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
					Title:    "Запись SPF (разрешённые серверы отправки для @" + mailDomain + ")",
					Status:   "warning",
					Summary:  fmt.Sprintf("Запись SPF есть, но в ней НЕ разрешён ваш сервер Kerio Connect (%s / %s)! Письма с Kerio получают статус SPF SoftFail → СПАМ!", recommendedHost, ipDisplay),
					Details:  []string{"Текущая запись (скорее всего осталась от старого хостинга): " + spf},
				},
				MailRemediationGuide{
					Severity:     "critical",
					Category:     "Аутентификация отправителя (DNS TXT — SPF)",
					Title:        fmt.Sprintf("Добавьте сервер Kerio (%s) в существующую SPF-запись домена %s", ipDisplay, mailDomain),
					WhyItMatters: "Частая ситуация: домен перенесли на свой Kerio Connect в офисе, а в DNS осталась старая SPF-запись веб-хостинга. В итоге каждый исходящий email с офисного IP проваливает проверку SPF!",
					Steps: []string{
						fmt.Sprintf("Откройте существующую TXT-запись v=spf1 в панели DNS домена %s (НЕ создавайте вторую запись — отредактируйте существующую!).", mailDomain),
						"Замените её текст на готовый объединённый вариант ниже (мы сохранили ваши текущие правила и добавили Kerio Connect):",
					},
					VerifyCmd: fmt.Sprintf("nslookup -type=txt %s 8.8.8.8", mailDomain),
					CopyItems: []CopySnippet{
						{Label: "Готовая объединённая TXT-запись SPF", Value: mergedSPF},
					},
				},
			)
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "spf",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Запись SPF (разрешённые серверы отправки для @" + mailDomain + ")",
				Status:   "ok",
				Summary:  "SPF-запись настроена правильно и разрешает отправку вашему серверу: " + spf,
				Details:  []string{"Активная TXT-запись: " + spf},
			})
		}
	}

	// =========================================================================
	// CHECK 4: DKIM SIGNATURE (Kerio built-in "mail._domainkey" + auto-scan)
	// =========================================================================
	if dkimFoundRecord == "" {
		deduct(16)
		addIssue(
			MailCheckItem{
				ID:       "dkim",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Цифровая криптографическая подпись писем (DKIM)",
				Status:   "error",
				Summary:  fmt.Sprintf("Не настроена цифровая подпись DKIM (проверены mail._domainkey.%s и ещё 11 селекторов)! В Kerio Connect это включается штатной галочкой за 2 минуты.", mailDomain),
				Details: []string{
					"Штатное имя DKIM-записи для Kerio Connect: mail._domainkey." + mailDomain,
					"Без подписи DKIM письма со счетами, актами, PDF/DOCX/XLSX и ссылками массово отфильтровываются в папку «Спам» в Gmail, Outlook и Mail.ru.",
				},
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Kerio Connect Admin + Панель DNS (DKIM)",
				Title:        fmt.Sprintf("Пошаговое включение подписи DKIM в Kerio Connect для домена %s", mailDomain),
				WhyItMatters: "В Kerio Connect встроен готовый генератор ключей DKIM — никаких сторонних плагинов ставить НЕ нужно! Kerio подписывает заголовок и тело каждого исходящего письма закрытым ключом, а Gmail / Yandex / Mail.ru проверяют подпись по открытому ключу из DNS и гарантируют, что письмо подлинное и не подделано.",
				Steps: []string{
					fmt.Sprintf("Откройте консоль администрирования Kerio Connect (например, https://10.146.100.14:4040/admin/ или https://%s:4040/admin/).", recommendedHost),
					fmt.Sprintf("В левом меню перейдите в «Конфигурация» (Configuration) → «Домены» (Domains) → дважды кликните на ваш домен «%s».", mailDomain),
					"В открывшемся окне «Изменить домен» на первой вкладке «Общие» (General) внизу найдите блок DomainKeys (DKIM).",
					"Поставьте галочку «Подписывать исходящие сообщения этого домена ключом DomainKeys Identified Mail (DKIM)».",
					"Нажмите единственную кнопку/ссылку под галочкой — «Показать открытый ключ... (Show public key...)» — откроется окошко с готовой записью вида: v=DKIM1; k=rsa; p=MIIBIjANBg... Скопируйте это значение ЦЕЛИКОМ!",
					fmt.Sprintf("Откройте панель управления DNS вашего домена %s и создайте новую запись: • Тип записи: TXT • Поле «Имя / Субдомен»: mail._domainkey (ВНИМАНИЕ: в hoster.by / active.by / Cloudflare пишите ТОЛЬКО mail._domainkey — НЕ дописывайте .%s! В ISPmanager пишите с точкой в самом конце: mail._domainkey.%s.) • Поле «Значение»: вставьте скопированную строку v=DKIM1; k=rsa; p=...", mailDomain, mailDomain, mailDomain),
					"Подождите 3–5 минут и нажмите кнопку «ОК» внизу окна «Изменить домен» в Kerio Connect (отдельной кнопки «Проверить DNS» в Kerio нет — Kerio САМ автоматически проверяет DNS прямо в момент нажатия «ОК»! Если окно закрылось без предупреждения об отсутствии записи DNS — значит Kerio увидел ключ и сразу включил подпись писем; затем нажмите «Проверить сервер» здесь в программе — пункт DKIM загорится зелёным ✅!).",
				},
				VerifyCmd: fmt.Sprintf("nslookup -type=txt mail._domainkey.%s 8.8.8.8", mailDomain),
				CopyItems: []CopySnippet{
					{Label: "Поле «Имя / Хост» для hoster.by / active.by / Cloudflare (Тип TXT)", Value: "mail._domainkey"},
					{Label: "Полное FQDN-имя (для ISPmanager — с точкой на конце)", Value: "mail._domainkey." + mailDomain + "."},
				},
			},
		)
	} else {
		algo, bits := parseDKIMPublicKeyBits(dkimFoundRecord)
		if algo == "rsa" && bits > 0 && bits < 1024 {
			deduct(8)
			addIssue(
				MailCheckItem{
					ID:       "dkim",
					Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
					Title:    "Цифровая криптографическая подпись писем (DKIM)",
					Status:   "warning",
					Summary:  fmt.Sprintf("Запись DKIM найдена (%s._domainkey.%s), но ключ RSA устаревшей длины %d бит (Gmail требует минимум 1024–2048 бит)!", dkimFoundSelector, mailDomain, bits),
					Details:  []string{fmt.Sprintf("Селектор: %s._domainkey.%s", dkimFoundSelector, mailDomain), dkimFoundRecord},
				},
				MailRemediationGuide{
					Severity:     "warning",
					Category:     "Kerio Connect + DNS (DKIM 2048 бит)",
					Title:        "Перегенерируйте DKIM-ключ длиной 1024/2048 бит в Kerio Connect",
					WhyItMatters: "Ключи RSA 512/768 бит считаются криптографически слабыми и отклоняются Google Gmail и Microsoft 365.",
					Steps: []string{
						fmt.Sprintf("В Kerio Connect WebAdmin → Конфигурация → Домены → %s → вкладка Дополнительно (DKIM) сгенерируйте новый ключ и обновите TXT-запись %s._domainkey в панели DNS.", mailDomain, dkimFoundSelector),
					},
					VerifyCmd: fmt.Sprintf("nslookup -type=txt %s._domainkey.%s 8.8.8.8", dkimFoundSelector, mailDomain),
				},
			)
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "dkim",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Цифровая криптографическая подпись писем (DKIM)",
				Status:   "ok",
				Summary:  fmt.Sprintf("Отлично! Активна криптографическая подпись DKIM (%s._domainkey.%s, ключ %s %d бит)", dkimFoundSelector, mailDomain, strings.ToUpper(algo), bits),
				Details:  []string{fmt.Sprintf("Селектор: %s._domainkey.%s", dkimFoundSelector, mailDomain), dkimFoundRecord},
			})
		}
	}

	// =========================================================================
	// CHECK 5: DMARC POLICY (_dmarc.<domain>)
	// =========================================================================
	recommendedDMARCSoft := fmt.Sprintf("v=DMARC1; p=none; sp=none; pct=100; rua=mailto:admin@%s; adkim=r; aspf=r", mailDomain)
	recommendedDMARCStrict := fmt.Sprintf("v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:admin@%s; adkim=r; aspf=r", mailDomain)
	if len(dmarcRecords) == 0 {
		deduct(12)
		var dDetails []string
		steps := []string{
			fmt.Sprintf("Войдите в панель управления DNS домена %s (hoster.by, active.by, Cloudflare, ISPmanager).", mailDomain),
		}
		if len(straySubdomainDMARC) > 0 {
			dDetails = append(dDetails, fmt.Sprintf("⚠️ НАЙДЕНА ПРИЧИНА: в вашей панели DNS запись DMARC сейчас ошибочно создана на поддомене «_dmarc.mail.%s» (%s) вместо «_dmarc.%s»!", mailDomain, straySubdomainDMARC[0], mailDomain))
			steps = append(steps, fmt.Sprintf("⚠️ ОБРАТИТЕ ВНИМАНИЕ: мы нашли вашу текущую запись «%s» на адресе _dmarc.mail.%s! Просто отредактируйте эту запись в панели DNS и измените поле «Имя / Хост» с «_dmarc.mail» на просто «_dmarc» (без .mail)!", straySubdomainDMARC[0], mailDomain))
		} else {
			dDetails = append(dDetails, "Отсутствует запись TXT для имени _dmarc."+mailDomain)
			steps = append(steps, "Нажмите «Добавить запись» → выберите Тип записи: TXT.")
			steps = append(steps, "В поле «Имя / Субдомен» напишите строго: _dmarc (ВНИМАНИЕ: НЕ пишите _dmarc.mail!).")
		}
		steps = append(steps,
			"Если вы только что настраиваете SPF и DKIM — вставьте на первые 3–5 дней мягкий режим мониторинга (p=none, кнопка копирования №2 ниже): ни одно ваше письмо не заблокируется, а на почту администратора придут отчёты.",
			"Когда убедитесь, что и SPF, и DKIM горят зелёным ✅ на этой вкладке — переключите значение на боевой защитный режим p=quarantine (кнопка копирования №3 ниже), чтобы чужие спамеры не могли подделывать письма от имени @"+mailDomain+"!",
		)
		addIssue(
			MailCheckItem{
				ID:       "dmarc",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Политика защиты домена DMARC (_dmarc." + mailDomain + ")",
				Status:   "error",
				Summary:  fmt.Sprintf("На основном домене _dmarc.%s отсутствует политика DMARC!", mailDomain),
				Details:  dDetails,
			},
			MailRemediationGuide{
				Severity:     "warning",
				Category:     "Аутентификация отправителя (DNS TXT — DMARC)",
				Title:        fmt.Sprintf("Добавьте (или перенесите с .mail) запись TXT _dmarc для домена %s", mailDomain),
				WhyItMatters: "Политика DMARC — третий обязательный элемент («золотой стандарт» SPF + DKIM + DMARC), без которого Gmail, Yahoo, Microsoft и Mail.ru снижают репутацию домена, а злоумышленники могут присылать вашим контрагентам поддельные счета якобы от имени вашего директора @" + mailDomain + ".",
				Steps:        steps,
				VerifyCmd:    fmt.Sprintf("nslookup -type=txt _dmarc.%s 8.8.8.8", mailDomain),
				CopyItems: []CopySnippet{
					{Label: "1. Поле «Имя / Хост» в hoster.by / Cloudflare (Тип TXT)", Value: "_dmarc"},
					{Label: "2. Безопасное значение TXT на старт (мониторинг p=none)", Value: recommendedDMARCSoft},
					{Label: "3. Боевое значение TXT после включения SPF+DKIM (защита p=quarantine)", Value: recommendedDMARCStrict},
				},
			},
		)
	} else {
		dm := dmarcRecords[0]
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "dmarc",
			Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
			Title:    "Политика защиты домена DMARC (_dmarc." + mailDomain + ")",
			Status:   "ok",
			Summary:  "Политика DMARC активна на корневом домене: " + dm,
			Details:  dmarcRecords,
		})
	}

	// =========================================================================
	// CHECK 6: SMTP PORT 25 + HELO BANNER HOSTNAME + OPEN RELAY CHECK
	// =========================================================================
	if !smtp25.Reachable {
		deduct(8)
		addIssue(
			MailCheckItem{
				ID:       "smtp25",
				Category: "Служба SMTP, межсетевой экран и безопасность Kerio Connect",
				Title:    "Доступность SMTP-сервера (порт 25), приветствие EHLO и защита от Open Relay",
				Status:   "warning",
				Summary:  fmt.Sprintf("С этого компьютера не удалось подключиться к %s:25 (%s)", probeTargetHost, smtp25.DialErr),
				Details: []string{
					"Проверенный адрес подключения: " + net.JoinHostPort(probeTargetHost, "25"),
					"Причина А (очень частая при проверке из дома/офиса): интернет-провайдер вашего рабочего ПК (Белтелеком / A1 / мобильный оператор) режет исходящий порт 25 для защиты от вирусов — при этом сам сервер для внешнего мира работает нормально! Чтобы обойти блокировку провайдера, укажите локальный VPN IP сервера (например, 10.146.100.14) в поле «IP для прямой проверки портов по VPN» наверху этой вкладки и нажмите «Проверить»!",
					"Причина Б: на вашем роутере (Kerio Control / MikroTik) не проброшен входящий порт TCP 25 на сервер Kerio Connect, либо остановлена служба SMTP — тогда внешние письма к вам вообще не доходят!",
				},
			},
			MailRemediationGuide{
				Severity:     "warning",
				Category:     "Kerio Connect SMTP + Межсетевой экран (Порт 25)",
				Title:        "Как за 1 минуту проверить порт 25 через VPN и настроить проброс портов на роутере",
				WhyItMatters: "Порт TCP 25 — единственный стандартный порт, на который Gmail, Mail.ru, Yandex и все серверы мира доставляют вам входящие письма. Кроме того, прямое подключение к порту 25 позволяет нашей программе проверить правильность имени HELO и отсутствие опасной дыры Open Relay!",
				Steps: []string{
					"ШАГ 1 (Проверка без блокировки вашего провайдера): Если вы подключены к сети предприятия по VPN — впишите внутренний IP сервера Kerio Connect (например, 10.146.100.14) в правое нижнее поле наверху этой вкладки («IP для прямой проверки портов по VPN») и снова нажмите кнопку «Проверить почтовый сервер»! Программа проверит живой порт 25, баннер HELO, Open Relay и все SSL-порты прямо внутри туннеля!",
					"ШАГ 2 (Проверка в Kerio Connect WebAdmin): Откройте https://...:4040/admin/ → «Конфигурация» → «Службы» (Services) → убедитесь, что службы «SMTP» (порт 25), «SMTPS» (порт 465), «Submission» (порт 587) и «IMAPS» (порт 993) имеют статус «Запущено» и галочку автозапуска.",
					"ШАГ 3 (Проброс портов на межсетевом экране роутера): На внешнем шлюзе (Kerio Control / MikroTik / Keenetic / Fortigate) должны быть проброшены снаружи (WAN → LAN IP сервера Kerio) TCP-порты: • 25 (SMTP приём внешней почты) • 465 и/или 587 (защищённая отправка для сотрудников с телефонов/ноутбуков) • 993 (IMAPS почта) • 443 (Kerio WebMail и ActiveSync).",
					"⚠️ КРИТИЧЕСКОЕ ПРАВИЛО НА РОУТЕРЕ (MikroTik / Kerio Control): При пробросе (DST-NAT) входящего порта TCP 25 НИ В КОЕМ СЛУЧАЕ НЕ ВКЛЮЧАЙТЕ Source NAT / Masquerade на LAN-интерфейсе для этого трафика! Иначе Kerio Connect будет видеть все спам-письма из интернета как пришедшие с локального IP вашего собственного роутера!",
					"ШАГ 4 (Живой тест приёма из интернета): Отправьте проверочное письмо с личного ящика @gmail.com или @yandex.by на любой ящик @" + mailDomain + " и убедитесь в Kerio Connect (Логи → Mail / Operations), что оно мгновенно пришло.",
				},
				VerifyCmd: fmt.Sprintf("Test-NetConnection -ComputerName %s -Port 25", probeTargetHost),
				QuickAction: "focus_vpn_ip",
			},
		)
	} else {
		// Check Open Relay FIRST — emergency security priority!
		if smtp25.OpenRelay {
			deduct(35)
			addIssue(
				MailCheckItem{
					ID:       "relay",
					Category: "Служба SMTP и безопасность Kerio Connect",
					Title:    "🚨 КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Открытый почтовый релей (Open Relay)!",
					Status:   "error",
					Summary:  "СЕРВЕР ПРИНЯЛ ЧУЖОЕ ПИСЬМО НА ВНЕШНИЙ АДРЕС БЕЗ ПАРОЛЯ! Ваш IP попадёт во все спам-базы и будет заблокирован провайдером!",
					Details:  []string{"Лог проверки: " + smtp25.RelayTestLog + " (соединение сброшено командой RSET без отправки письма)"},
				},
				MailRemediationGuide{
					Severity:     "critical",
					Category:     "ЭКСТРЕННАЯ ЗАЩИТА KERIO CONNECT + NAT",
					Title:        "НЕМЕДЛЕННО закройте Открытый релей (Open Relay) в Kerio Connect и на роутере!",
					WhyItMatters: "Боты сканируют все IP интернета каждые несколько минут. Открытый релей позволяет спамерам рассылать через ваш сервер десятки тысяч фишинговых писем в час — IP мгновенно попадает в Spamhaus, а провайдер (Белтелеком / A1) отключает порт 25 по жалобе Abuse!",
					Steps: []string{
						"Откройте Kerio Connect WebAdmin (:4040) → «Конфигурация» → «Сервер SMTP» → вкладка «Контроль реле (Relay Control)».",
						"Переключите в режим «Открыть реле только для следующих IP-групп» и УБЕРИТЕ оттуда локальную подсеть (оставьте только 127.0.0.1, если вы проверяли по VPN или если роутер делает NAT!).",
						"Проверьте главную ловушку MikroTik / Kerio Control: если на вашем роутере настроено общее правило Masquerade без указания out-interface=WAN (hairpin/LAN masquerade), то пакеты из интернета на порт 25 приходят в Kerio с исходным IP самого роутера (например, 10.146.100.1), который входит в «Доверенную локальную сеть» Kerio! В MikroTik в правиле masquerade обязательно укажите Out. Interface = WAN (интернет-провайдер)!",
						"Обязательно оставьте включённой галочку: «Пользователи, прошедшие аутентификацию по протоколу SMTP, могут пересылать сообщения на любой адрес» (тогда ваши сотрудники с паролем смогут отправлять письма откуда угодно, а спамеры — нет!).",
						"Нажмите «Применить» и тут же повторно нажмите «Проверить почтовый сервер» в этой программе — статус должен смениться на зелёный ✅!",
					},
				},
			)
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "relay",
				Category: "Служба SMTP и безопасность Kerio Connect",
				Title:    "Защита от открытого релея (Open Relay Protection)",
				Status:   "ok",
				Summary:  "Отлично! Сервер надёжно запрещает неавторизованную пересылку чужой почты (550 Relay denied).",
				Details:  []string{smtp25.RelayTestLog},
			})
		}

		// Check SMTP Banner Hostname == recommendedHost
		bannerMatches := strings.EqualFold(smtp25.BannerHost, recommendedHost)
		isLocalBanner := strings.HasSuffix(strings.ToLower(smtp25.BannerHost), ".local") ||
			strings.HasSuffix(strings.ToLower(smtp25.BannerHost), ".lan") ||
			!strings.Contains(smtp25.BannerHost, ".")
		if !bannerMatches || isLocalBanner {
			deduct(10)
			addIssue(
				MailCheckItem{
					ID:       "banner",
					Category: "Служба SMTP и безопасность Kerio Connect",
					Title:    "Приветствие SMTP-сервера (HELO / EHLO Banner Hostname)",
					Status:   "warning",
					Summary:  fmt.Sprintf("В приветствии SMTP ваш Kerio представляется именем «%s» вместо «%s»!", smtp25.BannerHost, recommendedHost),
					Details: []string{
						"Фактическая строка приветствия сервера (220): " + smtp25.BannerLine,
						"Должно быть полное интернет-имя (FQDN): " + recommendedHost,
					},
				},
				MailRemediationGuide{
					Severity:     "warning",
					Category:     "Настройка Kerio Connect WebAdmin (SMTP Имя узла)",
					Title:        fmt.Sprintf("Укажите правильное «Имя узла в сети Интернет» (%s) в Kerio Connect за 30 секунд", recommendedHost),
					WhyItMatters: fmt.Sprintf("По умолчанию Kerio Connect берёт локальное имя Windows-машины (например, WIN-KERIO.office.local или localhost). Когда ваш сервер подключается к Gmail или Yandex и говорит «Привет, я %s», спам-фильтр видит несовпадение с A/MX/PTR (%s) и начисляет штрафные баллы СПАМа (HELO_LOCALHOST / RDNS_HELO_MISMATCH)!", smtp25.BannerHost, recommendedHost),
					Steps: []string{
						"Откройте веб-админку Kerio Connect (:4040/admin/).",
						"В левом меню откройте «Конфигурация» (Configuration) → «Сервер SMTP» (SMTP Server) → вкладка «Общие» (General) — а также проверьте «Конфигурация» → «Домены» → ваш домен.",
						fmt.Sprintf("В поле «Имя узла в сети Интернет (Internet hostname)» впишите строго: %s", recommendedHost),
						"Нажмите кнопку «Применить (Apply)» внизу справа — почта НЕ прерывается, настройка применяется мгновенно!",
					},
					CopyItems: []CopySnippet{
						{Label: "Поле «Имя узла в сети Интернет (Internet hostname)» в Kerio Connect", Value: recommendedHost},
					},
				},
			)
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "banner",
				Category: "Служба SMTP и безопасность Kerio Connect",
				Title:    "Приветствие SMTP-сервера (HELO / EHLO Banner Hostname)",
				Status:   "ok",
				Summary:  fmt.Sprintf("Идеально! Kerio представляется правильным именем %s (отклик %d мс)", smtp25.BannerHost, smtp25.LatencyMs),
				Details:  []string{smtp25.BannerLine},
			})
		}
	}

	// =========================================================================
	// CHECK 7: SSL / TLS CERTIFICATE ACROSS ALL MAIL PORTS (25/465/587/993/443)
	// =========================================================================
	var sslBadPorts []string
	var sslExpiringSoon bool
	var sslDaysMin = 9999
	var anyOpenMailPort bool
	var sslDetails []string

	for _, p := range report.Ports {
		if !p.Open {
			sslDetails = append(sslDetails, fmt.Sprintf("Порт %d (%s): закрыт / нет ответа с текущей сети", p.Port, p.Protocol))
			continue
		}
		anyOpenMailPort = true
		if !p.TLSOK {
			sslBadPorts = append(sslBadPorts, fmt.Sprintf("%d (TLS не включён)", p.Port))
			sslDetails = append(sslDetails, fmt.Sprintf("Порт %d (%s): открыт (%d мс), но шифрование SSL/STARTTLS не сработало!", p.Port, p.Protocol, p.LatencyMs))
			continue
		}
		if p.CertDays < sslDaysMin {
			sslDaysMin = p.CertDays
		}
		if p.CertDays < 14 {
			sslExpiringSoon = true
		}
		if !p.TLSTrusted {
			sslBadPorts = append(sslBadPorts, fmt.Sprintf("%d", p.Port))
			sslDetails = append(sslDetails, fmt.Sprintf("❌ Порт %d (%s): НЕДОВЕРЕННЫЙ СЕРТИФИКАТ (%s, до %s) — %s", p.Port, p.Protocol, p.CertSubject, p.CertExpiry, p.Error))
		} else {
			sslDetails = append(sslDetails, fmt.Sprintf("✅ Порт %d (%s): доверенный SSL (%s, выдан %s, %s, действует ещё %d дн. до %s)", p.Port, p.Protocol, p.CertSubject, p.CertIssuer, p.TLSVersion, p.CertDays, p.CertExpiry))
		}
	}

	if len(sslBadPorts) > 0 {
		deduct(18)
		addIssue(
			MailCheckItem{
				ID:       "ssl",
				Category: "Шифрование почты (SSL / STARTTLS)",
				Title:    "Проверка SSL-сертификата и полной цепочки CA на почтовых портах",
				Status:   "error",
				Summary:  fmt.Sprintf("На почтовых портах [%s] активен недоверенный / самоподписанный / неполный SSL-сертификат!", strings.Join(sslBadPorts, ", ")),
				Details:  sslDetails,
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Kerio Connect SSL / Let's Encrypt",
				Title:        fmt.Sprintf("Выпустите и активируйте доверенный SSL-сертификат для %s прямо в этой программе!", recommendedHost),
				WhyItMatters: "Если в Kerio Connect активен старый самоподписанный сертификат или сертификат без промежуточной цепочки (Fullchain), у сотрудников в Outlook и на смартфонах iPhone/Android выскакивают окна «Не удаётся проверить подлинность сервера», а внешние почтовые системы снижают рейтинг безопасности TLS.",
				Steps: []string{
					fmt.Sprintf("Если вы уже выпустили сертификат %s в этой программе — перейдите на вкладку «📬 Установка в Kerio Connect», введите адрес и пароль админки :4040 и нажмите «Установить сертификат в Kerio Connect» (или импортируйте server.key + server.crt вручную в Конфигурация → Сертификаты SSL → Сделать активным).", recommendedHost),
					fmt.Sprintf("Если сертификат ещё не выпущен — нажмите синюю кнопку ниже, чтобы сразу перейти на вкладку выпуска сертификата Let's Encrypt для %s!", recommendedHost),
				},
				QuickAction: "goto_issue_ssl",
			},
		)
	} else if sslExpiringSoon && anyOpenMailPort {
		deduct(8)
		addIssue(
			MailCheckItem{
				ID:       "ssl",
				Category: "Шифрование почты (SSL / STARTTLS)",
				Title:    "Проверка SSL-сертификата и полной цепочки CA на почтовых портах",
				Status:   "warning",
				Summary:  fmt.Sprintf("SSL-сертификат доверенный, но истекает уже через %d дн.! Рекомендуется продлить сейчас.", sslDaysMin),
				Details:  sslDetails,
			},
			MailRemediationGuide{
				Severity:     "warning",
				Category:     "Kerio Connect SSL / Let's Encrypt",
				Title:        fmt.Sprintf("Обновите истекающий SSL-сертификат на %s (осталось %d дн.)", recommendedHost, sslDaysMin),
				WhyItMatters: "В день окончания сертификата Outlook и мобильные клиенты всех сотрудников перестанут отправлять и получать почту до замены сертификата.",
				Steps: []string{
					fmt.Sprintf("Нажмите кнопку ниже, перевыпустите свежий 90-дневный сертификат Let's Encrypt для %s и активируйте его на вкладке «Установка в Kerio Connect».", recommendedHost),
				},
				QuickAction: "goto_issue_ssl",
			},
		)
	} else if anyOpenMailPort {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "ssl",
			Category: "Шифрование почты (SSL / STARTTLS)",
			Title:    "Проверка SSL-сертификата и полной цепочки CA на почтовых портах",
			Status:   "ok",
			Summary:  fmt.Sprintf("Идеально! Все открытые почтовые порты защищены доверенным SSL-сертификатом Let's Encrypt / CA (осталось %d дн.)!", sslDaysMin),
			Details:  sslDetails,
		})
	} else {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "ssl",
			Category: "Шифрование почты (SSL / STARTTLS)",
			Title:    "Проверка SSL-сертификата и полной цепочки CA на почтовых портах",
			Status:   "info",
			Summary:  "Ни один из почтовых портов (25/465/587/993/995/443) не ответил по TCP с вашего текущего сетевого подключения.",
			Details:  sslDetails,
			Solution: &MailRemediationGuide{
				CheckID:      "ssl",
				Severity:     "info",
				Category:     "Проверка портов через VPN / WAN",
				Title:        "Укажите локальный IP сервера Kerio для проверки всех SSL-портов по VPN",
				WhyItMatters: "Если сервер пока доступен только внутри корпоративного VPN (например, 10.146.100.14), укажите этот IP в поле «IP для прямой проверки портов по VPN» наверху этой вкладки.",
				Steps: []string{
					"Впишите локальный IP вашего Kerio Connect (например, 10.146.100.14) в правое поле наверху вкладки и нажмите «Проверить почтовый сервер» — программа мгновенно проверит сертификаты на всех 6 портах (25, 465, 587, 993, 995, 443)!",
				},
				QuickAction: "focus_vpn_ip",
			},
		})
	}

	// =========================================================================
	// CHECK 8: DNSBL SPAM BLACKLISTS (11 GLOBAL RBLs)
	// =========================================================================
	var listedIn []RBLCheckEntry
	for _, b := range rbls {
		if b.Listed {
			listedIn = append(listedIn, b)
		}
	}
	if len(listedIn) > 0 {
		deduct(25)
		var bDetails []string
		steps := []string{
			"ШАГ 1 (Сначала устраните причину попадания в бан — иначе после удаления IP забанят повторно!): Откройте Kerio Connect WebAdmin → «Статус» (Status) → «Очередь сообщений» (Message Queue). Если в очереди висят сотни/тысячи чужих писем — значит у одного из сотрудников подобрали простой пароль от почты (посмотрите столбец Отправитель, немедленно смените пароль этому пользователю в Разделе «Пользователи» и очистите спам из очереди!).",
			"ШАГ 2: Убедитесь, что у вашего IP " + serverIP + " прописана обратная запись PTR (см. пункт про PTR выше) и закрыт Open Relay (некоторые списки, такие как SORBS / SpamRATS, вносят IP просто за отсутствие PTR-записи!).",
			"ШАГ 3: Откройте официальные страницы удаления (Delist) по каждому сработавшему списку ниже и отправьте бесплатный запрос на разблокировку IP " + serverIP + " (удаление занимает от 15 минут до 24 часов):",
		}
		for _, b := range listedIn {
			bDetails = append(bDetails, fmt.Sprintf("🔴 В чёрном списке %s (%s) — код %s, удаление: %s", b.Provider, b.Zone, b.ReturnCode, b.DelistURL))
			steps = append(steps, fmt.Sprintf("• %s → откройте %s , введите IP %s и нажмите Delist / Removal Request.", b.Provider, b.DelistURL, serverIP))
		}
		addIssue(
			MailCheckItem{
				ID:       "rbl",
				Category: "Репутация IP в спам-базах (DNSBL / RBL)",
				Title:    fmt.Sprintf("Проверка внешнего IP %s по %d мировым чёрным спискам спама", serverIP, len(rbls)),
				Status:   "error",
				Summary:  fmt.Sprintf("ВНИМАНИЕ: внешний IP %s числится в %d чёрных списках спама! Многие серверы отклоняют ваши письма ещё до чтения!", serverIP, len(listedIn)),
				Details:  bDetails,
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Репутация IP (Удаление из чёрных списков DNSBL)",
				Title:        fmt.Sprintf("Пошаговая очистка репутации и удаление IP %s из %d спам-баз", serverIP, len(listedIn)),
				WhyItMatters: "Почтовые шлюзы Microsoft, Gmail, банков и гос. организаций проверяют IP отправителя по базам Spamhaus, Barracuda и SpamCop прямо в момент TCP-соединения и мгновенно сбрасывают сессию с ошибкой 554 Service unavailable; Client host blocked using Spamhaus.",
				Steps:        steps,
			},
		)
	} else if len(rbls) > 0 {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "rbl",
			Category: "Репутация IP в спам-базах (DNSBL / RBL)",
			Title:    fmt.Sprintf("Проверка внешнего IP %s по %d мировым чёрным спискам спама", serverIP, len(rbls)),
			Status:   "ok",
			Summary:  fmt.Sprintf("Отлично! Внешний IP %s чист — не найден ни в одной из %d мировых спам-баз (Spamhaus, Barracuda, SpamCop, SORBS и др.).", serverIP, len(rbls)),
		})
	} else {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "rbl",
			Category: "Репутация IP в спам-базах (DNSBL / RBL)",
			Title:    "Проверка внешнего IP по 11 мировым чёрным спискам спама (DNSBL)",
			Status:   "info",
			Summary:  "Ожидает настройки A-записи домена с внешним публичным IPv4-адресом (локальные IP 10.x / 192.168.x в спам-базах не проверяются).",
		})
	}

	// =========================================================================
	// CHECK 9: OUTLOOK / MOBILE AUTODISCOVER & TLS-RPT
	// =========================================================================
	if len(autodiscoverIPs) == 0 && len(autodiscoverSRVs) == 0 {
		addIssue(
			MailCheckItem{
				ID:       "autodiscover",
				Category: "Удобство клиентов и расширенные стандарты",
				Title:    "Автонастройка Outlook / телефонов (Autodiscover SRV) и отчёты TLS-RPT",
				Status:   "info",
				Summary:  fmt.Sprintf("Рекомендуемое улучшение: добавьте SRV-запись _autodiscover._tcp.%s для автоматической настройки Outlook и мобильных клиентов.", mailDomain),
				Details: []string{
					fmt.Sprintf("MTA-STS: %d записей | TLS-RPT: %d записей", len(mtaStsRecords), len(tlsRptRecords)),
				},
			},
			MailRemediationGuide{
				Severity:     "info",
				Category:     "Автонастройка клиентов Kerio Connect (DNS SRV)",
				Title:        fmt.Sprintf("Настройте автоподключение Outlook / iOS / Android через SRV-запись для @%s", mailDomain),
				WhyItMatters: fmt.Sprintf("С одной SRV-записью любому сотруднику достаточно ввести в Outlook только свой email и пароль — программа сама найдёт %s:443 и настроит все порты! Причём в отличие от A-записи autodiscover.%s, для SRV-записи НЕ требуется выпускать отдельный SSL-сертификат — используется ваш основной сертификат %s!", recommendedHost, mailDomain, recommendedHost),
				Steps: []string{
					fmt.Sprintf("В панели управления DNS домена %s нажмите «Добавить запись» → выберите Тип: SRV.", mailDomain),
					fmt.Sprintf("Заполните поля: • Служба / Имя: _autodiscover._tcp • Приоритет: 0 • Вес: 0 • Порт: 443 • Цель (Target / Сервер): %s", recommendedHost),
					"(Дополнительно по желанию) Создайте запись TXT с именем _smtp._tls и значением из кнопки ниже, чтобы почтовые системы присылали вам уведомление, если когда-нибудь возникнет проблема с SSL при доставке писем.",
				},
				CopyItems: []CopySnippet{
					{Label: "SRV — Поле «Имя / Служба»", Value: "_autodiscover._tcp"},
					{Label: "SRV — Поле «Цель / Target» (Приоритет 0, Вес 0, Порт 443)", Value: recommendedHost},
					{Label: "TXT (_smtp._tls) — Отчёты о шифровании TLS", Value: fmt.Sprintf("v=TLSRPTv1; rua=mailto:admin@%s", mailDomain)},
				},
			},
		)
	} else {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "autodiscover",
			Category: "Удобство клиентов и расширенные стандарты",
			Title:    "Автонастройка Outlook / телефонов (Autodiscover SRV) и отчёты TLS-RPT",
			Status:   "ok",
			Summary:  "Автонастройка почтовых клиентов (Autodiscover) настроена в DNS!",
			Details:  append(autodiscoverIPs, autodiscoverSRVs...),
		})
	}

	// =========================================================================
	// EXTENDED DEEP SECURITY & DELIVERABILITY CHECKS (v4.0 PARALLEL PIPELINE)
	// =========================================================================
	var (
		roleAudit     smtpRoleAuditResult
		legacyTLS465  bool
		legacyTLS465V string
	)
	var extraWG sync.WaitGroup
	extraWG.Add(2)
	go func() {
		defer extraWG.Done()
		if smtp25.Reachable {
			roleAudit = inspectSMTPRolesAndCapabilities(net.JoinHostPort(probeTargetHost, "25"), mailDomain)
		}
	}()
	go func() {
		defer extraWG.Done()
		if port465.Open {
			legacyTLS465, legacyTLS465V = checkLegacyTLSAccepted(probeTargetHost, mailHost, 465)
		} else if port443.Open {
			legacyTLS465, legacyTLS465V = checkLegacyTLSAccepted(probeTargetHost, mailHost, 443)
		}
	}()
	extraWG.Wait()

	report.DomainBlacklists = domRBLs

	// CHECK 10: SPF 10-DNS-LOOKUP LIMIT & DEPRECATED MECHANISMS (RFC 7208)
	if len(spfRecords) == 1 {
		spfLookups, usedPTR, incDetails := countSPFDNSLookups(mailDomain, spfRecords[0], 0, map[string]bool{mailDomain: true})
		if spfLookups > 10 || usedPTR {
			deduct(12)
			addIssue(
				MailCheckItem{
					ID:       "spf_depth",
					Category: "Глубокий аудит стандартов RFC",
					Title:    fmt.Sprintf("Лимит вложенных DNS-запросов в SPF (%d из 10 макс. по RFC 7208)", spfLookups),
					Status:   "error",
					Summary:  fmt.Sprintf("Превышен лимит 10 DNS-запросов в SPF (%d запросов) или использован запрещённый механизм 'ptr' — Gmail и Outlook возвращают SPF PermError!", spfLookups),
					Details:  incDetails,
				},
				MailRemediationGuide{
					Severity:     "critical",
					Category:     "Оптимизация SPF (RFC 7208 Limit <= 10)",
					Title:        "Сократите количество include:/a/mx в SPF-записи до <= 10 DNS-запросов",
					WhyItMatters: "По стандарту RFC 7208 принимающий почтовый сервер делает не более 10 рекурсивных DNS-запросов при проверке SPF. На 11-м запросе проверка обрывается со статусом PermError (как будто SPF сломан)!",
					Steps: []string{
						"Замените лишние доменные проверки на прямые IPv4-адреса вида ip4:" + ipDisplay + " (механизм ip4: стоит 0 DNS-запросов!).",
						"Удалите из SPF неиспользуемые старые сервисы рассылок (include:...) и никогда не используйте устаревшее слово ptr.",
					},
					CopyItems: []CopySnippet{
						{Label: "Компактная SPF-запись (всего 2 из 10 DNS-запросов!)", Value: recommendedSPF},
					},
				},
			)
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "spf_depth",
				Category: "Глубокий аудит стандартов RFC",
				Title:    fmt.Sprintf("Рекурсивная глубина SPF (%d из 10 допустимых DNS-запросов)", spfLookups),
				Status:   "ok",
				Summary:  fmt.Sprintf("Отлично! SPF укладывается в жёсткий лимит RFC 7208 (%d из 10 запросов).", spfLookups),
				Details:  incDetails,
			})
		}
	}

	// CHECK 11: DOMAIN BLACKLISTS (DBL / SURBL / URIBL / SEM)
	var listedDom []RBLCheckEntry
	for _, d := range domRBLs {
		if d.Listed {
			listedDom = append(listedDom, d)
		}
	}
	if len(listedDom) > 0 {
		deduct(20)
		var dDet, dSteps []string
		dSteps = append(dSteps, "Проверьте сайт и почтовые подписи на домене "+mailDomain+" на отсутствие взломанных страниц/редиректов.")
		for _, ld := range listedDom {
			dDet = append(dDet, fmt.Sprintf("🔴 Домен %s в чёрном списке %s (%s) — код %s", mailDomain, ld.Provider, ld.Zone, ld.ReturnCode))
			dSteps = append(dSteps, fmt.Sprintf("Откройте портал разблокировки домена %s: %s (готовый текст обращения сформирован в Центре разблокировки ниже!).", ld.Provider, ld.DelistURL))
		}
		addIssue(
			MailCheckItem{
				ID:       "domain_rbl",
				Category: "Репутация домена в спам-базах (DBL / URIBL / SURBL)",
				Title:    fmt.Sprintf("Проверка самого домена @%s по %d доменным чёрным спискам", mailDomain, len(domRBLs)),
				Status:   "error",
				Summary:  fmt.Sprintf("ДОМЕН @%s НАЙДЕН В %d ДОМЕННЫХ СПАМ-БАЗАХ! Любое письмо со ссылкой или адресом @%s режется фильтрами!", mailDomain, len(listedDom), mailDomain),
				Details:  dDet,
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Разблокировка домена (Spamhaus DBL / SURBL / URIBL)",
				Title:        fmt.Sprintf("Срочно подайте заявку на исключение домена %s через Центр разблокировки ниже", mailDomain),
				WhyItMatters: "Даже при кристально чистом IP попадание самого имени домена в Spamhaus DBL / SURBL / URIBL блокирует все письма компании.",
				Steps:        dSteps,
			},
		)
	} else {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "domain_rbl",
			Category: "Репутация домена в спам-базах (DBL / URIBL / SURBL)",
			Title:    fmt.Sprintf("Проверка домена @%s по доменным чёрным спискам (Spamhaus DBL, SURBL, URIBL)", mailDomain),
			Status:   "ok",
			Summary:  fmt.Sprintf("Чисто! Домен @%s не числится в доменных спам-базах (Spamhaus DBL, SURBL, URIBL, SEM).", mailDomain),
		})
	}

	// CHECK 12: EXPOSED DANGEROUS MANAGEMENT PORTS ON PUBLIC INTERNET (3389 RDP / 4040 KERIO ADMIN / 445 SMB)
	if len(exposedAdmin) > 0 {
		deduct(18)
		addIssue(
			MailCheckItem{
				ID:       "exposed_admin",
				Category: "Кибербезопасность почтового сервера и защита от взлома",
				Title:    "🚨 ОПАСНЫЕ ПОРТЫ АДМИНИСТРИРОВАНИЯ ОТКРЫТЫ В ИНТЕРНЕТ (RDP 3389 / Kerio Admin 4040 / SMB 445)!",
				Status:   "error",
				Summary:  fmt.Sprintf("На внешнем IP %s открыты наружу критические порты управления (%d шт.) — главная причина взлома почты и попадания в Spamhaus!", serverIP, len(exposedAdmin)),
				Details:  exposedAdmin,
			},
			MailRemediationGuide{
				Severity:     "critical",
				Category:     "Межсетевой экран роутера (Защита от шифровальщиков и брутфорса)",
				Title:        fmt.Sprintf("НЕМЕДЛЕННО закройте порты %s на внешнем интерфейсе WAN роутера!", strings.Join(exposedAdmin, ", ")),
				WhyItMatters: "Открытый наружу порт 3389 (Windows RDP) или 4040 (Kerio WebAdmin) сканируется ботами каждую минуту. При подборе пароля или уязвимости сервер взламывают для массовой спам-рассылки или шифрования баз почты!",
				Steps: []string{
					"Откройте настройки межсетевого экрана вашего граничного роутера (MikroTik / Kerio Control / Fortigate).",
					"Отключите (удалите) проброс (DST-NAT) наружу для портов TCP 3389 (RDP), TCP 4040 (Kerio WebAdmin) и TCP 445 (SMB)!",
					"Оставьте доступ к веб-админке :4040 и удалённому рабочему столу :3389 ТОЛЬКО из локальной сети и через корпоративный VPN (например, 10.146.100.x)!",
				},
			},
		)
	} else if isGloballyRoutableIPv4(serverIP) {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "exposed_admin",
			Category: "Кибербезопасность почтового сервера и защита от взлома",
			Title:    "Защита опасных портов управления на внешнем IP (RDP 3389, Kerio Admin 4040, SMB 445)",
			Status:   "ok",
			Summary:  fmt.Sprintf("Отлично! Порты 3389 (RDP), 4040 (Kerio WebAdmin) и 445 (SMB) надёжно закрыты снаружи на IP %s.", serverIP),
		})
	}

	// CHECK 13: RFC 2142 MANDATORY ROLE MAILBOXES (postmaster@ & abuse@) + SMTP SIZE CAPABILITY
	postmasterReady := true
	if roleAudit.Checked {
		sizeInfo := "без явного ограничения"
		if roleAudit.MaxSizeBytes > 0 {
			sizeInfo = fmt.Sprintf("%.1f МБ (%d байт)", float64(roleAudit.MaxSizeBytes)/(1024*1024), roleAudit.MaxSizeBytes)
		}
		if !roleAudit.PostmasterOK || !roleAudit.AbuseOK {
			postmasterReady = false
			deduct(8)
			addIssue(
				MailCheckItem{
					ID:       "postmaster",
					Category: "Служба SMTP и требования выхода из чёрных списков (RFC 2142)",
					Title:    fmt.Sprintf("Обязательные служебные адреса postmaster@%s и abuse@%s + лимит вложений", mailDomain, mailDomain),
					Status:   "warning",
					Summary:  fmt.Sprintf("Сервер отклоняет письма на служебные адреса (postmaster: %v, abuse: %v)! Службы разблокировки RBL не смогут прислать письмо подтверждения!", roleAudit.PostmasterOK, roleAudit.AbuseOK),
					Details: []string{
						"Ответ на RCPT TO:<postmaster@" + mailDomain + ">: " + roleAudit.PostmasterResp,
						"Ответ на RCPT TO:<abuse@" + mailDomain + ">: " + roleAudit.AbuseResp,
						fmt.Sprintf("Лимит размера письма (SIZE): %s | 8BITMIME: %v | PIPELINING: %v | SMTPUTF8: %v", sizeInfo, roleAudit.Supports8BitMIME, roleAudit.SupportsPipelining, roleAudit.SupportsSMTPUTF8),
					},
				},
				MailRemediationGuide{
					Severity:     "warning",
					Category:     "Kerio Connect — Псевдонимы (Aliases) за 30 секунд",
					Title:        fmt.Sprintf("Создайте бесплатные псевдонимы postmaster@%s и abuse@%s (не расходуют лицензии Kerio!)", mailDomain, mailDomain),
					WhyItMatters: "Псевдонимы (Aliases) в Kerio Connect НЕ тратят платные пользовательские лицензии! При этом по стандарту RFC 2142 любой почтовый сервер обязан принимать почту на postmaster@ и abuse@ — именно туда Microsoft SNDS, Spamhaus, Mail.ru Postmaster и Google шлют коды подтверждения разблокировки и отчёты о жалобах!",
					Steps: []string{
						"Откройте Kerio Connect WebAdmin (:4040) → раздел «Учётные записи» (Accounts) → «Псевдонимы» (Aliases).",
						"Нажмите «Добавить» → Псевдоним: postmaster → Доставлять на: выберите ваш рабочий ящик администратора (например, admin@" + mailDomain + ") → ОК.",
						"Нажмите «Добавить» ещё раз → Псевдоним: abuse → Доставлять на: тот же ящик администратора → ОК!",
					},
				},
			)
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "postmaster",
				Category: "Служба SMTP и требования выхода из чёрных списков (RFC 2142)",
				Title:    fmt.Sprintf("Служебные адреса postmaster@ / abuse@ и расширения SMTP (лимит: %s)", sizeInfo),
				Status:   "ok",
				Summary:  fmt.Sprintf("Отлично! Адреса postmaster@%s и abuse@%s активны, макс. размер письма: %s.", mailDomain, mailDomain, sizeInfo),
				Details: []string{
					fmt.Sprintf("8BITMIME: %v | PIPELINING: %v | SMTPUTF8: %v", roleAudit.Supports8BitMIME, roleAudit.SupportsPipelining, roleAudit.SupportsSMTPUTF8),
				},
			})
		}
	}

	// CHECK 14: DEPRECATED TLS 1.0 / TLS 1.1 CHECK
	if legacyTLS465 {
		deduct(5)
		addIssue(
			MailCheckItem{
				ID:       "tls_legacy",
				Category: "Шифрование почты (SSL / STARTTLS)",
				Title:    "Проверка устаревших уязвимых протоколов TLS 1.0 / TLS 1.1",
				Status:   "warning",
				Summary:  fmt.Sprintf("Сервер всё ещё разрешает подключение по устаревшему протоколу %s (рекомендуется оставить только TLS 1.2 и TLS 1.3).", legacyTLS465V),
			},
			MailRemediationGuide{
				Severity:     "info",
				Category:     "Безопасность шифрования Kerio Connect",
				Title:        "Отключите устаревшие TLS 1.0 и TLS 1.1 (оставьте TLS 1.2 + TLS 1.3)",
				WhyItMatters: "Протоколы TLS 1.0/1.1 официально признаны уязвимыми (BEAST/POODLE). Если в компании больше нет компьютеров с Windows XP / Outlook 2007, рекомендуется отключить TLS 1.0/1.1 в настройках безопасности Kerio Connect (mailserver.cfg → DisableOlderTLS).",
				Steps: []string{
					"Убедитесь, что у сотрудников нет древних клиентов Windows XP / Android 4.",
					"В современных версиях Kerio Connect 9.4+ в разделе Конфигурация → Безопасность / mailserver.cfg включите использование только современных шифров TLS 1.2 / TLS 1.3.",
				},
			},
		)
	} else if anyOpenMailPort {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "tls_legacy",
			Category: "Шифрование почты (SSL / STARTTLS)",
			Title:    "Защита от устаревших протоколов шифрования TLS 1.0 / TLS 1.1",
			Status:   "ok",
			Summary:  "Отлично! Уязвимые старые протоколы TLS 1.0 / TLS 1.1 отключены (используются только современные TLS 1.2 / 1.3).",
		})
	}

	// CHECK 15: DNS CAA + MTA-STS POLICY + BIMI BRAND LOGO
	if caaBlocksLE {
		deduct(10)
		addIssue(
			MailCheckItem{
				ID:       "caa_bimi",
				Category: "Удобство клиентов и расширенные стандарты",
				Title:    "Записи защиты SSL (DNS CAA), строгий TLS (MTA-STS) и логотип компании в почте (BIMI)",
				Status:   "warning",
				Summary:  "ВНИМАНИЕ: в DNS домена " + mailDomain + " прописана чужая запись CAA, которая ЗАПРЕЩАЕТ выпуск бесплатных сертификатов Let's Encrypt!",
				Details:  caaRecs,
			},
			MailRemediationGuide{
				Severity:     "warning",
				Category:     "DNS CAA (Разрешение для Let's Encrypt)",
				Title:        "Добавьте разрешение issue \"letsencrypt.org\" в DNS CAA-запись домена",
				WhyItMatters: "Если в DNS есть запись CAA только для другого центра сертификации, автоматическое продление сертификата Let's Encrypt на Kerio через 90 дней завершится ошибкой CAA forbidden!",
				Steps: []string{
					"В панели DNS домена " + mailDomain + " добавьте запись типа CAA: Имя = @, Флаг = 0, Тег = issue, Значение = letsencrypt.org",
				},
				CopyItems: []CopySnippet{
					{Label: "Запись CAA (Имя @)", Value: `0 issue "letsencrypt.org"`},
				},
			},
		)
	} else {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "caa_bimi",
			Category: "Удобство клиентов и расширенные стандарты",
			Title:    "Расширенные стандарты доверия: DNS CAA, строгий MTA-STS и логотип BIMI",
			Status:   "ok",
			Summary:  fmt.Sprintf("CAA не блокирует Let's Encrypt (%d зап.) | MTA-STS файл: %v | BIMI логотип: %d зап.", len(caaRecs), mtaStsPolicy != "", len(bimiRecs)),
		})
	}

	// Build complete Delist Center + Ready-to-Send Letters for all active & private blacklists!
	ptrIsOK := false
	spfIsOK := false
	dkimIsOK := false
	relayIsSafe := !smtp25.OpenRelay
	for _, c := range report.Checks {
		if c.ID == "ptr" && c.Status == "ok" {
			ptrIsOK = true
		}
		if c.ID == "spf" && c.Status == "ok" {
			spfIsOK = true
		}
		if c.ID == "dkim" && c.Status == "ok" {
			dkimIsOK = true
		}
	}
	report.DelistCenter = buildDelistCenter(
		mailDomain, recommendedHost, serverIP,
		ptrIsOK, spfIsOK, dkimIsOK, relayIsSafe, postmasterReady,
		rbls, domRBLs, "",
	)

	// Count totals & calculate Grade + Verdict
	for _, c := range report.Checks {
		switch c.Status {
		case "error":
			report.CriticalCount++
		case "warning":
			report.WarningCount++
		case "ok":
			report.PassedCount++
		}
	}

	switch {
	case report.Score >= 95:
		report.Grade = "A+"
		report.Verdict = "Эталонная настройка почтового сервера! Высочайшая доставляемость во Входящие (Gmail, Mail.ru, Yandex, Outlook)."
	case report.Score >= 82:
		report.Grade = "A"
		report.Verdict = "Хорошая настройка сервера! Почта ходит стабильно — ниже даны тонкие улучшения для максимальной оценки 100/100."
	case report.Score >= 65:
		report.Grade = "B"
		report.Verdict = "Почта работает, но часть писем может попадать в «Спам». Прямо под каждым замечанием ниже дана подробная пошаговая инструкция по исправлению!"
	case report.Score >= 45:
		report.Grade = "C"
		report.Verdict = "Высокий риск попадания в «Спам» и отказов доставки! Выполните подробные пошаговые инструкции прямо под красными/жёлтыми карточками ниже."
	default:
		report.Grade = "F"
		report.Verdict = "Обнаружены критические ошибки настройки DNS / почтового сервера! Прямо внутри каждой красной карточки ниже расписана подробная пошаговая инструкция по решению."
	}

	log("success", fmt.Sprintf("Аудит @%s (%s) завершён: рейтинг %d/100 (оценка %s) — успешно: %d, предупреждений: %d, критических: %d",
		mailDomain, recommendedHost, report.Score, report.Grade, report.PassedCount, report.WarningCount, report.CriticalCount))

	return report, nil
}

func nonEmptyOr(val, fallback string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return fallback
}
