package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type MailAuditRequest struct {
	Domain       string `json:"domain"`
	MailHost     string `json:"mailHost"`
	ServerIP     string `json:"serverIp"`
	DKIMSelector string `json:"dkimSelector"`
}

type CopySnippet struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type MailCheckItem struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Status   string   `json:"status"` // "ok" | "warning" | "error" | "info"
	Summary  string   `json:"summary"`
	Details  []string `json:"details"`
}

type MailRemediationGuide struct {
	Severity     string        `json:"severity"` // "critical" | "warning" | "info"
	Category     string        `json:"category"`
	Title        string        `json:"title"`
	WhyItMatters string        `json:"whyItMatters"`
	Steps        []string      `json:"steps"`
	CopyItems    []CopySnippet `json:"copyItems,omitempty"`
	QuickAction  string        `json:"quickAction,omitempty"`
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
	CheckedAt     string                 `json:"checkedAt"`
	MailDomain    string                 `json:"mailDomain"`
	MailHost      string                 `json:"mailHost"`
	ServerIP      string                 `json:"serverIp"`
	Score         int                    `json:"score"`
	Grade         string                 `json:"grade"`
	Verdict       string                 `json:"verdict"`
	CriticalCount int                    `json:"criticalCount"`
	WarningCount  int                    `json:"warningCount"`
	PassedCount   int                    `json:"passedCount"`
	Checks        []MailCheckItem        `json:"checks"`
	Ports         []PortProbeResult      `json:"ports"`
	Blacklists    []RBLCheckEntry        `json:"blacklists"`
	Remediations  []MailRemediationGuide `json:"remediations"`
}

func makePublicResolvers() []*net.Resolver {
	out := []*net.Resolver{net.DefaultResolver}
	for _, srv := range []string{"8.8.8.8:53", "1.1.1.1:53"} {
		target := srv
		out = append(out, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 1800 * time.Millisecond}
				return d.DialContext(ctx, "udp", target)
			},
		})
	}
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

func lookupTXTQuick(fqdn string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	var lastErr error
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
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
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	for _, r := range makePublicResolvers() {
		ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
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
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	if at := strings.Index(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	}
	return strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
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
	Supports8Bit    bool
	SupportsSize    string
	OpenRelay       bool
	OpenRelayTested bool
	TLSState        *tls.ConnectionState
	TLSVerified     bool
	TLSVerifyErr    string
	DialErr         string
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

	reader := bufio.NewReader(conn)
	readResp := func() (int, []string, error) {
		var lines []string
		code := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return code, lines, err
			}
			line = strings.TrimRight(line, "\r\n")
			lines = append(lines, line)
			if len(line) >= 3 {
				_, _ = fmt.Sscanf(line[:3], "%d", &code)
			}
			if len(line) < 4 || line[3] != '-' {
				break
			}
		}
		return code, lines, nil
	}
	sendLine := func(cmd string) {
		_, _ = conn.Write([]byte(cmd + "\r\n"))
	}

	code, bannerLines, err := readResp()
	if err != nil || code != 220 {
		res.DialErr = fmt.Sprintf("неожиданный ответ SMTP: %v %v", code, bannerLines)
		return res
	}
	if len(bannerLines) > 0 {
		res.BannerLine = bannerLines[0]
		fields := strings.Fields(bannerLines[0])
		if len(fields) >= 2 {
			res.BannerHost = strings.Trim(strings.ToLower(fields[1]), ".")
		}
	}

	parseEHLOLines := func(lines []string) {
		for _, l := range lines {
			up := strings.ToUpper(l)
			if strings.Contains(up, "STARTTLS") {
				res.SupportsSTARTTLS = true
			}
			if strings.Contains(up, "AUTH ") || strings.HasSuffix(up, "AUTH") {
				res.SupportsAuth = true
			}
			if strings.Contains(up, "8BITMIME") {
				res.Supports8Bit = true
			}
			if idx := strings.Index(up, "SIZE"); idx >= 0 {
				res.SupportsSize = strings.TrimSpace(l[4:])
			}
		}
	}

	sendLine("EHLO audit.kerio-cert-manager.local")
	_, ehloLines, err := readResp()
	if err == nil {
		parseEHLOLines(ehloLines)
	}

	// Safe non-intrusive Open Relay probe on port 25 BEFORE STARTTLS (never sends DATA — immediately RSETs!)
	if checkRelay {
		sendLine("MAIL FROM:<check-noreply@example.org>")
		mCode, _, merr := readResp()
		if merr == nil && mCode >= 200 && mCode < 300 {
			sendLine("RCPT TO:<relay-audit-test@gmail.com>")
			rCode, _, rerr := readResp()
			res.OpenRelayTested = true
			if rerr == nil && rCode >= 200 && rCode < 300 {
				res.OpenRelay = true
			}
		} else if merr == nil {
			res.OpenRelayTested = true
		}
		sendLine("RSET")
		_, _, _ = readResp()
	}

	if res.SupportsSTARTTLS {
		sendLine("STARTTLS")
		stCode, _, stErr := readResp()
		if stErr == nil && stCode == 220 {
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: true,
			})
			if herr := tlsConn.Handshake(); herr == nil {
				st := tlsConn.ConnectionState()
				res.TLSState = &st
				verifyTrustedChain(&st, sniHost, &res.TLSVerified, &res.TLSVerifyErr)
				_, _ = tlsConn.Write([]byte("QUIT\r\n"))
				_ = tlsConn.Close()
				return res
			} else {
				res.TLSVerifyErr = herr.Error()
			}
		}
	}

	sendLine("QUIT")
	return res
}

func verifyTrustedChain(st *tls.ConnectionState, sniHost string, okOut *bool, errOut *string) {
	if st == nil || len(st.PeerCertificates) == 0 {
		*okOut = false
		*errOut = "сервер не отдал SSL-сертификат"
		return
	}
	leaf := st.PeerCertificates[0]
	interPool := x509.NewCertPool()
	for _, ic := range st.PeerCertificates[1:] {
		interPool.AddCert(ic)
	}
	opts := x509.VerifyOptions{
		DNSName:       sniHost,
		Intermediates: interPool,
		CurrentTime:   time.Now(),
	}
	if _, verr := leaf.Verify(opts); verr != nil {
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
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	t0 := time.Now()
	rawConn, err := net.DialTimeout("tcp", addr, 3800*time.Millisecond)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Open = true
	p.LatencyMs = time.Since(t0).Milliseconds()
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	if herr := tlsConn.Handshake(); herr != nil {
		p.Error = herr.Error()
		_ = rawConn.Close()
		return p
	}
	defer tlsConn.Close()
	st := tlsConn.ConnectionState()
	p.TLSOK = true
	p.TLSVersion = tlsVersionName(st.Version)
	var vErr string
	verifyTrustedChain(&st, host, &p.TLSTrusted, &vErr)
	if !p.TLSTrusted {
		p.Error = vErr
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		p.CertSubject = leaf.Subject.CommonName
		if p.CertSubject == "" && len(leaf.DNSNames) > 0 {
			p.CertSubject = leaf.DNSNames[0]
		}
		p.CertIssuer = leaf.Issuer.CommonName
		p.CertExpiry = leaf.NotAfter.Format("02.01.2006")
		p.CertDays = int(time.Until(leaf.NotAfter).Hours() / 24)
	}
	return p
}

func checkDNSBLLists(ip net.IP) []RBLCheckEntry {
	type rblDef struct {
		Name   string
		Zone   string
		Delist string
	}
	defs := []rblDef{
		{"Spamhaus ZEN", "zen.spamhaus.org", "https://check.spamhaus.org/"},
		{"Barracuda Reputation", "b.barracudacentral.org", "https://www.barracudacentral.org/rbl/removal-request"},
		{"SpamCop Blocking List", "bl.spamcop.net", "https://www.spamcop.net/bl.shtml"},
		{"SORBS DNSBL", "dnsbl.sorbs.net", "http://www.sorbs.net/lookup.shtml"},
		{"UCEPROTECT Level 1", "dnsbl-1.uceprotect.net", "https://www.uceprotect.net/en/rblcheck.php"},
		{"Passive Spam Block List (PSBL)", "psbl.surriel.com", "https://psbl.org/"},
		{"WPBL (Weighted Private Block List)", "db.wpbl.info", "http://wpbl.info/cgi-bin/detail.cgi"},
		{"NiX Spam (heise/manitu)", "ix.dnsbl.manitu.net", "https://www.dnsbl.manitu.net/"},
		{"SpamRATS NoPTR", "noptr.spamrats.com", "https://www.spamrats.com/lookup.php"},
		{"SpamRATS Dyna", "dyna.spamrats.com", "https://www.spamrats.com/lookup.php"},
		{"0SPAM Project", "bl.0spam.org", "https://0spam.org/check"},
	}

	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	revIP := fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])

	results := make([]RBLCheckEntry, len(defs))
	var wg sync.WaitGroup
	// Important: Use local/ISP resolver first for DNSBLs so Spamhaus doesn't block open Google/Cloudflare resolvers with 127.255.255.254!
	cloudflareOnly := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	for i, d := range defs {
		wg.Add(1)
		go func(idx int, def rblDef) {
			defer wg.Done()
			entry := RBLCheckEntry{
				Provider:  def.Name,
				Zone:      def.Zone,
				DelistURL: def.Delist,
			}
			q := revIP + "." + def.Zone
			ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, q)
			cancel()
			if err != nil && def.Zone != "zen.spamhaus.org" {
				ctx2, cancel2 := context.WithTimeout(context.Background(), 2000*time.Millisecond)
				addrs, err = cloudflareOnly.LookupIPAddr(ctx2, q)
				cancel2()
			}
			if err == nil {
				for _, a := range addrs {
					ip4 := a.IP.To4()
					// Filter out special error codes 127.255.255.x returned when open DNS resolvers query RBLs!
					if ip4 != nil && ip4[0] == 127 && ip4[1] < 255 {
						entry.Listed = true
						entry.ReturnCode = ip4.String()
						break
					}
				}
			}
			results[idx] = entry
		}(i, d)
	}
	wg.Wait()
	return results
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

	asciiInput, dispInput, err := NormalizeDomain(rawInput)
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

	// Smart split if user typed "mail.leend.by" directly in Domain field:
	// check whether asciiInput has MX; if not and parent domain (leend.by) exists, use parent as mailDomain and asciiInput as mailHost!
	mxs, mxErr := lookupMXMulti(mailDomain)
	if mxErr != nil {
		parts := strings.Split(asciiInput, ".")
		if len(parts) >= 3 {
			parentCandidate := strings.Join(parts[1:], ".")
			if parentMXs, perr := lookupMXMulti(parentCandidate); perr == nil && len(parentMXs) > 0 {
				if mailHost == "" {
					mailHost = asciiInput
				}
				mailDomain = parentCandidate
				mxs = parentMXs
				mxErr = nil
				log("info", fmt.Sprintf("Автоопределение: почтовый домен @%s, хост сервера %s", mailDomain, mailHost))
			} else if mailHost == "" {
				mailHost = asciiInput
				mailDomain = parentCandidate
			}
		}
	}
	if mailHost == "" {
		if len(mxs) > 0 {
			mailHost = mxs[0].Host
		} else {
			mailHost = "mail." + mailDomain
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

	// Always resolve real PUBLIC IP from DNS for PTR, SPF, and RBL checks!
	// If req.ServerIP is a private/VPN IP (e.g. 10.146.100.14), use it cleanly for TCP port probing when ISP blocks public port 25, while still auditing public IP in PTR/SPF/RBL!
	var publicIP string
	hostIPs, hostLookupErr := LookupDomainIPsMultiResolver(mailHost)
	if len(hostIPs) > 0 {
		for _, hip := range hostIPs {
			if p := net.ParseIP(hip); p != nil && p.To4() != nil {
				publicIP = hip
				break
			}
		}
		if publicIP == "" {
			publicIP = hostIPs[0]
		}
	}
	userOverrideHost := strings.TrimSpace(req.ServerIP)
	serverIP := publicIP
	if userOverrideHost != "" {
		if parsed := net.ParseIP(userOverrideHost); parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() {
			serverIP = userOverrideHost
		} else if serverIP == "" {
			serverIP = userOverrideHost
		}
	}
	report.ServerIP = serverIP

	// Run slow network checks in parallel:
	// 1. PTR check
	// 2. DNSBL 11 blacklists
	// 3. Port 25 SMTP + Banner + STARTTLS + Open Relay
	// 4. Port 587 Submission STARTTLS
	// 5. Implicit TLS ports: 465 SMTPS, 993 IMAPS, 995 POP3S, 443 WebMail HTTPS
	// 6. DKIM multi-selector scan
	var (
		ptrs     []string
		rbls     []RBLCheckEntry
		smtp25   smtpLiveDetails
		smtp587  smtpLiveDetails
		port465  PortProbeResult
		port993  PortProbeResult
		port995  PortProbeResult
		port443  PortProbeResult
		dkimFoundSelector string
		dkimFoundRecord   string
		spfRecords        []string
		dmarcRecords      []string
		mtaStsRecords     []string
		tlsRptRecords     []string
		autodiscoverIPs   []string
		autodiscoverSRVs  []string
	)

	probeTargetHost := mailHost
	if userOverrideHost != "" {
		probeTargetHost = userOverrideHost
	} else if serverIP != "" && hostLookupErr != nil {
		probeTargetHost = serverIP
	}

	var wg sync.WaitGroup
	wg.Add(10)

	go func() {
		defer wg.Done()
		if serverIP != "" {
			ptrs = lookupPTRMulti(serverIP)
		}
	}()

	go func() {
		defer wg.Done()
		if parsed := net.ParseIP(serverIP); parsed != nil {
			rbls = checkDNSBLLists(parsed)
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
		port465 = probeImplicitTLSPort(probeTargetHost, 465, "SMTPS (SSL отправка)")
	}()

	go func() {
		defer wg.Done()
		port993 = probeImplicitTLSPort(probeTargetHost, 993, "IMAPS (SSL почта)")
	}()

	go func() {
		defer wg.Done()
		port995 = probeImplicitTLSPort(probeTargetHost, 995, "POP3S (SSL сбор)")
	}()

	go func() {
		defer wg.Done()
		port443 = probeImplicitTLSPort(probeTargetHost, 443, "HTTPS (Kerio WebMail)")
	}()

	go func() {
		defer wg.Done()
		if txts, terr := lookupTXTQuick(mailDomain); terr == nil {
			for _, t := range txts {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
					spfRecords = append(spfRecords, strings.TrimSpace(t))
				}
			}
		}
		if dtxts, derr := lookupTXTQuick("_dmarc." + mailDomain); derr == nil {
			for _, t := range dtxts {
				if strings.Contains(strings.ToLower(t), "v=dmarc1") {
					dmarcRecords = append(dmarcRecords, strings.TrimSpace(t))
				}
			}
		}
		if stxts, serr := lookupTXTQuick("_mta-sts." + mailDomain); serr == nil {
			mtaStsRecords = stxts
		}
		if rtxts, rerr := lookupTXTQuick("_smtp._tls." + mailDomain); rerr == nil {
			tlsRptRecords = rtxts
		}
		if aips, aerr := LookupDomainIPsMultiResolver("autodiscover." + mailDomain); aerr == nil {
			autodiscoverIPs = aips
		}
		autodiscoverSRVs = lookupSRVAutodiscover(mailDomain)
	}()

	go func() {
		defer wg.Done()
		selectors := []string{}
		if custom := strings.TrimSpace(req.DKIMSelector); custom != "" {
			custom = strings.TrimSuffix(custom, "._domainkey")
			selectors = append(selectors, custom)
		}
		// "mail" is Kerio Connect's default built-in DKIM selector!
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

	// =========================================================================
	// CHECK 1: MX RECORDS
	// =========================================================================
	if len(mxs) == 0 {
		deduct(20)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "mx",
			Category: "DNS Маршрутизация",
			Title:    "Записи приёма почты (DNS MX)",
			Status:   "error",
			Summary:  fmt.Sprintf("У домена %s отсутствует MX-запись — внешние отправители не смогут доставить вам письма!", dispInput),
			Details:  []string{"Ни один публичный DNS-сервер (8.8.8.8 / 1.1.1.1) не вернул запись типа MX для " + mailDomain},
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "critical",
			Category:     "DNS Маршрутизация",
			Title:        "Добавьте MX-запись и A-запись почтового сервера в DNS",
			WhyItMatters: "Без MX-записи Gmail, Outlook, Yandex и любые внешние серверы не знают, куда доставлять входящие письма для @" + mailDomain + ", а также начисляют штраф при проверке обратного отправителя.",
			Steps: []string{
				"Откройте панель управления DNS вашего домена " + mailDomain + " (hoster.by / active.by / Cloudflare).",
				"Убедитесь, что создана запись типа A: Имя = mail, Значение = " + nonEmptyOr(serverIP, "<белый IP вашего сервера Kerio>") + ".",
				"Создайте запись типа MX: Имя = @ (пусто / корень домена), Приоритет = 10, Значение (Сервер) = " + mailHost + ".",
			},
			CopyItems: []CopySnippet{
				{Label: "Запись MX (Имя @, Приоритет 10)", Value: mailHost},
			},
		})
	} else {
		var mxDetails []string
		mxPointsToIP := false
		for _, m := range mxs {
			ips, _ := LookupDomainIPsMultiResolver(m.Host)
			if net.ParseIP(m.Host) != nil {
				mxPointsToIP = true
			}
			mxDetails = append(mxDetails, fmt.Sprintf("Приоритет %d → %s (%s)", m.Pref, m.Host, strings.Join(ips, ", ")))
		}
		if mxPointsToIP {
			deduct(10)
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "mx",
				Category: "DNS Маршрутизация",
				Title:    "Записи приёма почты (DNS MX)",
				Status:   "warning",
				Summary:  "MX-запись указывает напрямую на цифру IP вместо доменного имени (нарушение RFC 5321)!",
				Details:  mxDetails,
			})
			report.Remediations = append(report.Remediations, MailRemediationGuide{
				Severity:     "warning",
				Category:     "DNS Маршрутизация",
				Title:        "Исправьте MX-запись: укажите имя хоста (mail." + mailDomain + ") вместо IP-адреса",
				WhyItMatters: "По стандарту RFC 5321 MX-запись обязана указывать на доменное имя (A-запись), а не на IP-адрес. Многие антиспам-фильтры блокируют такие домены.",
				Steps: []string{
					"Создайте A-запись: mail." + mailDomain + " → " + nonEmptyOr(serverIP, "<IP сервера>"),
					"Измените значение MX-записи с IP-адреса на доменное имя mail." + mailDomain,
				},
			})
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "mx",
				Category: "DNS Маршрутизация",
				Title:    "Записи приёма почты (DNS MX)",
				Status:   "ok",
				Summary:  fmt.Sprintf("Найдено %d MX-записей (основной сервер: %s → %s)", len(mxs), mxs[0].Host, nonEmptyOr(serverIP, "OK")),
				Details:  mxDetails,
			})
		}
	}

	// =========================================================================
	// CHECK 2: REVERSE DNS (PTR) & FCrDNS — #1 SPAM CAUSE IN CIS/BELARUS!
	// =========================================================================
	if serverIP == "" {
		deduct(15)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "ptr",
			Category: "Обратная зона провайдера (PTR / rDNS)",
			Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
			Status:   "error",
			Summary:  fmt.Sprintf("Хост почтового сервера %s не резолвится в публичный IP-адрес!", mailHost),
		})
	} else if len(ptrs) == 0 {
		deduct(22)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "ptr",
			Category: "Обратная зона провайдера (PTR / rDNS)",
			Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
			Status:   "error",
			Summary:  fmt.Sprintf("У IP-адреса %s НЕТ обратной записи PTR! Письма на Gmail, Mail.ru, Yandex и многие корп. серверы будут отклоняться с ошибкой 550 5.7.1!", serverIP),
			Details: []string{
				"Проверенный IP сервера: " + serverIP,
				"Ожидаемая PTR-запись: " + mailHost,
				"Фактический ответ DNS: NXDOMAIN (запись отсутствует у интернет-провайдера)",
			},
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "critical",
			Category:     "Обратная зона провайдера (PTR / rDNS)",
			Title:        fmt.Sprintf("Пропишите обратную запись PTR для IP %s → %s у интернет-провайдера", serverIP, mailHost),
			WhyItMatters: "Отсутствие PTR — причина №1 мгновенной блокировки писем (ошибка 550 Client host rejected: cannot find your reverse hostname) в Gmail, Mail.ru, Yandex, Rambler и на корпоративных шлюзах. Важно: PTR-запись прописывается НЕ в панели домена hoster.by, а ТОЛЬКО у провайдера интернета, выдавшего статический IP " + serverIP + " (Белтелеком, A1, МТС, Деловая сеть и др.)!",
			Steps: []string{
				"Убедитесь, что прямая A-запись в вашей панели DNS уже существует: " + mailHost + " → " + serverIP + ".",
				"Отправьте заявку в техподдержку вашего интернет-провайдера (Белтелеком: support@belpak.by / кабинет юрлица, A1, МТС или хостинг-провайдер VPS) с текстом ниже.",
				"Подождите 1–4 часа после ответа провайдера и нажмите «Проверить снова» на этой вкладке.",
			},
			CopyItems: []CopySnippet{
				{
					Label: "Готовый текст заявки интернет-провайдеру на добавление PTR",
					Value: fmt.Sprintf("Здравствуйте! Просим прописать обратную DNS-запись (PTR / rDNS) в обратной зоне для нашего статического IP-адреса %s на имя нашего почтового сервера: %s. Прямая A-запись %s -> %s уже настроена. Заранее спасибо!", serverIP, mailHost, mailHost, serverIP),
				},
			},
		})
	} else {
		exactMatch := false
		fcrdnsOK := false
		genericISP := false
		for _, p := range ptrs {
			if strings.EqualFold(p, mailHost) {
				exactMatch = true
			}
			low := strings.ToLower(p)
			for _, bad := range []string{"pool", "dynamic", "dhcp", "pppoe", "broadband", "dsl", "cable", "nat"} {
				if strings.Contains(low, bad) {
					genericISP = true
				}
			}
			if fwdIPs, ferr := LookupDomainIPsMultiResolver(p); ferr == nil {
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
				Category: "Обратная зона провайдера (PTR / rDNS)",
				Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
				Status:   "ok",
				Summary:  fmt.Sprintf("Идеально! IP %s имеет PTR-запись %s, полностью совпадающую с прямой A-записью (FCrDNS OK)", serverIP, ptrs[0]),
				Details:  []string{fmt.Sprintf("%s ↔ %s (двусторонняя проверка FCrDNS пройдена)", serverIP, strings.Join(ptrs, ", "))},
			})
		} else {
			deduct(10)
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "ptr",
				Category: "Обратная зона провайдера (PTR / rDNS)",
				Title:    "Обратная запись IP-адреса (PTR / FCrDNS)",
				Status:   "warning",
				Summary:  fmt.Sprintf("PTR-запись есть (%s), но НЕ совпадает с именем почтового сервера (%s)", strings.Join(ptrs, ", "), mailHost),
				Details: []string{
					"Текущая PTR-запись у провайдера: " + strings.Join(ptrs, ", "),
					"Имя почтового сервера (MX / SSL): " + mailHost,
					fmt.Sprintf("Проверка FCrDNS (PTR → A → %s): %v, Похоже на пул провайдера: %v", serverIP, fcrdnsOK, genericISP),
				},
			})
			report.Remediations = append(report.Remediations, MailRemediationGuide{
				Severity:     "warning",
				Category:     "Обратная зона провайдера (PTR / rDNS)",
				Title:        fmt.Sprintf("Согласуйте обратную запись PTR (%s → %s) с именем сервера Kerio", ptrs[0], mailHost),
				WhyItMatters: "Когда PTR-запись IP-адреса (" + ptrs[0] + ") выглядит как техническое имя провайдера или не совпадает с именем SMTP-сервера (" + mailHost + "), спам-фильтры Gmail/Yandex снижают репутацию отправителя.",
				Steps: []string{
					"Попросите интернет-провайдера заменить текущую PTR-запись " + ptrs[0] + " для IP " + serverIP + " на " + mailHost + ".",
				},
				CopyItems: []CopySnippet{
					{
						Label: "Готовый текст заявки провайдеру на изменение PTR",
						Value: fmt.Sprintf("Здравствуйте! Просим изменить обратную запись PTR для нашего статического IP-адреса %s с текущего значения %s на имя почтового сервера: %s. Прямая A-запись %s -> %s настроена.", serverIP, ptrs[0], mailHost, mailHost, serverIP),
					},
				},
			})
		}
	}

	// =========================================================================
	// CHECK 3: SPF RECORD (v=spf1)
	// =========================================================================
	recommendedSPF := fmt.Sprintf("v=spf1 mx a:%s ~all", mailHost)
	if serverIP != "" {
		recommendedSPF = fmt.Sprintf("v=spf1 mx a:%s ip4:%s ~all", mailHost, serverIP)
	}
	if len(spfRecords) == 0 {
		deduct(18)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "spf",
			Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
			Title:    "Запись SPF (защита от подделки отправителя)",
			Status:   "error",
			Summary:  fmt.Sprintf("У домена %s НЕТ SPF-записи! Письма на Gmail, Yahoo, Mail.ru и корпоративную почту почти гарантированно попадут в СПАМ или будут отклонены (550 5.7.26)!", mailDomain),
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "critical",
			Category:     "Аутентификация отправителя (SPF)",
			Title:        "Добавьте TXT-запись SPF для домена " + mailDomain,
			WhyItMatters: "С 2024–2026 гг. Google (Gmail), Yahoo, Microsoft Outlook и Mail.ru официально отклоняют или отправляют в СПАМ все письма с доменов без корректной SPF-записи.",
			Steps: []string{
				"Откройте панель управления DNS домена " + mailDomain + " (hoster.by / active.by / Cloudflare).",
				"Создайте новую запись типа TXT.",
				"В поле Имя (Хост / Субдомен) укажите @ (или оставьте пустым, если панель обозначает корень домена пустым полем).",
				"В поле Значение вставьте готовую строку ниже (она уже включает ваш MX-сервер " + mailHost + " и внешний IP " + nonEmptyOr(serverIP, "") + ").",
			},
			CopyItems: []CopySnippet{
				{Label: "Имя записи (Host)", Value: "@"},
				{Label: "Готовое значение TXT (SPF)", Value: recommendedSPF},
			},
		})
	} else if len(spfRecords) > 1 {
		deduct(16)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "spf",
			Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
			Title:    "Запись SPF (защита от подделки отправителя)",
			Status:   "error",
			Summary:  fmt.Sprintf("КРИТИЧЕСКАЯ ОШИБКА: обнаружено сразу %d разных SPF-записей! По стандарту RFC 7208 это даёт статус PermError (SPF полностью сломан)!", len(spfRecords)),
			Details:  spfRecords,
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "critical",
			Category:     "Аутентификация отправителя (SPF)",
			Title:        "Объедините несколько SPF-записей в одну-единственную TXT-запись",
			WhyItMatters: "Если у домена больше одной записи v=spf1, любой почтовый сервер обязан вернуть ошибку PermError и отправить письмо в СПАМ.",
			Steps: []string{
				"Удалите дублирующиеся записи v=spf1 в панели DNS домена " + mailDomain + ", объединив все разрешённые include:/ip4: в одну строку.",
			},
			CopyItems: []CopySnippet{
				{Label: "Единая рекомендуемая SPF-запись", Value: recommendedSPF},
			},
		})
	} else {
		spf := spfRecords[0]
		lowSPF := strings.ToLower(spf)
		hasPlusAll := strings.Contains(lowSPF, "+all")
		coversServer := strings.Contains(lowSPF, "mx") ||
			(serverIP != "" && strings.Contains(lowSPF, serverIP)) ||
			strings.Contains(lowSPF, mailHost)
		if hasPlusAll {
			deduct(20)
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "spf",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Запись SPF (защита от подделки отправителя)",
				Status:   "error",
				Summary:  "ОПАСНО: в SPF-записи указано '+all' — это разрешает ЛЮБОМУ спамеру в мире рассылать письма от вашего имени!",
				Details:  []string{spf},
			})
			report.Remediations = append(report.Remediations, MailRemediationGuide{
				Severity:     "critical",
				Category:     "Аутентификация отправителя (SPF)",
				Title:        "Немедленно замените '+all' на '~all' или '-all' в SPF-записи",
				WhyItMatters: "Механизм +all отключает защиту домена и приводит к попаданию домена в чёрные списки.",
				Steps: []string{
					"Замените текущую TXT-запись SPF в панели DNS на безопасный вариант ниже:",
				},
				CopyItems: []CopySnippet{
					{Label: "Исправленное значение TXT (SPF)", Value: recommendedSPF},
				},
			})
		} else if !coversServer {
			deduct(14)
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "spf",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Запись SPF (защита от подделки отправителя)",
				Status:   "warning",
				Summary:  fmt.Sprintf("SPF-запись найдена, но в ней НЕ указан ни 'mx', ни IP вашего сервера %s — письма с Kerio не пройдут SPF!", serverIP),
				Details:  []string{"Текущая запись: " + spf},
			})
			mergedSPF := strings.TrimSpace(strings.Replace(spf, "~all", "", 1))
			mergedSPF = strings.TrimSpace(strings.Replace(mergedSPF, "-all", "", 1)) + fmt.Sprintf(" mx ip4:%s ~all", serverIP)
			report.Remediations = append(report.Remediations, MailRemediationGuide{
				Severity:     "critical",
				Category:     "Аутентификация отправителя (SPF)",
				Title:        "Добавьте IP вашего сервера Kerio (" + serverIP + ") в существующую SPF-запись",
				WhyItMatters: "Если сервер отправляет почту с IP " + serverIP + ", которого нет в вашей SPF-записи, все получатели видят статус SPF SoftFail / Fail -> СПАМ.",
				Steps: []string{
					"Откройте существующую TXT-запись v=spf1 в панели DNS домена " + mailDomain + ".",
					"Обновите её на объединённый вариант ниже (сохранены все ваши старые настройки + добавлен сервер Kerio):",
				},
				CopyItems: []CopySnippet{
					{Label: "Обновлённая запись TXT (SPF)", Value: mergedSPF},
				},
			})
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "spf",
				Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
				Title:    "Запись SPF (защита от подделки отправителя)",
				Status:   "ok",
				Summary:  "SPF-запись настроена корректно и включает ваш почтовый сервер: " + spf,
				Details:  []string{"Активная TXT-запись: " + spf},
			})
		}
	}

	// =========================================================================
	// CHECK 4: DKIM SIGNATURE (Kerio built-in "mail._domainkey" + auto-scan)
	// =========================================================================
	if dkimFoundRecord == "" {
		deduct(16)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "dkim",
			Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
			Title:    "Цифровая криптографическая подпись писем (DKIM)",
			Status:   "error",
			Summary:  fmt.Sprintf("В DNS не найдена публичная запись DKIM (проверены mail._domainkey.%s и ещё 11 стандартных селекторов)!", mailDomain),
			Details: []string{
				"В Kerio Connect по умолчанию используется имя записи: mail._domainkey." + mailDomain,
				"Без цифровой подписи DKIM письма часто попадают в папку «Спам» в Gmail, Outlook и Mail.ru (особенно с вложениями PDF/DOCX/счетами!).",
			},
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "critical",
			Category:     "Kerio Connect + DNS (DKIM)",
			Title:        "Включите криптографическую подпись DKIM в Kerio Connect за 2 минуты",
			WhyItMatters: "DKIM прикрепляет к каждому исходящему письму цифровую RSA-подпись вашего домена. Для Gmail, Mail.ru и Yandex наличие DKIM — главный признак легитимного корпоративного сервера, а не спам-бота.",
			Steps: []string{
				"Откройте веб-админку Kerio Connect: https://" + mailHost + ":4040/admin/ → раздел «Конфигурация» → «Домены».",
				"Дважды щёлкните на ваш домен «" + mailDomain + "» → перейдите на вкладку «Дополнительно» (в новых версиях — блок DomainKeys / DKIM).",
				"Поставьте галочку «Подписывать исходящие сообщения ключом DomainKeys Identified Mail (DKIM)» и нажмите кнопку «Показать открытый ключ» (Kerio сам сгенерирует ключ и покажет готовый текст v=DKIM1; k=rsa; p=...).",
				"Откройте панель DNS вашего домена (" + mailDomain + ") и создайте запись типа TXT с коротким именем mail._domainkey и скопированным из Kerio значением!",
				"Вернитесь в окно домена в Kerio Connect и нажмите «Проверить DNS» → «ОК» → «Применить».",
			},
			CopyItems: []CopySnippet{
				{Label: "Короткое имя TXT-записи (для hoster.by / Cloudflare / ISPmanager)", Value: "mail._domainkey"},
				{Label: "Полное FQDN-имя TXT-записи", Value: "mail._domainkey." + mailDomain},
			},
		})
	} else {
		algo, bits := parseDKIMPublicKeyBits(dkimFoundRecord)
		status := "ok"
		summary := fmt.Sprintf("Найдена активная запись DKIM (%s._domainkey.%s, ключ %s %d бит)", dkimFoundSelector, mailDomain, strings.ToUpper(algo), bits)
		if algo == "rsa" && bits > 0 && bits < 1024 {
			status = "warning"
			deduct(8)
			summary = fmt.Sprintf("DKIM найден (%s._domainkey), но длина RSA-ключа слишком мала (%d бит — рекомендуется 1024–2048 бит)!", dkimFoundSelector, bits)
		}
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "dkim",
			Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
			Title:    "Цифровая криптографическая подпись писем (DKIM)",
			Status:   status,
			Summary:  summary,
			Details:  []string{fmt.Sprintf("Селектор: %s._domainkey.%s", dkimFoundSelector, mailDomain), dkimFoundRecord},
		})
	}

	// =========================================================================
	// CHECK 5: DMARC POLICY (_dmarc.<domain>)
	// =========================================================================
	recommendedDMARC := fmt.Sprintf("v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:postmaster@%s; adkim=r; aspf=r", mailDomain)
	if len(dmarcRecords) == 0 {
		deduct(12)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "dmarc",
			Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
			Title:    "Политика DMARC (_dmarc." + mailDomain + ")",
			Status:   "error",
			Summary:  "Запись _dmarc." + mailDomain + " отсутствует! Gmail, Yahoo, Outlook и Mail.ru требуют обязательного наличия DMARC.",
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "warning",
			Category:     "Аутентификация отправителя (DMARC)",
			Title:        "Добавьте политику DMARC (_dmarc) в панель DNS домена " + mailDomain,
			WhyItMatters: "Политика DMARC связывает воедино SPF + DKIM и защищает ваших клиентов и бухгалтерию от фишинговых писем с подменой вашего домена @" + mailDomain + ". Важно: включайте p=quarantine после того, как настроили SPF и DKIM (на первое время для мониторинга можно поставить p=none).",
			Steps: []string{
				"Откройте панель управления DNS домена " + mailDomain + " (hoster.by / active.by / Cloudflare).",
				"Создайте запись типа TXT с коротким именем _dmarc и вставьте готовое значение ниже:",
			},
			CopyItems: []CopySnippet{
				{Label: "Короткое имя TXT (для hoster.by / Cloudflare)", Value: "_dmarc"},
				{Label: "Полное имя FQDN", Value: "_dmarc." + mailDomain},
				{Label: "Готовое значение TXT (защита p=quarantine + отчёты на postmaster)", Value: recommendedDMARC},
				{Label: "Мягкий стартовый вариант TXT (p=none — если DKIM ещё не включён)", Value: fmt.Sprintf("v=DMARC1; p=none; rua=mailto:postmaster@%s", mailDomain)},
			},
		})
	} else {
		dm := dmarcRecords[0]
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "dmarc",
			Category: "Аутентификация отправителя (SPF / DKIM / DMARC)",
			Title:    "Политика DMARC (_dmarc." + mailDomain + ")",
			Status:   "ok",
			Summary:  "Политика DMARC настроена: " + dm,
			Details:  dmarcRecords,
		})
	}

	// =========================================================================
	// CHECK 6: SMTP PORT 25 + HELO BANNER HOSTNAME + OPEN RELAY CHECK
	// =========================================================================
	if !smtp25.Reachable {
		// Note: Outbound port 25 from client ISP might be filtered even if server is fine, explain clearly!
		deduct(8)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "smtp25",
			Category: "Служба SMTP и безопасность Kerio Connect",
			Title:    "Доступность SMTP-сервера (порт 25), баннер EHLO и проверка Open Relay",
			Status:   "warning",
			Summary:  fmt.Sprintf("Не удалось подключиться к %s:25 (%s)", probeTargetHost, smtp25.DialErr),
			Details: []string{
				"Возможные причины: 1) Ваш текущий интернет-провайдер на рабочем ПК блокирует исходящий порт 25 (частая практика у домашних тарифов Белтелеком/A1), ИЛИ 2) На межсетевом экране почтового сервера закрыт входящий порт TCP 25 (тогда к вам не доходят внешние письма!).",
			},
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "warning",
			Category:     "Служба SMTP и межсетевой экран",
			Title:        "Проверьте открытость входящего порта TCP 25 на роутере почтового сервера",
			WhyItMatters: "Все внешние почтовые серверы интернета доставляют входящую почту строго на порт TCP 25 (SMTP).",
			Steps: []string{
				"Если вы запустили проверку с домашнего/мобильного интернета — провайдер вашего ПК может резать исходящий порт 25 (в этом случае проверьте приём тестовым письмом с Gmail/Yandex).",
				"Если внешние письма действительно не приходят — на главном роутере почтового сервера проверьте проброс порта TCP 25 → внутренний IP сервера Kerio Connect, а в Kerio WebAdmin (Конфигурация → Службы → SMTP) убедитесь, что служба запущена.",
			},
		})
	} else {
		// Check Open Relay FIRST — emergency security priority!
		if smtp25.OpenRelay {
			deduct(35)
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "relay",
				Category: "Служба SMTP и безопасность Kerio Connect",
				Title:    "КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Открытый почтовый релей (Open Relay)!",
				Status:   "error",
				Summary:  "СЕРВЕР ПРИНЯЛ ЧУЖОЕ ПИСЬМО НА ВНЕШНИЙ АДРЕС БЕЗ ПАРОЛЯ! Ваш IP попадёт во все мировые спам-базы за считанные часы!",
				Details:  []string{"Проверка MAIL FROM:<check-noreply@example.org> → RCPT TO:<relay-audit-test@gmail.com> вернула код 250 OK вместо 550 Relay denied!"},
			})
			report.Remediations = append(report.Remediations, MailRemediationGuide{
				Severity:     "critical",
				Category:     "Безопасность Kerio Connect",
				Title:        "СРОЧНО закройте Открытый релей (Open Relay) в настройках Kerio Connect!",
				WhyItMatters: "Спам-боты круглосуточно сканируют порт 25. Сервер с открытым релеем за 2–3 часа начинает рассылать десятки тысяч спам-писем, после чего IP блокируется в Spamhaus и у провайдера связи.",
				Steps: []string{
					"Немедленно откройте Kerio Connect WebAdmin → «Конфигурация» → «Сервер SMTP» → вкладка «Контроль реле (Relay Control)».",
					"Снимите разрешение «Открытый релей» и выберите «Открыть реле только для следующих IP-групп» (оставьте ТОЛЬКО «Локальные клиенты / 127.0.0.1», а НЕ всю подсеть роутера, если роутер делает Src-NAT/Masquerade на входящий порт 25!).",
					"Внимание (частая ловушка MikroTik/Kerio Control!): если на роутере включён Masquerade на внутреннем интерфейсе LAN, Kerio Connect видит ВСЕ входящие письма из интернета как пришедшие с локального IP самого роутера (например, 10.146.100.1) и считает их «своими»! Отключите src-nat/masquerade для проброса порта 25 на роутере или уберите IP шлюза из доверенной группы релея в Kerio!",
					"Обязательно оставьте галочку «Пользователи, прошедшие аутентификацию по SMTP, могут пересылать почту куда угодно».",
				},
			})
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "relay",
				Category: "Служба SMTP и безопасность Kerio Connect",
				Title:    "Защита от открытого релея (Open Relay Protection)",
				Status:   "ok",
				Summary:  "Отлично! Сервер надёжно отклоняет неавторизованную пересылку чужой почты (550 Relay denied).",
			})
		}

		// Check SMTP Banner Hostname == mailHost
		bannerMatches := strings.EqualFold(smtp25.BannerHost, mailHost)
		isLocalBanner := strings.HasSuffix(smtp25.BannerHost, ".local") || strings.HasSuffix(smtp25.BannerHost, ".lan") || !strings.Contains(smtp25.BannerHost, ".")
		if !bannerMatches || isLocalBanner {
			deduct(10)
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "banner",
				Category: "Служба SMTP и безопасность Kerio Connect",
				Title:    "Приветствие SMTP-сервера (HELO / Banner Hostname)",
				Status:   "warning",
				Summary:  fmt.Sprintf("В приветствии SMTP сервер представляется как «%s» вместо «%s»!", smtp25.BannerHost, mailHost),
				Details: []string{
					"Полученный баннер 220: " + smtp25.BannerLine,
					"Ожидаемое имя в баннере (совпадающее с MX, A и PTR): " + mailHost,
				},
			})
			report.Remediations = append(report.Remediations, MailRemediationGuide{
				Severity:     "warning",
				Category:     "Kerio Connect SMTP",
				Title:        fmt.Sprintf("Пропишите правильное Интернет-имя узла (%s) в настройках SMTP Kerio Connect", mailHost),
				WhyItMatters: "Когда Kerio Connect при отправке писем представляется внутренним именем Windows-сервера (например, WIN-SERVER.domain.local или localhost), антиспам-фильтры SpamAssassin / Rspamd начисляют штрафные баллы HELO_LOCALHOST / HELO_MISMATCH и отправляют письма в Спам!",
				Steps: []string{
					"Откройте веб-админку Kerio Connect → «Конфигурация» → «Сервер SMTP» → вкладка «Общие» (или «Конфигурация» → «Сетевые настройки» / «Домены»).",
					"В поле «Имя узла в сети Интернет (Internet hostname)» впишите ровно: " + mailHost,
					"Нажмите «Применить» — изменение вступает в силу сразу без перезагрузки сервера!",
				},
				CopyItems: []CopySnippet{
					{Label: "Имя узла в сети Интернет для Kerio SMTP", Value: mailHost},
				},
			})
		} else {
			report.Checks = append(report.Checks, MailCheckItem{
				ID:       "banner",
				Category: "Служба SMTP и безопасность Kerio Connect",
				Title:    "Приветствие SMTP-сервера (HELO / Banner Hostname)",
				Status:   "ok",
				Summary:  fmt.Sprintf("Баннер SMTP корректен (%s — отклик %d мс)", smtp25.BannerHost, smtp25.LatencyMs),
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
			sslDetails = append(sslDetails, fmt.Sprintf("Порт %d (%s): закрыт / недоступен", p.Port, p.Protocol))
			continue
		}
		anyOpenMailPort = true
		if !p.TLSOK {
			sslBadPorts = append(sslBadPorts, fmt.Sprintf("%d (TLS не включён)", p.Port))
			sslDetails = append(sslDetails, fmt.Sprintf("Порт %d (%s): открыт (%d мс), но шифрование TLS/STARTTLS не сработало!", p.Port, p.Protocol, p.LatencyMs))
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
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "ssl",
			Category: "Шифрование почты (SSL / STARTTLS)",
			Title:    "Проверка SSL-сертификата и полной цепочки CA на почтовых портах",
			Status:   "error",
			Summary:  fmt.Sprintf("На почтовых портах [%s] обнаружен недоверенный / самоподписанный / неполный SSL-сертификат!", strings.Join(sslBadPorts, ", ")),
			Details:  sslDetails,
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "critical",
			Category:     "Шифрование почты (SSL / STARTTLS)",
			Title:        "Установите доверенный SSL-сертификат Let's Encrypt с полной цепочкой (Fullchain) на " + mailHost,
			WhyItMatters: "При самоподписанном или просроченном сертификате (или если загружен только листовой сертификат без промежуточного R10/R11) Outlook, iPhone/Android выдают постоянные окна ошибок безопасности, внешние серверы с политикой MTA-STS отказываются принимать письма, а спам-фильтры снижают рейтинг доверия TLS.",
			Steps: []string{
				"Нажмите кнопку ниже «Перейти к выпуску доверенного SSL для " + mailHost + "» прямо в этой программе!",
				"Выпустите бесплатный 90-дневный сертификат Let's Encrypt для домена " + mailHost + ".",
				"Установите его в 1 клик через вкладку «Установка в Kerio Connect» (порт 4040) — наш файл server.crt уже содержит полную цепочку Fullchain!",
			},
			QuickAction: "goto_issue_ssl",
		})
	} else if sslExpiringSoon && anyOpenMailPort {
		deduct(8)
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "ssl",
			Category: "Шифрование почты (SSL / STARTTLS)",
			Title:    "Проверка SSL-сертификата и полной цепочки CA на почтовых портах",
			Status:   "warning",
			Summary:  fmt.Sprintf("SSL-сертификат действителен, но истекает уже через %d дн.! Пора обновить сертификат.", sslDaysMin),
			Details:  sslDetails,
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "warning",
			Category:     "Шифрование почты (SSL / STARTTLS)",
			Title:        fmt.Sprintf("Обновите истекающий SSL-сертификат на %s (осталось %d дн.)", mailHost, sslDaysMin),
			WhyItMatters: "Как только срок действия сертификата закончится, у всех сотрудников в Outlook, на iPhone и Android мгновенно остановится отправка и получение почты.",
			Steps: []string{
				"Нажмите кнопку ниже, чтобы за 1 минуту перевыпустить свежий сертификат для " + mailHost + " и активировать его в Kerio Connect.",
			},
			QuickAction: "goto_issue_ssl",
		})
	} else if anyOpenMailPort {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "ssl",
			Category: "Шифрование почты (SSL / STARTTLS)",
			Title:    "Проверка SSL-сертификата и полной цепочки CA на почтовых портах",
			Status:   "ok",
			Summary:  fmt.Sprintf("Все открытые почтовые порты используют полностью доверенный SSL-сертификат (осталось %d дн.)!", sslDaysMin),
			Details:  sslDetails,
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
		var steps []string
		steps = append(steps, "1. Сначала устраните первопричину попадания IP в спам-базу: проверьте, нет ли взломанного почтового ящика со слабым паролем в Kerio Connect (Статус → Очередь сообщений — если в очереди сотни чужих писем, смените пароль скомпрометированного пользователя!), закройте Open Relay и обязательно пропишите PTR-запись у провайдера!")
		for _, b := range listedIn {
			bDetails = append(bDetails, fmt.Sprintf("🔴 В чёрном списке %s (%s) — код ответа %s, ссылка удаления: %s", b.Provider, b.Zone, b.ReturnCode, b.DelistURL))
			steps = append(steps, fmt.Sprintf("Подайте бесплатный запрос на удаление IP %s из %s по ссылке: %s", serverIP, b.Provider, b.DelistURL))
		}
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "rbl",
			Category: "Репутация IP в спам-базах (DNSBL / RBL)",
			Title:    fmt.Sprintf("Проверка IP %s по %d мировым чёрным спискам спама", serverIP, len(rbls)),
			Status:   "error",
			Summary:  fmt.Sprintf("ВНИМАНИЕ: IP-адрес %s найден в %d спам-базах! Исходящие письма блокируются на уровне соединения!", serverIP, len(listedIn)),
			Details:  bDetails,
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "critical",
			Category:     "Репутация IP (удаление из чёрных списков)",
			Title:        fmt.Sprintf("Исключите IP-адрес %s из чёрных списков спама (%d баз)", serverIP, len(listedIn)),
			WhyItMatters: "Большинство почтовых систем проверяют IP отправителя по базам Spamhaus, Barracuda и SpamCop ещё до чтения заголовков письма и мгновенно разрывают соединение.",
			Steps:        steps,
		})
	} else if len(rbls) > 0 {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "rbl",
			Category: "Репутация IP в спам-базах (DNSBL / RBL)",
			Title:    fmt.Sprintf("Проверка IP %s по %d мировым чёрным спискам спама", serverIP, len(rbls)),
			Status:   "ok",
			Summary:  fmt.Sprintf("Чисто! IP-адрес %s не числится ни в одном из %d проверенных чёрных списков (Spamhaus, Barracuda, SpamCop, SORBS и др.).", serverIP, len(rbls)),
		})
	}

	// =========================================================================
	// CHECK 9: OUTLOOK / MOBILE AUTODISCOVER & MTA-STS / TLS-RPT BONUS
	// =========================================================================
	if len(autodiscoverIPs) == 0 && len(autodiscoverSRVs) == 0 {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "autodiscover",
			Category: "Удобство клиентов и расширенные стандарты",
			Title:    "Автонастройка Outlook / мобильных клиентов (Autodiscover) и TLS-RPT",
			Status:   "info",
			Summary:  fmt.Sprintf("Не настроена SRV-запись _autodiscover._tcp.%s (сотрудникам приходится вводить сервер и порты в Outlook вручную).", mailDomain),
			Details: []string{
				fmt.Sprintf("MTA-STS: %d записей, TLS-RPT: %d записей", len(mtaStsRecords), len(tlsRptRecords)),
			},
		})
		report.Remediations = append(report.Remediations, MailRemediationGuide{
			Severity:     "info",
			Category:     "Автонастройка почтовых клиентов Kerio Connect",
			Title:        "Добавьте SRV-запись Autodiscover для автонастройки Microsoft Outlook и телефонов",
			WhyItMatters: "Когда сотрудник вводит только email и пароль в Outlook / iOS / Android, клиент автоматически находит сервер " + mailHost + ":443 без ручного ввода IMAP/SMTP портов! И при этом не нужно выпускать отдельный SSL-сертификат на поддомен autodiscover." + mailDomain + "!",
			Steps: []string{
				"В панели DNS домена " + mailDomain + " создайте запись типа SRV: Служба/Имя = _autodiscover._tcp, Приоритет = 0, Вес = 0, Порт = 443, Цель (Target) = " + mailHost,
				"(По желанию) Добавьте TXT-запись отчётности о сбоях шифрования _smtp._tls → v=TLSRPTv1; rua=mailto:postmaster@" + mailDomain,
			},
			CopyItems: []CopySnippet{
				{Label: "Запись SRV (_autodiscover._tcp — Приоритет 0, Вес 0, Порт 443)", Value: mailHost},
				{Label: "Запись TXT (_smtp._tls — отчёты о доставке TLS)", Value: fmt.Sprintf("v=TLSRPTv1; rua=mailto:postmaster@%s", mailDomain)},
			},
		})
	} else {
		report.Checks = append(report.Checks, MailCheckItem{
			ID:       "autodiscover",
			Category: "Удобство клиентов и расширенные стандарты",
			Title:    "Автонастройка Outlook / мобильных клиентов (Autodiscover) и TLS-RPT",
			Status:   "ok",
			Summary:  "Автонастройка почтовых клиентов (Autodiscover) настроена в DNS!",
			Details:  append(autodiscoverIPs, autodiscoverSRVs...),
		})
	}

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
		report.Verdict = "Хорошая настройка сервера! Почта ходит стабильно, но есть пара тонких улучшений ниже для максимальной репутации 10/10."
	case report.Score >= 65:
		report.Grade = "B"
		report.Verdict = "Почта ходит, но часть писем (особенно в Gmail / строгие корп. фильтры) может попадать в папку «Спам». Выполните пошаговую инструкцию ниже!"
	case report.Score >= 45:
		report.Grade = "C"
		report.Verdict = "Высокий риск попадания в «Спам» и отказов при отправке писем! Ниже подготовлен точный план исправления по шагам."
	default:
		report.Grade = "F"
		report.Verdict = "Критические проблемы настройки почтового сервера — многие почтовые провайдеры блокируют ваши письма! Исправьте пункты ниже по порядку."
	}

	log("success", fmt.Sprintf("Аудит @%s (%s) завершён: рейтинг %d/100 (оценка %s) — успешно: %d, предупреждений: %d, критических: %d",
		mailDomain, mailHost, report.Score, report.Grade, report.PassedCount, report.WarningCount, report.CriticalCount))

	return report, nil
}

func nonEmptyOr(val, fallback string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return fallback
}
