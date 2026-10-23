package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// DELIST CENTER MODELS & READY-TO-SEND APPEAL TEMPLATES
// ============================================================================

type DelistPreCheckItem struct {
	Label  string `json:"label"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type DelistProviderAction struct {
	ID            string   `json:"id"`
	Provider      string   `json:"provider"`
	TargetType    string   `json:"targetType"` // "IP RBL" | "Domain DBL" | "Почтовый гигант (Private BL)" | "Интернет-провайдер"
	IsListedNow   bool     `json:"isListedNow"`
	ReturnCode    string   `json:"returnCode,omitempty"`
	CodeMeaning   string   `json:"codeMeaning,omitempty"`
	PortalURL     string   `json:"portalUrl"`
	SupportEmail  string   `json:"supportEmail,omitempty"`
	SubjectLine   string   `json:"subjectLine"`
	LetterBody    string   `json:"letterBody"`
	MailtoLink    string   `json:"mailtoLink,omitempty"`
	ImportantNote string   `json:"importantNote,omitempty"`
	Steps         []string `json:"steps"`
}

type DelistCenterData struct {
	ReadyForDelist     bool                   `json:"readyForDelist"`
	ReadinessSummary   string                 `json:"readinessSummary"`
	PreChecks          []DelistPreCheckItem   `json:"preChecks"`
	MikrotikPort25Rule string                 `json:"mikrotikPort25Rule"`
	ActiveListings     []DelistProviderAction `json:"activeListings"`
	MajorProviders     []DelistProviderAction `json:"majorProviders"`
}

type TestEmailRequest struct {
	SMTPHost  string `json:"smtpHost"`
	SMTPPort  int    `json:"smtpPort"`
	Security  string `json:"security"` // "starttls" | "ssl" | "plain"
	Username  string `json:"username"`
	Password  string `json:"password"`
	FromEmail string `json:"fromEmail"`
	ToEmail   string `json:"toEmail"`
}

type TestEmailResult struct {
	Success    bool     `json:"success"`
	DurationMs int64    `json:"durationMs"`
	TLSInfo    string   `json:"tlsInfo"`
	ServerResp string   `json:"serverResp"`
	SessionLog []string `json:"sessionLog"`
}

type BounceDecodeRequest struct {
	BounceText   string `json:"bounceText"`
	MailDomain   string `json:"mailDomain"`
	MailHost     string `json:"mailHost"`
	ServerIP     string `json:"serverIp"`
	ContactEmail string `json:"contactEmail"`
}

type BounceDecodeResult struct {
	DetectedProviderID string               `json:"detectedProviderId"`
	DetectedTitle      string               `json:"detectedTitle"`
	Explanation        string               `json:"explanation"`
	RecommendedAction  DelistProviderAction `json:"recommendedAction"`
}

// ============================================================================
// EXPANDED 16 IP DNSBLs + 4 DOMAIN DBLs WITH EXACT RETURN-CODE DECODER
// ============================================================================

type rblProviderSpec struct {
	id     string
	name   string
	zone   string
	urlFmt string // %s replaced with IP or domain
}

func explainDNSBLReturnCode(providerID, code string) string {
	switch providerID {
	case "spamhaus":
		switch code {
		case "127.0.0.2":
			return "SBL (Spamhaus Block List) — прямая рассылка спама или скомпрометированный сервер; требуется устранение причины и заявка на check.spamhaus.org"
		case "127.0.0.3":
			return "SBL CSS — подозрительная спам-активность с подсети/IP; требуется проверка очереди Kerio и запрос удаления"
		case "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7":
			return "XBL / CBL (Composite Blocking List) — ЗАРАЖЁННЫЙ ПК В ОФИСНОЙ СЕТИ или взломанный аккаунт рассылает спам с вашего NAT IP, либо некорректный HELO! Закройте на роутере порт 25 для всех ПК, кроме сервера Kerio!"
		case "127.0.0.10", "127.0.0.11":
			return "PBL (Policy Block List) — провайдер пометил диапазон IP как «динамический/пользовательский»! НЕ является спамом: пропишите PTR у провайдера и за 2 минуты снимите блокировку самостоятельно на check.spamhaus.org!"
		}
	case "backscatterer":
		return "Backscatter (Обратный спам) — сервер отправляет автоответы/отлупы (NDR) на поддельные чужие адреса отправителей! Отключите NDR наружу в Kerio Connect."
	case "blocklistde":
		return "BlockList.de — с вашего белого IP фиксировались попытки подбора паролей (SSH / SMTP / RDP brute-force) с заражённого устройства внутри офиса!"
	case "uceprotect":
		return "UCEPROTECT L1 — ВНИМАНИЕ: НИКОГДА НЕ ПЛАТИТЕ ДЕНЬГИ UCEPROTECT за платное экспресс-удаление! После устранения причины IP удаляется автоматически и бесплатно через 7 дней."
	}
	if code != "" {
		return "Код листинга " + code + " — требуется устранение первопричины и запрос на исключение (Delist)"
	}
	return ""
}

func checkExpandedDNSBLLists(ip net.IP) []RBLCheckEntry {
	ip4 := ip.To4()
	if ip4 == nil || ip.IsPrivate() || ip.IsLoopback() {
		return nil
	}
	ipStr := ip4.String()
	rev := fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])

	providers := []rblProviderSpec{
		{"spamhaus", "Spamhaus ZEN (SBL+XBL+PBL)", "zen.spamhaus.org", "https://check.spamhaus.org/results/?query=%s"},
		{"barracuda", "Barracuda Reputation (BRBL)", "b.barracudacentral.org", "https://www.barracudacentral.org/rbl/removal-request"},
		{"spamcop", "SpamCop Blocking List", "bl.spamcop.net", "https://www.spamcop.net/w3m?action=checkblock&ip=%s"},
		{"sorbs", "SORBS DNSBL", "dnsbl.sorbs.net", "http://www.sorbs.net/cgi-bin/support"},
		{"backscatterer", "Backscatterer (Обратный спам NDR)", "ips.backscatterer.org", "https://ips.backscatterer.org/?ip=%s"},
		{"blocklistde", "BlockList.de (Атаки / Брутфорс)", "bl.blocklist.de", "https://www.blocklist.de/en/delist.html"},
		{"uceprotect", "UCEPROTECT Level 1", "dnsbl-1.uceprotect.net", "https://www.uceprotect.net/en/rblcheck.php?ipr=%s"},
		{"psbl", "PSBL (Passive Spam Block)", "psbl.surriel.com", "https://psbl.org/listing?ip=%s"},
		{"wpbl", "WPBL (Weighted Private)", "db.wpbl.info", "http://wpbl.info/cgi-bin/detail.cgi?ip=%s"},
		{"mailspike", "Mailspike Reputation BL", "bl.mailspike.net", "https://mailspike.org/iplookup.html"},
		{"nixspam", "NiX Spam (Heise Germany)", "ix.dnsbl.manitu.net", "https://www.dnsbl.manitu.net/?value=%s"},
		{"spamrats", "SpamRATS All (No-PTR / Bot)", "all.spamrats.com", "https://www.spamrats.com/lookup.php?ip=%s"},
		{"zerospam", "0SPAM Project", "bl.0spam.org", "https://0spam.org/check"},
		{"truncate", "Truncate GBUdb", "truncate.gbudb.net", "http://www.gbudb.com/truncate/index.jsp"},
		{"lashback", "LashBack Unsubscribe BL", "ubl.unsubscore.com", "https://blacklist.lashback.com/"},
		{"dronebl", "DroneBL (Заражённые хосты / NAT)", "dnsbl.dronebl.org", "https://dronebl.org/lookup?ip=%s"},
	}

	out := make([]RBLCheckEntry, len(providers))
	var wg sync.WaitGroup
	sysRes := net.DefaultResolver

	for i, prv := range providers {
		wg.Add(1)
		go func(idx int, spec rblProviderSpec) {
			defer wg.Done()
			delistURL := spec.urlFmt
			if strings.Contains(delistURL, "%s") {
				delistURL = fmt.Sprintf(spec.urlFmt, url.QueryEscape(ipStr))
			}
			entry := RBLCheckEntry{
				Provider:  spec.name,
				Zone:      spec.zone,
				DelistURL: delistURL,
			}
			q := rev + "." + spec.zone

			// Try direct OS DNS first (avoids Spamhaus public-resolver block code 127.255.255.254)
			ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
			ips, err := sysRes.LookupIPAddr(ctx, q)
			cancel()
			isNXDomain := false
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				isNXDomain = true
			}
			if err == nil && len(ips) > 0 {
				for _, hit := range ips {
					h4 := hit.IP.To4()
					if h4 != nil && h4[0] == 127 && !(h4[1] == 255 && h4[2] == 255) {
						entry.Listed = true
						entry.ReturnCode = h4.String() + " — " + explainDNSBLReturnCode(spec.id, h4.String())
						break
					}
				}
			} else if !isNXDomain && spec.id != "spamhaus" {
				// Fallback via DoH ONLY when UDP/53 timed out or failed (NOT on NXDOMAIN, which already proves clean status!)
				if ans, _, derr := queryDoH(q, "A"); derr == nil {
					for _, a := range ans {
						if a.Type == 1 {
							if h4 := net.ParseIP(a.Data).To4(); h4 != nil && h4[0] == 127 && !(h4[1] == 255 && h4[2] == 255) {
								entry.Listed = true
								entry.ReturnCode = h4.String() + " — " + explainDNSBLReturnCode(spec.id, h4.String())
								break
							}
						}
					}
				}
			}
			out[idx] = entry
		}(i, prv)
	}
	wg.Wait()
	return out
}

// Check domain blacklists (DBL / SURBL / URIBL / SEM)
func checkDomainBlacklists(domain string) []RBLCheckEntry {
	specs := []rblProviderSpec{
		{"dbl", "Spamhaus DBL (Репутация домена)", "dbl.spamhaus.org", "https://check.spamhaus.org/results/?query=%s"},
		{"surbl", "SURBL Multi (Ссылки в письмах)", "multi.surbl.org", "http://www.surbl.org/surbl-analysis"},
		{"uribl", "URIBL Multi (Доменный фильтр)", "multi.uribl.com", "https://lookup.uribl.com/"},
		{"sem", "SpamEatingMonkey URI", "uribl.spameatingmonkey.net", "https://spameatingmonkey.com/lookup/%s"},
	}
	out := make([]RBLCheckEntry, len(specs))
	var wg sync.WaitGroup
	sysRes := net.DefaultResolver
	for i, sp := range specs {
		wg.Add(1)
		go func(idx int, spec rblProviderSpec) {
			defer wg.Done()
			u := spec.urlFmt
			if strings.Contains(u, "%s") {
				u = fmt.Sprintf(spec.urlFmt, url.QueryEscape(domain))
			}
			e := RBLCheckEntry{
				Provider:  spec.name,
				Zone:      spec.zone,
				DelistURL: u,
			}
			q := domain + "." + spec.zone
			ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
			ips, err := sysRes.LookupIPAddr(ctx, q)
			cancel()
			if err == nil && len(ips) > 0 {
				for _, hit := range ips {
					h4 := hit.IP.To4()
					// URIBL returns 127.0.0.255 when blocked query, Spamhaus DBL returns 127.255.255.x
					if h4 != nil && h4[0] == 127 && !(h4[1] == 255 && h4[2] == 255) && h4[3] != 255 {
						e.Listed = true
						e.ReturnCode = h4.String()
						break
					}
				}
			}
			out[idx] = e
		}(i, sp)
	}
	wg.Wait()
	return out
}

// ============================================================================
// DEEP CHECK HELPERS: SPF LOOKUP COUNT, DANGEROUS PORTS, LEGACY TLS, CAA, POSTMASTER
// ============================================================================

// countSPFDNSLookups counts recursive RFC 7208 DNS-querying mechanisms (max allowed by standard = 10!).
func countSPFDNSLookups(domain string, spf string, depth int, visited map[string]bool) (count int, usedDeprecatedPTR bool, details []string) {
	if depth > 3 {
		return 0, false, nil
	}
	tokens := strings.Fields(spf)
	for _, tok := range tokens {
		low := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(tok, "+"), "-"), "~"), "?"))
		switch {
		case low == "a" || strings.HasPrefix(low, "a:") || strings.HasPrefix(low, "a/"):
			count++
		case low == "mx" || strings.HasPrefix(low, "mx:") || strings.HasPrefix(low, "mx/"):
			count++
		case low == "ptr" || strings.HasPrefix(low, "ptr:"):
			count++
			usedDeprecatedPTR = true
		case strings.HasPrefix(low, "exists:"):
			count++
		case strings.HasPrefix(low, "include:"):
			count++
			incDom := strings.TrimPrefix(low, "include:")
			if incDom != "" && !visited[incDom] {
				visited[incDom] = true
				var subSPF string
				if txts, err := lookupTXTQuick(incDom); err == nil {
					for _, t := range txts {
						if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
							subSPF = t
							break
						}
					}
				}
				if subSPF != "" {
					subCnt, subPTR, _ := countSPFDNSLookups(incDom, subSPF, depth+1, visited)
					count += subCnt
					if subPTR {
						usedDeprecatedPTR = true
					}
					details = append(details, fmt.Sprintf("include:%s (+%d вложенных DNS-запросов)", incDom, 1+subCnt))
				} else {
					details = append(details, fmt.Sprintf("include:%s (⚠️ запись не найдена — +1 пустой запрос!)", incDom))
				}
			}
		case strings.HasPrefix(low, "redirect="):
			count++
			redDom := strings.TrimPrefix(low, "redirect=")
			if redDom != "" && !visited[redDom] {
				visited[redDom] = true
				if txts, err := lookupTXTQuick(redDom); err == nil {
					for _, t := range txts {
						if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
							subCnt, subPTR, _ := countSPFDNSLookups(redDom, t, depth+1, visited)
							count += subCnt
							if subPTR {
								usedDeprecatedPTR = true
							}
							break
						}
					}
				}
			}
		}
	}
	return count, usedDeprecatedPTR, details
}

// checkExposedAdminPorts probes dangerous management ports on PUBLIC IP (3389 RDP, 4040 Kerio Admin, 445 SMB)!
func checkExposedAdminPorts(publicIP string) (openPorts []string) {
	if !isGloballyRoutableIPv4(publicIP) {
		return nil
	}
	targets := []struct {
		port  int
		label string
	}{
		{3389, "3389 (Windows RDP — удалённый рабочий стол открыт на весь интернет!)"},
		{4040, "4040 (Веб-админка Kerio Connect Administration открыта наружу!)"},
		{445, "445 (Windows SMB файловые шары открыты в интернет!)"},
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(port int, label string) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(publicIP, strconv.Itoa(port)), 1800*time.Millisecond)
			if err == nil {
				_ = c.Close()
				mu.Lock()
				openPorts = append(openPorts, label)
				mu.Unlock()
			}
		}(t.port, t.label)
	}
	wg.Wait()
	return openPorts
}

// checkLegacyTLS10or11 checks if obsolete insecure TLS 1.0 / 1.1 is still accepted on port 465 or 443.
func checkLegacyTLSAccepted(targetHost, sniHost string, port int) (acceptsLegacy bool, negotiatedVer string) {
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, strconv.Itoa(port)), 2200*time.Millisecond)
	if err != nil {
		return false, ""
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	tc := tls.Client(raw, &tls.Config{
		ServerName:         sniHost,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
		InsecureSkipVerify: true,
	})
	if err := tc.Handshake(); err == nil {
		return true, tlsVersionName(tc.ConnectionState().Version)
	}
	return false, ""
}

// checkCAAAndMTASTSAndBIMI checks CAA, MTA-STS policy file, and BIMI avatar record.
func checkAdvancedDomainStandards(domain string) (caaRecords []string, caBlocksLE bool, mtaStsPolicy string, bimiRecords []string) {
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if ans, _, err := queryDoH(domain, "CAA"); err == nil {
			hasIssueRule := false
			allowsLE := false
			for _, a := range ans {
				if a.Type == 257 {
					caaRecords = append(caaRecords, a.Data)
					low := strings.ToLower(a.Data)
					if strings.Contains(low, "issue") {
						hasIssueRule = true
						if strings.Contains(low, "letsencrypt.org") {
							allowsLE = true
						}
					}
				}
			}
			if hasIssueRule && !allowsLE {
				caBlocksLE = true
			}
		}
	}()

	go func() {
		defer wg.Done()
		req, err := http.NewRequest(http.MethodGet, "https://mta-sts."+domain+"/.well-known/mta-sts.txt", nil)
		if err != nil {
			return
		}
		resp, err := sharedFastHTTPClient.Do(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(b), "version: STSv1") {
				mtaStsPolicy = strings.TrimSpace(string(b))
			}
		}
	}()

	go func() {
		defer wg.Done()
		if txts, err := lookupTXTQuick("default._bimi." + domain); err == nil {
			for _, t := range txts {
				if strings.Contains(strings.ToLower(t), "v=bimi1") {
					bimiRecords = append(bimiRecords, t)
				}
			}
		}
	}()

	wg.Wait()
	return
}

// probeRoleMailboxesAndCaps checks postmaster@ / abuse@ acceptance & EHLO capabilities without sending any email!
type smtpRoleAuditResult struct {
	Checked          bool
	PostmasterOK     bool
	PostmasterResp   string
	AbuseOK          bool
	AbuseResp        string
	MaxSizeBytes     int64
	Supports8BitMIME bool
	SupportsPipelining bool
	SupportsSMTPUTF8 bool
}

func inspectSMTPRolesAndCapabilities(targetAddr, mailDomain string) smtpRoleAuditResult {
	var out smtpRoleAuditResult
	conn, err := net.DialTimeout("tcp", targetAddr, 3200*time.Millisecond)
	if err != nil {
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	br := bufio.NewReader(conn)

	code, _, err := readSMTPReply(br)
	if err != nil || code != 220 {
		return out
	}
	_, _ = fmt.Fprintf(conn, "EHLO postmaster-check.kerio-audit.invalid\r\n")
	_, ehloText, err := readSMTPReply(br)
	if err != nil {
		return out
	}
	out.Checked = true

	for _, part := range strings.Split(ehloText, "|") {
		up := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "250-")))
		up = strings.TrimSpace(strings.TrimPrefix(up, "250 "))
		switch {
		case strings.HasPrefix(up, "SIZE"):
			fields := strings.Fields(up)
			if len(fields) >= 2 {
				if sz, perr := strconv.ParseInt(fields[1], 10, 64); perr == nil {
					out.MaxSizeBytes = sz
				}
			}
		case up == "8BITMIME":
			out.Supports8BitMIME = true
		case up == "PIPELINING":
			out.SupportsPipelining = true
		case up == "SMTPUTF8":
			out.SupportsSMTPUTF8 = true
		}
	}

	// Null reverse-path MAIL FROM:<> is exact RFC 5321 bounce/postmaster probe standard!
	_, _ = fmt.Fprintf(conn, "MAIL FROM:<>\r\n")
	mCode, _, mErr := readSMTPReply(br)
	if mErr == nil && mCode >= 200 && mCode < 300 {
		_, _ = fmt.Fprintf(conn, "RCPT TO:<postmaster@%s>\r\n", mailDomain)
		pCode, pResp, pErr := readSMTPReply(br)
		out.PostmasterResp = pResp
		if pErr == nil && pCode >= 200 && pCode < 300 {
			out.PostmasterOK = true
		}

		_, _ = fmt.Fprintf(conn, "RCPT TO:<abuse@%s>\r\n", mailDomain)
		aCode, aResp, aErr := readSMTPReply(br)
		out.AbuseResp = aResp
		if aErr == nil && aCode >= 200 && aCode < 300 {
			out.AbuseOK = true
		}
	}
	_, _ = fmt.Fprintf(conn, "RSET\r\n")
	_, _, _ = readSMTPReply(br)
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")
	return out
}

// ============================================================================
// BUILD COMPLETE DELIST CENTER + READY-TO-SEND LETTERS (8 PROVIDERS + ACTIVE RBLs)
// ============================================================================

func buildDelistCenter(
	mailDomain, mailHost, serverIP string,
	ptrOK, spfOK, dkimOK, relaySafe, postmasterOK bool,
	ipRBLs []RBLCheckEntry,
	domainRBLs []RBLCheckEntry,
	customBounce string,
) DelistCenterData {
	ipDisp := nonEmptyOr(serverIP, "[ВАШ_БЕЛЫЙ_IP]")
	hostDisp := nonEmptyOr(mailHost, "mail."+mailDomain)
	adminMail := "postmaster@" + mailDomain

	preChecks := []DelistPreCheckItem{
		{
			Label:  "1. Закрыт открытый релей (Open Relay) и проверена очередь сообщений Kerio",
			Passed: relaySafe,
			Detail: "В Kerio Connect → Статус → Очередь сообщений не должно быть чужих спам-писем, а релей разрешён только с авторизацией.",
		},
		{
			Label:  "2. Настроена обратная зона провайдера PTR (" + ipDisp + " → " + hostDisp + ")",
			Passed: ptrOK,
			Detail: "Spamhaus, Microsoft, Mail.ru и Barracuda автоматически ОТКЛОНЯЮТ заявку на разблокировку, если у IP нет корректной PTR!",
		},
		{
			Label:  "3. Активны записи аутентификации SPF и цифровая подпись DKIM",
			Passed: spfOK && dkimOK,
			Detail: "Доказывают почтовым гигантам, что сервер настроен по корпоративным стандартам RFC.",
		},
		{
			Label:  "4. Работают служебные адреса postmaster@" + mailDomain + " и abuse@" + mailDomain,
			Passed: postmasterOK,
			Detail: "На эти ящики службы антиспама присылают код подтверждения снятия блокировки и жалобы FBL!",
		},
	}

	readyCount := 0
	for _, pc := range preChecks {
		if pc.Passed {
			readyCount++
		}
	}
	readyAll := readyCount == len(preChecks)
	summary := "Сервер полностью готов к подаче заявок на исключение из чёрных списков!"
	if !readyAll {
		summary = fmt.Sprintf("Внимание: выполнено %d из %d условий перед разблокировкой! Сначала исправьте отмеченные красным пункты (особенно PTR и закрытие порта 25 для ПК офиса), иначе после снятия бана IP заблокируют повторно уже без права быстрой амнистии!", readyCount, len(preChecks))
	}

	mikrotikRule := fmt.Sprintf(
		`/ip firewall filter`+"\n"+
			`add chain=forward protocol=tcp dst-port=25 src-address=10.146.100.14 action=accept comment="Allow Kerio Mail Server outbound SMTP 25"`+"\n"+
			`add chain=forward protocol=tcp dst-port=25 in-interface-list=LAN action=drop log=yes log-prefix="INFECTED-PC-SMTP25:" comment="Block ALL infected office PCs from sending spam via NAT"`,
	)

	bounceSnippet := ""
	if strings.TrimSpace(customBounce) != "" {
		bounceSnippet = "\nDiagnostic / SMTP Error Log:\n" + strings.TrimSpace(customBounce) + "\n"
	}

	enTechSummary := fmt.Sprintf(
		"Hello Deliverability & Abuse Team,\n\n"+
			"We are requesting delisting / reputation review for our corporate mail server:\n"+
			"- Corporate Domain: %s\n"+
			"- Outbound SMTP Hostname (HELO/EHLO): %s\n"+
			"- Dedicated Static IPv4 Address: %s\n"+
			"- Forward & Reverse DNS (FCrDNS / PTR): %s <-> %s\n"+
			"- Authentication configured: Valid SPF (v=spf1), 2048-bit RSA DKIM (%s), DMARC policy (_dmarc.%s), TLS 1.2/1.3 encryption\n"+
			"- Postmaster / Abuse contact: %s (monitored 24/7)\n%s\n"+
			"Root cause investigation & permanent remediation completed:\n"+
			"1. Outbound TCP port 25 on our perimeter firewall is strictly restricted exclusively to our Kerio Connect mail server IP (all workstation LAN traffic on port 25 is blocked).\n"+
			"2. Open Relay is disabled; strict SMTP authentication + complex password policy + anti-hammering protection are enforced.\n"+
			"3. Outbound message queue has been audited — our server sends exclusively legitimate business correspondence to partners and clients.\n\n"+
			"Could you please review and remove %s (%s) from the blocklist? Thank you very much for your assistance!\n\n"+
			"Best regards,\nPostmaster / System Administrator (%s)\nEmail: %s",
		mailDomain, hostDisp, ipDisp, ipDisp, hostDisp, "mail._domainkey."+mailDomain, mailDomain, adminMail, bounceSnippet, ipDisp, mailDomain, mailDomain, adminMail,
	)

	ruTechSummaryMailRu := fmt.Sprintf(
		"Здравствуйте, уважаемая Служба поддержки Почты Mail.ru!\n\n"+
			"Просим проверить репутацию и снять фильтрацию / блокировку с нашего корпоративного почтового сервера:\n"+
			"• Почтовый домен организации: %s\n"+
			"• Имя SMTP-сервера (HELO / MX): %s\n"+
			"• Статический внешний IP-адрес: %s\n"+
			"• Обратная запись PTR (FCrDNS): %s -> %s\n"+
			"• Настроенные подписи безопасности: корректные записи SPF, цифровая подпись DKIM (mail._domainkey.%s), политика DMARC (_dmarc.%s), шифрование STARTTLS / TLS 1.2–1.3\n"+
			"• Контактный адрес администратора: %s\n%s\n"+
			"Сервер используется исключительно для деловой переписки сотрудников компании (счета, договоры, переписка с клиентами, массовые рекламные рассылки не ведутся).\n"+
			"На межсетевом экране исходящий порт TCP 25 закрыт для всех рабочих станций сети (разрешён строго только для почтового сервера Kerio Connect), открытый релей (Open Relay) закрыт, очередь сообщений чиста.\n\n"+
			"Просим разблокировать приём писем с IP %s (домен @%s). При необходимости готовы предоставить полные заголовки (RFC-822) тестового письма.\n\n"+
			"С уважением,\nСистемный администратор домена %s (%s)",
		mailDomain, hostDisp, ipDisp, ipDisp, hostDisp, mailDomain, mailDomain, adminMail, bounceSnippet, ipDisp, mailDomain, mailDomain, adminMail,
	)

	makeMailto := func(to, subj, body string) string {
		if to == "" {
			return ""
		}
		return fmt.Sprintf("mailto:%s?subject=%s&body=%s", to, url.PathEscape(subj), url.PathEscape(body))
	}

	var activeListings []DelistProviderAction
	for _, r := range ipRBLs {
		if !r.Listed {
			continue
		}
		subj := fmt.Sprintf("Delisting Request for Static Corporate Mail Server IP %s (%s)", ipDisp, hostDisp)
		activeListings = append(activeListings, DelistProviderAction{
			ID:          "rbl_" + r.Zone,
			Provider:    r.Provider + " (" + r.Zone + ")",
			TargetType:  "IP RBL (АКТИВНАЯ БЛОКИРОВКА!)",
			IsListedNow: true,
			ReturnCode:  r.ReturnCode,
			CodeMeaning: r.ReturnCode,
			PortalURL:   r.DelistURL,
			SubjectLine: subj,
			LetterBody:  enTechSummary,
			Steps: []string{
				"1. Убедитесь, что очередь сообщений в Kerio Connect чиста, на роутере закрыт исходящий порт 25 для офисных ПК, а PTR прописан.",
				"2. Нажмите кнопку «Открыть портал разблокировки» ниже — откроется официальная форма " + r.Provider + " для IP " + ipDisp + ".",
				"3. Вставьте в форму готовый английский технический отчёт из поля ниже и укажите корпоративный ящик " + adminMail + " для получения ссылки подтверждения.",
			},
		})
	}
	for _, d := range domainRBLs {
		if !d.Listed {
			continue
		}
		subj := fmt.Sprintf("Domain Delisting Request for %s (IP %s)", mailDomain, ipDisp)
		activeListings = append(activeListings, DelistProviderAction{
			ID:          "dbl_" + d.Zone,
			Provider:    d.Provider + " (" + d.Zone + ")",
			TargetType:  "Domain DBL (БЛОКИРОВКА ДОМЕНА!)",
			IsListedNow: true,
			ReturnCode:  d.ReturnCode,
			PortalURL:   d.DelistURL,
			SubjectLine: subj,
			LetterBody:  enTechSummary,
			Steps: []string{
				"1. Проверьте сайт на домене " + mailDomain + " на отсутствие чужих вредоносных редиректов/скриптов и проверьте SPF/DKIM/DMARC.",
				"2. Откройте портал " + d.Provider + " по кнопке ниже и отправьте готовый текст апелляции.",
			},
		})
	}

	// Build 8 complete always-available delist kits for ALL major private & public anti-spam systems!
	msSubj := fmt.Sprintf("Delist Request — Corporate Mail Server %s (%s) — Error 550 5.7.1 S3150/S3140", ipDisp, mailDomain)
	mailruSubj := fmt.Sprintf("Запрос на снятие блокировки с корпоративного сервера %s (IP %s)", mailDomain, ipDisp)
	yandexSubj := fmt.Sprintf("Ложное срабатывание спам-фильтра для корпоративного домена %s (IP %s)", mailDomain, ipDisp)
	ispSubj := fmt.Sprintf("Заявка по договору: настройка обратной записи PTR для IP %s -> %s", ipDisp, hostDisp)
	ispBody := fmt.Sprintf(
		"Здравствуйте!\n\n"+
			"Организация (домен %s), договор № [УКАЖИТЕ НОМЕР ДОГОВОРА].\n"+
			"Просим выполнить настройку для нашего статического внешнего IP-адреса %s:\n"+
			"1. Прописать в обратной зоне (rDNS) запись типа PTR:\n"+
			"   %s  PTR  %s.\n"+
			"   (Прямая запись %s -> %s в публичном DNS уже настроена.)\n"+
			"2. Проверить отсутствие ограничений оператора на входящий/исходящий порт TCP 25 (SMTP) для статического IP %s.\n\n"+
			"Контактный телефон / email системного администратора: %s.\nЗаранее благодарим за оперативную помощь!",
		mailDomain, ipDisp, ipDisp, hostDisp, hostDisp, ipDisp, ipDisp, adminMail,
	)

	majorProviders := []DelistProviderAction{
		{
			ID:           "microsoft",
			Provider:     "Microsoft Outlook / Hotmail / Live / Office 365 (ошибка 550 5.7.1 S3150 / S3140)",
			TargetType:   "Закрытая база Microsoft (НЕ видна в обычных RBL!)",
			PortalURL:    "https://sender.office.com/",
			SubjectLine:  msSubj,
			LetterBody:   enTechSummary + "\n\n[Доп. ссылка на ручную анкету Outlook.com Deliverability Support, если sender.office.com пишет 'not qualified for mitigation': https://olcsupport.office.com/ ]",
			ImportantNote: "Microsoft блокирует целые подсети белорусских и СНГ-провайдеров (код S3150) даже у идеально чистых серверов! Заявка подаётся БЕСПЛАТНО в 2 этапа: 1) Автоматический портал Microsoft Office 365 Anti-Spam IP Delist Portal (sender.office.com) — снимает бан с Office 365 за 15 минут; 2) Форма olcsupport.office.com — снимает бан с @outlook.com / @hotmail.com за 24 часа!",
			Steps: []string{
				"Шаг 1 (Для доставки клиентам на корпоративный Microsoft 365): Откройте https://sender.office.com/ , введите ваш email @" + mailDomain + " и заблокированный IP " + ipDisp + " → подтвердите ссылку из письма → разблокировка за 15–30 минут!",
				"Шаг 2 (Если не уходят письма на @outlook.com / @hotmail.com / @live.com — ошибка S3150): Откройте анкету https://olcsupport.office.com/ : • Issue Title: " + msSubj + " • Contact Email: ваш рабочий ящик на др. домене (напр. @gmail.com, чтобы ответ Microsoft точно дошёл!) • Domain from which you send: " + mailDomain + " • IP addresses: " + ipDisp + "/32 • Server type: Dedicated corporate Kerio Connect server • Paste description below!",
				"Шаг 3 (Бонус): Зарегистрируйте IP " + ipDisp + " в панели репутации Microsoft SNDS (https://sendersupport.olc.protection.outlook.com/snds/).",
			},
		},
		{
			ID:            "mailru",
			Provider:      "Mail.ru / BK.ru / List.ru / Inbox.ru / VK WorkMail (550 spam message rejected)",
			TargetType:    "Закрытая антиспам-база Почты Mail.ru",
			PortalURL:     "https://postmaster.mail.ru/",
			SupportEmail:  "abuse@corp.mail.ru",
			SubjectLine:   mailruSubj,
			LetterBody:    ruTechSummaryMailRu,
			MailtoLink:    makeMailto("abuse@corp.mail.ru", mailruSubj, ruTechSummaryMailRu),
			ImportantNote: "Если в ошибке отлупа от Mail.ru есть ссылка вида http://help.mail.ru/notspam-support/id?c=XXXX — ОБЯЗАТЕЛЬНО перейдите прямо по этой уникальной ссылке из лога Kerio (там уже зашит ID конкретного заблокированного письма — техподдержка Mail.ru снимает фильтр за 2–4 часа!).",
			Steps: []string{
				"Шаг 1: Добавьте домен " + mailDomain + " в бесплатный кабинет https://postmaster.mail.ru/ (подтверждается одной TXT-записью за 2 минуты) — там сразу видна точная причина попадания в Спам и репутация вашего IP!",
				"Шаг 2: Если в логе Kerio есть ссылка help.mail.ru/notspam-support/id?c=... — откройте её и вставьте готовый текст ниже. Либо нажмите кнопку «Открыть готовое письмо в почтовой программе (abuse@corp.mail.ru)»!",
			},
		},
		{
			ID:           "gmail",
			Provider:     "Google Gmail / Google Workspace (550-5.7.1 / 550-5.7.26 / попадание в папку «Спам»)",
			TargetType:   "Репутация домена и IP в Google Gmail",
			PortalURL:    "https://postmaster.google.com/",
			SubjectLine:  fmt.Sprintf("Gmail Sender Escalation — Legitimate Corporate Domain %s (%s)", mailDomain, ipDisp),
			LetterBody:   enTechSummary + "\n\n[Прямая форма обращения инженерам Gmail Sender Support: https://support.google.com/mail/contact/msgdelivery ]",
			ImportantNote: "У Google нет ручного белого списка без базовой тройки PTR + SPF + DKIM + DMARC! Но как только PTR, SPF, DKIM и DMARC горят зелёным ✅ на этой вкладке, отправка формы Google Sender Contact Form + добавление домена в Google Postmaster Tools восстанавливает репутацию в течение 24–72 часов!",
			Steps: []string{
				"Шаг 1: Убедитесь, что в проверке выше зелёным горят: Обратная запись PTR (" + ipDisp + " → " + hostDisp + "), SPF, DKIM и DMARC.",
				"Шаг 2: Добавьте домен " + mailDomain + " в https://postmaster.google.com/ (через проверочную TXT-запись в DNS) — Google сразу признаёт вас подтверждённым владельцем домена.",
				"Шаг 3: Попросите 3–5 реальных контрагентов на @gmail.com открыть ваше письмо в папке «Спам» и нажать кнопку «Не спам» + отправьте готовую заявку по форме https://support.google.com/mail/contact/msgdelivery .",
			},
		},
		{
			ID:           "yandex",
			Provider:     "Яндекс Почта / Яндекс 360 для бизнеса (554 5.7.1 Message rejected under suspicion of SPAM)",
			TargetType:   "Спамоборона Яндекса",
			PortalURL:    "https://yandex.ru/support/mail/web/spam/honest-mailers.html",
			SupportEmail: "abuse@yandex.ru",
			SubjectLine:  yandexSubj,
			LetterBody:   strings.ReplaceAll(ruTechSummaryMailRu, "Почты Mail.ru", "Яндекс Почты (Спамоборона)"),
			MailtoLink:   makeMailto("abuse@yandex.ru", yandexSubj, strings.ReplaceAll(ruTechSummaryMailRu, "Почты Mail.ru", "Яндекс Почты (Спамоборона)")),
			ImportantNote: "Яндекс крайне строго проверяет совпадение трёх имён: 1) PTR у провайдера == 2) A-запись == 3) Имя узла в приветствии SMTP HELO в Kerio Connect (" + hostDisp + ")!",
			Steps: []string{
				"Шаг 1: Проверьте, чтобы PTR, A-запись и баннер HELO в Kerio Connect совпадали буква в букву (" + hostDisp + ").",
				"Шаг 2: Откройте форму для добросовестных отправителей Яндекса по кнопке ниже (или отправьте готовое письмо) и приложите текст ошибки 554 из лога Kerio.",
			},
		},
		{
			ID:           "spamhaus",
			Provider:     "Spamhaus (ZEN: SBL / XBL / CBL / PBL и доменный DBL)",
			TargetType:   "Главная мировая спам-база №1 в мире",
			PortalURL:    "https://check.spamhaus.org/results/?query=" + url.QueryEscape(ipDisp),
			SubjectLine:  fmt.Sprintf("Spamhaus Removal Request — %s (%s)", ipDisp, hostDisp),
			LetterBody:   enTechSummary,
			ImportantNote: "ВАЖНЕЙШИЙ СЕКРЕТ SPAMHAUS: если код блокировки 127.0.0.4–127.0.0.7 (CBL/XBL), причина в 95% случаев — один из обычных рабочих ПК с Windows в вашем офисе подхватил вирус и шлёт спам наружу через общий роутер! Обязательно примените правило блокировки порта 25 для всех ПК офиса (кроме Kerio) из блока выше ПЕРЕД нажатием кнопки Remove на сайте Spamhaus!",
			Steps: []string{
				"Шаг 1: Закройте на роутере (MikroTik / Kerio Control) исходящий порт TCP 25 для всех локальных ПК, оставив разрешение ТОЛЬКО для IP сервера Kerio Connect!",
				"Шаг 2: Нажмите кнопку «Открыть портал разблокировки» (откроется сразу страница проверки вашего IP " + ipDisp + " на check.spamhaus.org).",
				"Шаг 3: Нажмите «Show details» → поставьте галочку подтверждения → вставьте готовый английский текст из поля ниже и укажите корпоративный ящик " + adminMail + " (Spamhaus не принимает бесплатные ящики @gmail/@mail.ru!). Удаление занимает 15–30 минут!",
			},
		},
		{
			ID:          "barracuda",
			Provider:    "Barracuda Central (b.barracudacentral.org — корп. шлюзы банков и госорганов)",
			TargetType:  "Мировая корпоративная RBL-база",
			PortalURL:   "https://www.barracudacentral.org/rbl/removal-request",
			SubjectLine: fmt.Sprintf("Barracuda BRBL Removal — %s (%s)", ipDisp, hostDisp),
			LetterBody:  enTechSummary,
			Steps: []string{
				"Шаг 1: Откройте https://www.barracudacentral.org/rbl/removal-request .",
				"Шаг 2: В поле «Email server IP address» вставьте " + ipDisp + ", в поле «Email address» — " + adminMail + ", а в поле «Reason for removal» скопируйте готовый английский отчёт ниже! Barracuda снимает блокировку обычно за 30–60 минут.",
			},
		},
		{
			ID:           "spamcop_sorbs",
			Provider:     "SpamCop / SORBS / Backscatterer / UCEPROTECT",
			TargetType:   "Автоматические спам-ловушки (Spamtraps)",
			PortalURL:    "https://www.spamcop.net/w3m?action=checkblock&ip=" + url.QueryEscape(ipDisp),
			SubjectLine:  fmt.Sprintf("RBL Delisting Request — %s (%s)", ipDisp, hostDisp),
			LetterBody:   enTechSummary,
			ImportantNote: "⚠️ НИКОГДА НЕ ПЛАТИТЕ ДЕНЬГИ СЕРВИСУ UCEPROTECT! Они требуют 90+ CHF за «срочное удаление», но ни Gmail, ни Mail.ru, ни Yandex, ни Microsoft НЕ используют платные уровни UCEPROTECT! В SpamCop и UCEPROTECT L1 IP удаляется АВТОМАТИЧЕСКИ И БЕСПЛАТНО через 24 часа — 7 дней после прекращения спама!",
			Steps: []string{
				"Для SpamCop: откройте ссылку ниже — если новых жалоб не было 24 часа, IP снимается автоматически (или кнопкой Delist).",
				"Для SORBS (http://www.sorbs.net/cgi-bin/support): зарегистрируйте бесплатный тикет и вставьте готовый английский текст ниже (если блокировка DUHL — приложите ответ провайдера, что IP " + ipDisp + " является статическим бизнес-адресом с PTR " + hostDisp + ").",
				"Для Backscatterer (https://ips.backscatterer.org/?ip=" + url.QueryEscape(ipDisp) + "): отключите автоответы «Вне офиса» на внешние домены в Kerio Connect — бесплатное автоудаление произойдёт через 4 недели (НИКОГДА не платите им за платное ускорение!).",
			},
		},
		{
			ID:            "isp_belarus",
			Provider:      "Заявка интернет-провайдеру (Белтелеком / A1 / МТС / Деловая сеть / Хостер VPS)",
			TargetType:    "Настройка обратной зоны PTR и открытие порта 25",
			PortalURL:     "https://beltelecom.by/",
			SupportEmail:  "support@belpak.by",
			SubjectLine:   ispSubj,
			LetterBody:    ispBody,
			MailtoLink:    makeMailto("support@belpak.by", ispSubj, ispBody),
			ImportantNote: "Для абонентов РУП «Белтелеком» (ByFly Бизнес / Пакет услуг): заявка на прописывание обратной записи PTR отправляется бесплатно на support@belpak.by (или региональный отдел техподдержки юрлиц / через личный кабинет) с указанием номера договора!",
			Steps: []string{
				"Впишите номер вашего договора в квадратные скобки в готовом тексте ниже.",
				"Нажмите кнопку «Открыть готовое письмо в почтовой программе» (или скопируйте текст и отправьте в техподдержку вашего провайдера).",
			},
		},
	}

	return DelistCenterData{
		ReadyForDelist:     readyAll,
		ReadinessSummary:   summary,
		PreChecks:          preChecks,
		MikrotikPort25Rule: mikrotikRule,
		ActiveListings:     activeListings,
		MajorProviders:     majorProviders,
	}
}

// ============================================================================
// SMART SMTP BOUNCE / KERIO LOG DECODER + CUSTOMIZED APPEAL BUILDER
// ============================================================================

func DecodeSMTPBounceAndBuildLetter(req BounceDecodeRequest) BounceDecodeResult {
	domain := cleanInputHost(req.MailDomain)
	if domain == "" {
		domain = "company.by"
	}
	host := cleanInputHost(req.MailHost)
	if host == "" {
		host = "mail." + domain
	}
	ip := strings.TrimSpace(req.ServerIP)
	if ip == "" {
		ip = DetectPublicIPFast()
	}

	dc := buildDelistCenter(domain, host, ip, true, true, true, true, true, nil, nil, req.BounceText)
	low := strings.ToLower(req.BounceText)

	findByID := func(id string) DelistProviderAction {
		for _, p := range dc.MajorProviders {
			if p.ID == id {
				return p
			}
		}
		return dc.MajorProviders[0]
	}

	switch {
	case strings.Contains(low, "spamhaus") || strings.Contains(low, "sbl") || strings.Contains(low, "xbl") || strings.Contains(low, "pbl") || strings.Contains(low, "cbl.abuseat"):
		return BounceDecodeResult{
			DetectedProviderID: "spamhaus",
			DetectedTitle:      "🚨 Обнаружена блокировка базой Spamhaus (ZEN / SBL / XBL / CBL / PBL)!",
			Explanation:        "Принимающий сервер отклонил ваше письмо со ссылкой на Spamhaus. Проверьте, не отправлял ли вирус с одного из офисных ПК спам наружу по порту 25 (самая частая причина кода XBL/CBL!), примените правило блокировки порта 25 на роутере и подайте бесплатную заявку на check.spamhaus.org с готовым текстом ниже!",
			RecommendedAction:  findByID("spamhaus"),
		}
	case strings.Contains(low, "outlook") || strings.Contains(low, "hotmail") || strings.Contains(low, "protection.outlook.com") || strings.Contains(low, "s3150") || strings.Contains(low, "s3140") || strings.Contains(low, "live.com"):
		return BounceDecodeResult{
			DetectedProviderID: "microsoft",
			DetectedTitle:      "🇬🇧 Обнаружена внутренняя блокировка подсети в Microsoft (Outlook / Hotmail / Office 365 — код S3150/S3140)!",
			Explanation:        "Ваш сервер не обязательно рассылал спам — Microsoft часто превентивно блокирует целые блоки IP-адресов провайдеров! Снимается БЕСПЛАТНО через портал sender.office.com (для Microsoft 365) и анкету olcsupport.office.com (для @outlook.com / @hotmail.com) — готовый английский текст с вашим логом ошибки уже сформирован ниже!",
			RecommendedAction:  findByID("microsoft"),
		}
	case strings.Contains(low, "mail.ru") || strings.Contains(low, "mxs.mail.ru") || strings.Contains(low, "notspam-support"):
		return BounceDecodeResult{
			DetectedProviderID: "mailru",
			DetectedTitle:      "🇷🇺 Обнаружена фильтрация Почты Mail.ru / VK WorkMail!",
			Explanation:        "Обратите внимание: если внутри вставленного текста ошибки есть ссылка вида http://help.mail.ru/notspam-support/id?c=... — откройте её прямо в браузере и вставьте готовое письмо ниже! Также обязательно добавьте домен в postmaster.mail.ru.",
			RecommendedAction:  findByID("mailru"),
		}
	case strings.Contains(low, "gmail") || strings.Contains(low, "google.com") || strings.Contains(low, "gsmtp") || strings.Contains(low, "5.7.26") || strings.Contains(low, "5.7.28"):
		return BounceDecodeResult{
			DetectedProviderID: "gmail",
			DetectedTitle:      "🇺🇸 Обнаружена блокировка политикой Google Gmail (550-5.7.26 / 550-5.7.1)!",
			Explanation:        "Код 550-5.7.26 означает, что письмо не прошло обязательную проверку аутентификации Google (отсутствует или не сходится PTR / SPF / DKIM / DMARC). Сначала убедитесь, что все 4 пункта горят зелёным в нашей проверке, затем добавьте домен в Google Postmaster Tools и отправьте форму ниже!",
			RecommendedAction:  findByID("gmail"),
		}
	case strings.Contains(low, "yandex") || strings.Contains(low, "suspicion of spam"):
		return BounceDecodeResult{
			DetectedProviderID: "yandex",
			DetectedTitle:      "🇷🇺 Обнаружено срабатывание Спамобороны Яндекса!",
			Explanation:        "Проверьте совпадение PTR, A-записи и имени узла SMTP HELO в Kerio Connect, после чего отправьте готовое обращение в поддержку Яндекс Почты ниже.",
			RecommendedAction:  findByID("yandex"),
		}
	case strings.Contains(low, "barracuda"):
		return BounceDecodeResult{
			DetectedProviderID: "barracuda",
			DetectedTitle:      "🛡️ Обнаружена блокировка шлюзом Barracuda Central (BRBL)!",
			Explanation:        "Подайте бесплатную заявку на странице barracudacentral.org/rbl/removal-request с готовым текстом ниже — разблокировка занимает около 30–60 минут.",
			RecommendedAction:  findByID("barracuda"),
		}
	case strings.Contains(low, "reverse") || strings.Contains(low, "rdns") || strings.Contains(low, "ptr") || strings.Contains(low, "cannot find your hostname") || strings.Contains(low, "client host rejected: cannot find"):
		return BounceDecodeResult{
			DetectedProviderID: "isp_belarus",
			DetectedTitle:      "📡 Причина отказа — у вашего внешнего IP не прописана обратная запись PTR у интернет-провайдера!",
			Explanation:        "Это НЕ спам-лист, а отказ из-за пустой обратной зоны (rDNS / PTR) у вашего интернет-провайдера! Отправьте готовое письмо ниже в техподдержку вашего провайдера (Белтелеком / A1 / МТС) — сразу после добавления PTR письма пойдут без ошибок!",
			RecommendedAction:  findByID("isp_belarus"),
		}
	default:
		return BounceDecodeResult{
			DetectedProviderID: "spamhaus",
			DetectedTitle:      "📋 Сформирован универсальный технический пакет разблокировки (RU + EN) с вашим логом ошибки!",
			Explanation:        "Ваш текст ошибки автоматически включён в готовое обращение администратора ниже. Выберите нужного получателя (Microsoft, Mail.ru, Gmail, Yandex, Spamhaus, Barracuda или интернет-провайдера) или скопируйте готовое письмо!",
			RecommendedAction:  findByID("microsoft"),
		}
	}
}

// ============================================================================
// LIVE AUTHENTICATED TEST EMAIL SENDER (WITH FULL STEP-BY-STEP SMTP TRANSCRIPT)
// ============================================================================

func SendDiagnosticTestEmail(req TestEmailRequest) (*TestEmailResult, error) {
	t0 := time.Now()
	res := &TestEmailResult{}
	logStep := func(s string) {
		res.SessionLog = append(res.SessionLog, fmt.Sprintf("[+%dms] %s", time.Since(t0).Milliseconds(), s))
	}

	host := cleanInputHost(req.SMTPHost)
	if host == "" {
		return nil, fmt.Errorf("укажите адрес SMTP-сервера (например, mail.leend.by или 10.146.100.14)")
	}
	port := req.SMTPPort
	if port <= 0 {
		if req.Security == "ssl" {
			port = 465
		} else {
			port = 587
		}
	}
	from := strings.TrimSpace(req.FromEmail)
	to := strings.TrimSpace(req.ToEmail)
	if from == "" || !strings.Contains(from, "@") {
		return nil, fmt.Errorf("укажите корректный email отправителя (например, admin@leend.by)")
	}
	if to == "" || !strings.Contains(to, "@") {
		return nil, fmt.Errorf("укажите email получателя для доставки тестового письма (например, ваш @gmail.com или адрес с mail-tester.com)")
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	logStep("Подключение к SMTP-серверу " + addr + " ...")

	var conn net.Conn
	var err error
	if req.Security == "ssl" || port == 465 {
		raw, derr := net.DialTimeout("tcp", addr, 6*time.Second)
		if derr != nil {
			return nil, fmt.Errorf("не удалось подключиться к %s: %w", addr, derr)
		}
		tc := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if herr := tc.Handshake(); herr != nil {
			raw.Close()
			return nil, fmt.Errorf("ошибка SSL/TLS на порту %d: %w", port, herr)
		}
		st := tc.ConnectionState()
		res.TLSInfo = fmt.Sprintf("%s (%s)", tlsVersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
		logStep("Установлено прямое шифрованное SSL/TLS соединение: " + res.TLSInfo)
		conn = tc
	} else {
		conn, err = net.DialTimeout("tcp", addr, 6*time.Second)
		if err != nil {
			return nil, fmt.Errorf("не удалось подключиться к %s: %w", addr, err)
		}
		logStep("TCP-соединение установлено успешно")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	br := bufio.NewReader(conn)
	code, banner, err := readSMTPReply(br)
	if err != nil || code != 220 {
		return nil, fmt.Errorf("неожиданный ответ приветствия SMTP (%d): %s (%v)", code, banner, err)
	}
	logStep("220 Баннер сервера: " + banner)

	fromDomain := strings.SplitN(from, "@", 2)[1]
	_, _ = fmt.Fprintf(conn, "EHLO mail.%s\r\n", fromDomain)
	eCode, ehloResp, err := readSMTPReply(br)
	if err != nil || eCode >= 400 {
		return nil, fmt.Errorf("ошибка EHLO (%d): %s", eCode, ehloResp)
	}
	logStep("EHLO успешно принят: " + ehloResp)

	if req.Security != "ssl" && port != 465 && req.Security != "plain" && strings.Contains(strings.ToUpper(ehloResp), "STARTTLS") {
		logStep("Переход на защищённый канал STARTTLS...")
		_, _ = fmt.Fprintf(conn, "STARTTLS\r\n")
		stCode, stResp, stErr := readSMTPReply(br)
		if stErr != nil || stCode != 220 {
			return nil, fmt.Errorf("сервер отклонил STARTTLS (%d): %s", stCode, stResp)
		}
		tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if herr := tc.Handshake(); herr != nil {
			return nil, fmt.Errorf("ошибка рукопожатия STARTTLS: %w", herr)
		}
		st := tc.ConnectionState()
		res.TLSInfo = fmt.Sprintf("%s (%s)", tlsVersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
		logStep("STARTTLS успешно согласован: " + res.TLSInfo)
		conn = tc
		br = bufio.NewReader(conn)
		_, _ = fmt.Fprintf(conn, "EHLO mail.%s\r\n", fromDomain)
		_, _, _ = readSMTPReply(br)
	}

	if strings.TrimSpace(req.Username) != "" {
		logStep("Выполнение SMTP AUTH PLAIN для пользователя " + req.Username + " ...")
		authPayload := base64.StdEncoding.EncodeToString([]byte("\x00" + strings.TrimSpace(req.Username) + "\x00" + req.Password))
		_, _ = fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", authPayload)
		aCode, aResp, aErr := readSMTPReply(br)
		if aErr != nil || aCode != 235 {
			// Fallback to AUTH LOGIN (used by older Kerio configs)
			logStep("AUTH PLAIN вернул " + strconv.Itoa(aCode) + ", пробуем AUTH LOGIN...")
			_, _ = fmt.Fprintf(conn, "AUTH LOGIN\r\n")
			lCode, _, _ := readSMTPReply(br)
			if lCode == 334 {
				_, _ = fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(req.Username))))
				uCode, _, _ := readSMTPReply(br)
				if uCode == 334 {
					_, _ = fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(req.Password)))
					aCode, aResp, aErr = readSMTPReply(br)
				}
			}
			if aErr != nil || aCode != 235 {
				return nil, fmt.Errorf("ошибка авторизации SMTP (%d): %s — проверьте логин и пароль ящика!", aCode, aResp)
			}
		}
		logStep("235 Авторизация SMTP прошла успешно!")
	}

	_, _ = fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", from)
	mCode, mResp, err := readSMTPReply(br)
	if err != nil || mCode >= 400 {
		return nil, fmt.Errorf("сервер отклонил отправителя MAIL FROM (%d): %s", mCode, mResp)
	}
	logStep("MAIL FROM принят: " + mResp)

	_, _ = fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", to)
	rCode, rResp, err := readSMTPReply(br)
	if err != nil || rCode >= 400 {
		return nil, fmt.Errorf("сервер отклонил получателя RCPT TO (%d): %s", rCode, rResp)
	}
	logStep("RCPT TO принят: " + rResp)

	_, _ = fmt.Fprintf(conn, "DATA\r\n")
	dCode, dResp, err := readSMTPReply(br)
	if err != nil || dCode != 354 {
		return nil, fmt.Errorf("ошибка команды DATA (%d): %s", dCode, dResp)
	}

	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	msgID := fmt.Sprintf("<%d.%s@%s>", time.Now().Unix(), hex.EncodeToString(rnd[:]), fromDomain)
	nowRFC := time.Now().Format(time.RFC1123Z)

	subjText := fmt.Sprintf("Проверка доставляемости почтового сервера %s (%s)", fromDomain, time.Now().Format("02.01.2006 15:04:05"))
	encodedSubj := "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(subjText)) + "?="

	bodyPlain := fmt.Sprintf(
		"Здравствуйте!\r\n\r\n"+
			"Это контрольное диагностическое письмо отправлено с корпоративного почтового сервера домена %s для проверки корректности доставки, цифровой подписи DKIM, записи SPF, политики DMARC и шифрования TLS.\r\n\r\n"+
			"Параметры отправки:\r\n"+
			"- Отправитель: %s\r\n"+
			"- Получатель: %s\r\n"+
			"- SMTP-сервер: %s:%d\r\n"+
			"- Шифрование сессии: %s\r\n"+
			"- Message-ID: %s\r\n"+
			"- Время отправки: %s\r\n\r\n"+
			"Если вы открыли это письмо в Gmail / Mail.ru / Yandex — откройте «Показать оригинал / Служебные заголовки» и убедитесь, что строки SPF, DKIM и DMARC имеют статус PASS!\r\n",
		fromDomain, from, to, host, port, nonEmptyOr(res.TLSInfo, "без шифрования"), msgID, nowRFC,
	)

	msg := strings.Join([]string{
		"From: <" + from + ">",
		"To: <" + to + ">",
		"Subject: " + encodedSubj,
		"Date: " + nowRFC,
		"Message-ID: " + msgID,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: base64",
		"",
		base64.StdEncoding.EncodeToString([]byte(bodyPlain)),
	}, "\r\n")

	_, _ = fmt.Fprintf(conn, "%s\r\n.\r\n", msg)
	qCode, qResp, err := readSMTPReply(br)
	if err != nil || qCode >= 400 {
		return nil, fmt.Errorf("сервер отклонил тело письма (%d): %s", qCode, qResp)
	}
	logStep("250 Письмо успешно поставлено в очередь отправки Kerio Connect: " + qResp)
	_, _ = fmt.Fprintf(conn, "QUIT\r\n")

	res.Success = true
	res.DurationMs = time.Since(t0).Milliseconds()
	res.ServerResp = qResp
	return res, nil
}
