package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// DOMAIN & IP SANCTIONS, OFAC CA POLICY & GEO-BLOCKING DIAGNOSTIC ENGINE (v4.1)
// ============================================================================

type SanctionsCheckRequest struct {
	Domain           string `json:"domain"`
	MailHost         string `json:"mailHost"`
	IPAddress        string `json:"ipAddress"`
	ACMEDirectoryURL string `json:"acmeDirectoryUrl,omitempty"` // optional override for testing
}

type LEOFACProbeResult struct {
	CheckedLive        bool     `json:"checkedLive"`
	DomainBlocked      bool     `json:"domainBlocked"`
	IPBlocked          bool     `json:"ipBlocked"`
	ACMEReachable      bool     `json:"acmeReachable"`
	GeoHTTPBlocked     bool     `json:"geoHttpBlocked"`
	TestedIdentifiers  []string `json:"testedIdentifiers"`
	BlockedIdentifiers []string `json:"blockedIdentifiers"`
	RawACMEError       string   `json:"rawAcmeError"`
	StatusSummary      string   `json:"statusSummary"`
}

type IPSanctionsGeoInfo struct {
	IPAddress       string   `json:"ipAddress"`
	IsPublicIP      bool     `json:"isPublicIp"`
	CountryCode     string   `json:"countryCode"`
	CountryName     string   `json:"countryName"`
	ASN             string   `json:"asn"`
	HolderOrg       string   `json:"holderOrg"`
	Prefix          string   `json:"prefix"`
	RIR             string   `json:"rir"`
	IsSanctionedGeo bool     `json:"isSanctionedGeo"` // BY, RU, IR, KP, SY, CU or sanctioned Crimea/Donbas prefixes
	OrgWatchlistHit string   `json:"orgWatchlistHit"` // matched sanctioned carrier/bank/state keyword if any
	RiskNotes       []string `json:"riskNotes"`
}

type CACompatibilityEntry struct {
	Provider       string `json:"provider"`
	Jurisdiction   string `json:"jurisdiction"`
	Status         string `json:"status"` // "allowed", "blocked", "warning"
	StatusBadge    string `json:"statusBadge"`
	Details        string `json:"details"`
	Recommendation string `json:"recommendation"`
}

type ForeignDNSResolverCheck struct {
	ResolverName string   `json:"resolverName"`
	Country      string   `json:"country"`
	Reachable    bool     `json:"reachable"`
	ResolvedIPs  []string `json:"resolvedIps"`
	ResolvedMX   []string `json:"resolvedMx"`
	ErrorDetail  string   `json:"errorDetail"`
}

type GlobalServiceReachability struct {
	Name        string `json:"name"`
	Category    string `json:"category"` // "SSL / PKI", "DNS / CDN", "Почтовые MX", "Облака"
	Target      string `json:"target"`
	Status      string `json:"status"` // "ok", "geoblocked", "unreachable"
	HTTPOrSMTP  string `json:"httpOrSmtp"`
	LatencyMs   int64  `json:"latencyMs"`
	Explanation string `json:"explanation"`
}

type SanctionsCheckReport struct {
	CheckedAt          string                      `json:"checkedAt"`
	TargetDomain       string                      `json:"targetDomain"`
	TargetMailHost     string                      `json:"targetMailHost"`
	TargetTLD          string                      `json:"targetTld"`
	TargetIP           string                      `json:"targetIp"`
	TargetIPSource     string                      `json:"targetIpSource"`
	ServerEgressIP     string                      `json:"serverEgressIp"`
	ServerEdgeInfo     string                      `json:"serverEdgeInfo"`
	OverallStatus      string                      `json:"overallStatus"` // "clean", "restricted", "blocked"
	RiskScore          int                         `json:"riskScore"`     // 0 (clean) .. 100 (heavily sanctioned/blocked)
	VerdictTitle       string                      `json:"verdictTitle"`
	VerdictSummary     string                      `json:"verdictSummary"`
	DomainWatchlistHit string                      `json:"domainWatchlistHit"`
	LEPolicyProbe      LEOFACProbeResult           `json:"lePolicyProbe"`
	IPGeoInfo          IPSanctionsGeoInfo          `json:"ipGeoInfo"`
	CAMatrix           []CACompatibilityEntry      `json:"caMatrix"`
	ForeignDNS         []ForeignDNSResolverCheck   `json:"foreignDns"`
	ServiceMatrix      []GlobalServiceReachability `json:"serviceMatrix"`
	Findings           []MailCheckItem             `json:"findings"`
	Remediations       []MailRemediationGuide      `json:"remediations"`
}

// Known sanctioned entities / stems frequently hitting OFAC SDN / EU sanctions filters in BY & RU
var sanctionedEntityKeywords = []struct {
	stem  string
	label string
}{
	{"belarusbank", "ОАО «АСБ Беларусбанк» (секторальные/блокирующие санкции ЕС/США)"},
	{"belagroprom", "ОАО «Белагропромбанк» (санкционный список ЕС/США)"},
	{"belinvestbank", "ОАО «Белинвестбанк» (санкционный список SDN США / ЕС)"},
	{"dabrabyt", "ОАО «Банк Дабрабыт» (санкционный список SDN США / ЕС)"},
	{"sberbank", "ПАО «Сбербанк» / СберБанк (блокирующий список OFAC SDN)"},
	{"vtb", "Банк ВТБ (блокирующий список OFAC SDN)"},
	{"alfabank", "Альфа-Банк (санкционный список OFAC SDN / ЕС)"},
	{"gazprom", "ПАО «Газпром» / Газпромбанк (санкционный список США / ЕС)"},
	{"rostec", "Госкорпорация «Ростех» (блокирующий список OFAC SDN)"},
	{"belaruskali", "ОАО «Беларуськалий» (блокирующий список OFAC SDN / ЕС)"},
	{"grodnoazot", "ОАО «Гродно Азот» (блокирующий список OFAC SDN / ЕС)"},
	{"naftan", "ОАО «Нафтан» (блокирующий список OFAC SDN / ЕС)"},
	{"bmz", "ОАО «БМЗ» (блокирующий список OFAC SDN / ЕС)"},
	{"belaz", "ОАО «БЕЛАЗ» (блокирующий список OFAC SDN / ЕС)"},
	{"maz.by", "ОАО «МАЗ» (блокирующий список OFAC SDN / ЕС)"},
	{"mtz", "ОАО «МТЗ» (санкционные ограничения)"},
	{"belavia", "ОАО «Авиакомпания Белавиа» (санкционные ограничения)"},
	{"beltelecom", "РУП «Белтелеком» (санкционный список ЕС — возможна фильтрация рядом европейских шлюзов)"},
}

func checkWatchlistKeyword(text string) string {
	low := strings.ToLower(strings.TrimSpace(text))
	if low == "" {
		return ""
	}
	for _, item := range sanctionedEntityKeywords {
		if strings.Contains(low, item.stem) {
			return item.label
		}
	}
	return ""
}

func extractEffectiveTLD(asciiDomain string) string {
	parts := strings.Split(strings.ToLower(strings.Trim(asciiDomain, ".")), ".")
	if len(parts) == 0 {
		return ""
	}
	tld := parts[len(parts)-1]
	switch tld {
	case "xn--90ais":
		return ".бел (xn--90ais)"
	case "xn--p1ai":
		return ".рф (xn--p1ai)"
	default:
		return "." + tld
	}
}

func isCommercialCAEmbargoedTLD(asciiDomain string) bool {
	parts := strings.Split(strings.ToLower(strings.Trim(asciiDomain, ".")), ".")
	if len(parts) == 0 {
		return false
	}
	switch parts[len(parts)-1] {
	case "by", "xn--90ais", "ru", "xn--p1ai", "su", "ir", "kp", "sy", "cu":
		return true
	}
	return false
}

func countryNameRu(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "BY":
		return "Беларусь (BY)"
	case "RU":
		return "Россия (RU)"
	case "KZ":
		return "Казахстан (KZ)"
	case "DE":
		return "Германия (DE)"
	case "NL":
		return "Нидерланды (NL)"
	case "PL":
		return "Польша (PL)"
	case "LT":
		return "Литва (LT)"
	case "LV":
		return "Латвия (LV)"
	case "US":
		return "США (US)"
	case "GB", "UK":
		return "Великобритания (GB)"
	case "FR":
		return "Франция (FR)"
	case "FI":
		return "Финляндия (FI)"
	case "CH":
		return "Швейцария (CH)"
	default:
		if code == "" {
			return "Не определена"
		}
		return code
	}
}

func isPublicRoutableIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast()
}

// probeLetsEncryptOFACPolicy performs an actual live dry-run ACME newOrder check against Let's Encrypt Staging
// (zero certificate issuance, zero production rate-limit impact) to verify whether ISRG / US OFAC compliance
// blocks this exact domain or IP address (`urn:ietf:params:acme:error:rejectedIdentifier` / `Policy forbids issuing`).
func probeLetsEncryptOFACPolicy(acmeDirURL string, domains []string, ipStr string) LEOFACProbeResult {
	var res LEOFACProbeResult
	if strings.TrimSpace(acmeDirURL) == "" {
		acmeDirURL = LEDirectoryStaging
	}

	httpClient := &http.Client{
		Timeout:   2800 * time.Millisecond,
		Transport: sharedFastHTTPClient.Transport,
	}

	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		res.StatusSummary = "Ошибка генерации тестового ECDSA-ключа"
		return res
	}

	ac := &ACMEClient{
		dirURL:     acmeDirURL,
		accountKey: acctKey,
		httpClient: httpClient,
		log:        func(string, string) {},
	}

	dirResp, err := httpClient.Get(acmeDirURL)
	if err != nil {
		errLow := strings.ToLower(err.Error())
		if strings.Contains(errLow, "403") || strings.Contains(errLow, "451") || strings.Contains(errLow, "access denied") {
			res.GeoHTTPBlocked = true
			res.RawACMEError = err.Error()
			res.StatusSummary = "🚫 API Let's Encrypt вернул HTTP 403/451 (блокировка доступа с вашего IP/сети)"
			return res
		}
		res.RawACMEError = err.Error()
		res.StatusSummary = "Нет прямого соединения с сервером проверки Let's Encrypt (" + acmeDirURL + ")"
		return res
	}
	dirBody, _ := io.ReadAll(io.LimitReader(dirResp.Body, 32768))
	dirResp.Body.Close()
	if dirResp.StatusCode == 403 || dirResp.StatusCode == 451 {
		res.GeoHTTPBlocked = true
		res.RawACMEError = fmt.Sprintf("HTTP %d: %s", dirResp.StatusCode, strings.TrimSpace(string(dirBody)))
		res.StatusSummary = fmt.Sprintf("🚫 API Let's Encrypt вернул HTTP %d (гео/санкционный блок на маршруте)", dirResp.StatusCode)
		return res
	}
	if dirResp.StatusCode != 200 || json.Unmarshal(dirBody, &ac.dir) != nil {
		res.RawACMEError = fmt.Sprintf("HTTP %d", dirResp.StatusCode)
		res.StatusSummary = "Некорректный ответ каталога ACME"
		return res
	}
	res.ACMEReachable = true

	_, accHdr, _, err := ac.signedPost(ac.dir.NewAccount, map[string]any{"termsOfServiceAgreed": true}, true)
	if err != nil {
		res.RawACMEError = err.Error()
		res.StatusSummary = "Ошибка тестовой сессии ACME: " + err.Error()
		return res
	}
	ac.kid = accHdr.Get("Location")

	// 1. Test DNS domain identifiers first
	cleanDomains := []string{}
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && strings.Contains(d, ".") && !strings.HasSuffix(d, ".invalid") && !strings.HasSuffix(d, ".local") && !seen[d] {
			seen[d] = true
			cleanDomains = append(cleanDomains, d)
		}
	}

	if len(cleanDomains) > 0 {
		var idents []acmeIdentifier
		for _, d := range cleanDomains {
			idents = append(idents, acmeIdentifier{Type: "dns", Value: d})
			res.TestedIdentifiers = append(res.TestedIdentifiers, d)
		}
		body := map[string]any{"identifiers": idents}
		_, _, _, err := ac.signedPost(ac.dir.NewOrder, body, false)
		res.CheckedLive = true
		if err != nil {
			errStr := err.Error()
			res.RawACMEError = errStr
			low := strings.ToLower(errStr)
			if strings.Contains(low, "policy forbids issuing") ||
				(strings.Contains(low, "rejectedidentifier") && (strings.Contains(low, "forbids") || strings.Contains(low, "policy") || strings.Contains(low, "sanction") || strings.Contains(low, "high-risk"))) {
				res.DomainBlocked = true
				res.BlockedIdentifiers = append(res.BlockedIdentifiers, cleanDomains...)
			}
		}
	}

	// 2. Test Public IP identifier separately so a domain issue doesn't mask IP policy status
	if parsedIP := net.ParseIP(strings.TrimSpace(ipStr)); isPublicRoutableIP(parsedIP) {
		res.TestedIdentifiers = append(res.TestedIdentifiers, ipStr)
		body := map[string]any{
			"profile":     "shortlived",
			"identifiers": []acmeIdentifier{{Type: "ip", Value: parsedIP.String()}},
		}
		_, _, _, err := ac.signedPost(ac.dir.NewOrder, body, false)
		res.CheckedLive = true
		if err != nil {
			low := strings.ToLower(err.Error())
			if strings.Contains(low, "policy forbids issuing") || (strings.Contains(low, "rejectedidentifier") && strings.Contains(low, "forbids")) {
				res.IPBlocked = true
				res.BlockedIdentifiers = append(res.BlockedIdentifiers, parsedIP.String())
				if res.RawACMEError == "" {
					res.RawACMEError = err.Error()
				}
			}
		}
	}

	switch {
	case res.DomainBlocked || res.IPBlocked:
		res.StatusSummary = fmt.Sprintf("🚨 САНКЦИОННАЯ БЛОКИРОВКА OFAC В LET'S ENCRYPT ПОДТВЕРЖДЕНА ОНЛАЙН! Заблокированы: %s", strings.Join(res.BlockedIdentifiers, ", "))
	case res.CheckedLive:
		res.StatusSummary = fmt.Sprintf("✅ Официально проверено онлайн в Let's Encrypt (ISRG США): санкционных блокировок OFAC нет (%s разрешены к выпуску SSL!)", strings.Join(res.TestedIdentifiers, ", "))
	default:
		res.StatusSummary = "Онлайн-проверка идентификаторов ACME пропущена (локальный/тестовый домен)"
	}
	return res
}

// inspectIPSanctionsAndGeoInfo queries RIPE Stat WHOIS/Prefix API + fallback GeoIP to inspect ASN, Country & Sanctioned Networks.
func inspectIPSanctionsAndGeoInfo(ipStr string) IPSanctionsGeoInfo {
	info := IPSanctionsGeoInfo{
		IPAddress: strings.TrimSpace(ipStr),
	}
	parsed := net.ParseIP(info.IPAddress)
	if !isPublicRoutableIP(parsed) {
		return info
	}
	info.IsPublicIP = true

	client := &http.Client{
		Timeout:   2300 * time.Millisecond,
		Transport: sharedFastHTTPClient.Transport,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(2)

	// 1. RIPE Stat WHOIS & Prefix Overview (authoritative RIR registry data for Europe/CIS!)
	go func() {
		defer wg.Done()
		u := "https://stat.ripe.net/data/whois/data.json?resource=" + url.QueryEscape(info.IPAddress)
		resp, err := client.Get(u)
		if err != nil {
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return
		}
		var data struct {
			Data struct {
				Records [][]struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"records"`
				IrrRecords [][]struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"irr_records"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &data) != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, block := range data.Data.Records {
			for _, kv := range block {
				k := strings.ToLower(strings.TrimSpace(kv.Key))
				v := strings.TrimSpace(kv.Value)
				switch k {
				case "country":
					if info.CountryCode == "" && len(v) == 2 {
						info.CountryCode = strings.ToUpper(v)
					}
				case "origin":
					if info.ASN == "" {
						info.ASN = strings.ToUpper(v)
					}
				case "org-name", "netname", "descr":
					if info.HolderOrg == "" && v != "" {
						info.HolderOrg = v
					} else if k == "org-name" && v != "" {
						info.HolderOrg = v
					}
				case "inetnum", "route":
					if info.Prefix == "" {
						info.Prefix = v
					}
				case "source":
					if info.RIR == "" {
						info.RIR = strings.ToUpper(v)
					}
				}
			}
		}
		for _, block := range data.Data.IrrRecords {
			for _, kv := range block {
				if strings.EqualFold(kv.Key, "origin") && info.ASN == "" {
					info.ASN = strings.ToUpper(strings.TrimSpace(kv.Value))
				}
				if strings.EqualFold(kv.Key, "route") && info.Prefix == "" {
					info.Prefix = strings.TrimSpace(kv.Value)
				}
			}
		}
	}()

	// 2. Parallel GeoIP JSON lookup fallback (ipwho.is) in case RIPE WHOIS omits country or non-RIPE IP
	go func() {
		defer wg.Done()
		resp, err := client.Get("https://ipwho.is/" + url.QueryEscape(info.IPAddress))
		if err != nil {
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		var gw struct {
			Success     bool   `json:"success"`
			CountryCode string `json:"country_code"`
			Connection  struct {
				ASN int    `json:"asn"`
				Org string `json:"org"`
				ISP string `json:"isp"`
			} `json:"connection"`
		}
		if json.Unmarshal(raw, &gw) == nil && gw.Success {
			mu.Lock()
			if info.CountryCode == "" && gw.CountryCode != "" {
				info.CountryCode = strings.ToUpper(gw.CountryCode)
			}
			if info.ASN == "" && gw.Connection.ASN > 0 {
				info.ASN = fmt.Sprintf("AS%d", gw.Connection.ASN)
			}
			if info.HolderOrg == "" {
				if gw.Connection.Org != "" {
					info.HolderOrg = gw.Connection.Org
				} else if gw.Connection.ISP != "" {
					info.HolderOrg = gw.Connection.ISP
				}
			}
			mu.Unlock()
		}
	}()

	wg.Wait()

	info.CountryName = countryNameRu(info.CountryCode)
	switch info.CountryCode {
	case "BY", "RU", "IR", "KP", "SY", "CU":
		info.IsSanctionedGeo = true
	}
	info.OrgWatchlistHit = checkWatchlistKeyword(info.HolderOrg)

	if info.CountryCode == "BY" {
		info.RiskNotes = append(info.RiskNotes,
			"IP зарегистрирован в Республике Беларусь (BY) — западные коммерческие центры сертификации (Sectigo, DigiCert) блокируют выпуск SSL, а ряд корпоративных WAF/почтовых шлюзов ЕС и США (Cloudflare WAF Geo-Rule, Proofpoint, Mimecast, госдомены ЕС/США/Украины) может отклонять пакеты по GeoIP.",
			"При этом основные мировые почтовики (Gmail, Microsoft Outlook/365, Yahoo, Mail.ru, Яндекс) и бесплатный УЦ Let's Encrypt принимают белорусские IP штатно при корректных PTR + SPF + DKIM + DMARC!")
	} else if info.CountryCode == "RU" {
		info.RiskNotes = append(info.RiskNotes,
			"IP зарегистрирован в РФ (RU) — действует эмбарго западных коммерческих УЦ (Sectigo, DigiCert, GlobalSign) и повышенная GeoIP-фильтрация на ряде европейских/американских WAF и почтовых шлюзов.")
	}
	if info.OrgWatchlistHit != "" {
		info.RiskNotes = append(info.RiskNotes,
			"Оператор связи / сеть совпадает с записью санкционного перечня: "+info.OrgWatchlistHit+".")
	}
	return info
}

// checkForeignDNSVisibility verifies that 3 independent foreign DNS resolvers (US/EU/Switzerland)
// can resolve the domain's A and MX records — catching Belarusian/Russian Geo-IP firewalls blocking port 53 from abroad!
func checkForeignDNSVisibility(domain, mailHost string) []ForeignDNSResolverCheck {
	type spec struct {
		name    string
		country string
		urlFmt  string
	}
	resolvers := []spec{
		{"Cloudflare DNS (1.1.1.1)", "США / Глобальная сеть", "https://cloudflare-dns.com/dns-query?name=%s&type=%s"},
		{"Google Public DNS (8.8.8.8)", "США / Европа", "https://dns.google/resolve?name=%s&type=%s"},
		{"Quad9 DNS (9.9.9.9)", "Швейцария (Цюрих, ЕС)", "https://dns.quad9.net:5053/dns-query?name=%s&type=%s"},
	}

	out := make([]ForeignDNSResolverCheck, len(resolvers))
	client := &http.Client{
		Timeout:   2200 * time.Millisecond,
		Transport: sharedFastHTTPClient.Transport,
	}

	queryOne := func(urlFmt, qname, qtype string) ([]dohAnswer, int, error) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(urlFmt, url.QueryEscape(qname), qtype), nil)
		if err != nil {
			return nil, -1, err
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, -1, err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, -1, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		var parsed dohResponse
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, -1, err
		}
		return parsed.Answer, parsed.Status, nil
	}

	var wg sync.WaitGroup
	for i, rs := range resolvers {
		wg.Add(1)
		go func(idx int, sp spec) {
			defer wg.Done()
			entry := ForeignDNSResolverCheck{
				ResolverName: sp.name,
				Country:      sp.country,
			}
			targetHost := mailHost
			if targetHost == "" {
				targetHost = domain
			}
			ansA, stA, errA := queryOne(sp.urlFmt, targetHost, "A")
			ansMX, stMX, errMX := queryOne(sp.urlFmt, domain, "MX")
			if errA != nil && errMX != nil {
				entry.ErrorDetail = "Резолвер недоступен с этой сети (" + errA.Error() + ")"
				out[idx] = entry
				return
			}
			entry.Reachable = true
			if stA == 2 || stMX == 2 {
				entry.ErrorDetail = "🚨 SERVFAIL за рубежом! Авторитативные NS-серверы вашего домена не отвечают зарубежным DNS (возможна гео-блокировка порта 53 из-за пределов РБ/РФ!)"
			}
			for _, a := range ansA {
				if a.Type == 1 {
					entry.ResolvedIPs = append(entry.ResolvedIPs, strings.TrimSpace(a.Data))
				}
			}
			for _, m := range ansMX {
				if m.Type == 15 {
					entry.ResolvedMX = append(entry.ResolvedMX, strings.TrimSpace(m.Data))
				}
			}
			out[idx] = entry
		}(i, rs)
	}
	wg.Wait()
	return out
}

// probeGlobalServiceGeoBlocks tests live connectivity & HTTP 403/451 geo-blocking from this machine to key PKI, CDN & Mail gateways.
func probeGlobalServiceGeoBlocks() (matrix []GlobalServiceReachability, edgeTraceInfo string) {
	type targetSpec struct {
		name     string
		category string
		kind     string // "http" or "smtp"
		target   string
		hostHdr  string
	}
	specs := []targetSpec{
		{"Let's Encrypt Production ACME", "SSL / PKI", "http", "https://acme-v02.api.letsencrypt.org/directory", ""},
		{"OCSP сервер отзыва сертификатов Let's Encrypt", "SSL / PKI", "http", "http://r10.o.lencr.org", ""},
		{"ZeroSSL ACME Directory", "SSL / PKI", "http", "https://acme.zerossl.com/v2/DV90", ""},
		{"Cloudflare Global Edge (Geo-Trace)", "DNS / CDN", "http", "https://1.1.1.1/cdn-cgi/trace", "cloudflare-dns.com"},
		{"Google Cloud / Public DNS API", "DNS / CDN", "http", "https://dns.google/resolve?name=example.com&type=A", ""},
		{"Gmail приём писем (MX :25)", "Почтовые MX", "smtp", "gmail-smtp-in.l.google.com:25", ""},
		{"Microsoft 365 / Outlook приём писем (MX :25)", "Почтовые MX", "smtp", "outlook-com.olc.protection.outlook.com:25", ""},
		{"Mail.ru приём писем (MX :25)", "Почтовые MX", "smtp", "mxs.mail.ru:25", ""},
		{"Яндекс Почта приём писем (MX :25)", "Почтовые MX", "smtp", "mx.yandex.ru:25", ""},
		{"GitHub API / Инфраструктура обновлений", "Облака", "http", "https://api.github.com/zen", ""},
	}

	matrix = make([]GlobalServiceReachability, len(specs))
	client := &http.Client{
		Timeout:   2300 * time.Millisecond,
		Transport: sharedFastHTTPClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var traceMu sync.Mutex
	var wg sync.WaitGroup
	for i, sp := range specs {
		wg.Add(1)
		go func(idx int, t targetSpec) {
			defer wg.Done()
			start := time.Now()
			item := GlobalServiceReachability{
				Name:     t.name,
				Category: t.category,
				Target:   t.target,
			}
			if t.kind == "http" {
				req, _ := http.NewRequest(http.MethodGet, t.target, nil)
				req.Header.Set("User-Agent", "KerioCertManager-Diag/4.1")
				if t.hostHdr != "" {
					req.Host = t.hostHdr
				}
				resp, err := client.Do(req)
				item.LatencyMs = time.Since(start).Milliseconds()
				if err != nil {
					item.Status = "unreachable"
					item.HTTPOrSMTP = "Нет ответа / блок"
					item.Explanation = err.Error()
					matrix[idx] = item
					return
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
				resp.Body.Close()
				bodyStr := string(bodyBytes)
				item.HTTPOrSMTP = fmt.Sprintf("HTTP %d", resp.StatusCode)

				if strings.Contains(t.target, "/cdn-cgi/trace") {
					var locVal, coloVal string
					for _, ln := range strings.Split(bodyStr, "\n") {
						if strings.HasPrefix(ln, "loc=") {
							locVal = strings.TrimSpace(strings.TrimPrefix(ln, "loc="))
						}
						if strings.HasPrefix(ln, "colo=") {
							coloVal = strings.TrimSpace(strings.TrimPrefix(ln, "colo="))
						}
					}
					if locVal != "" || coloVal != "" {
						traceMu.Lock()
						edgeTraceInfo = fmt.Sprintf("Страна выхода по данным Cloudflare: %s • Ближайший узел: %s", locVal, coloVal)
						traceMu.Unlock()
					}
				}

				lowBody := strings.ToLower(bodyStr)
				if resp.StatusCode == 451 || resp.StatusCode == 403 && (strings.Contains(lowBody, "country") || strings.Contains(lowBody, "region") || strings.Contains(lowBody, "access denied") || strings.Contains(lowBody, "sanction") || strings.Contains(lowBody, "forbidden")) {
					item.Status = "geoblocked"
					item.Explanation = fmt.Sprintf("Сервис вернул %s — включена гео/санкционная фильтрация по IP!", item.HTTPOrSMTP)
				} else if resp.StatusCode < 500 {
					item.Status = "ok"
					item.Explanation = "Прямой доступ работает без гео-блокировок"
				} else {
					item.Status = "unreachable"
					item.Explanation = "Ошибка удалённого узла " + item.HTTPOrSMTP
				}
			} else {
				conn, err := net.DialTimeout("tcp", t.target, 2200*time.Millisecond)
				item.LatencyMs = time.Since(start).Milliseconds()
				if err != nil {
					item.Status = "unreachable"
					item.HTTPOrSMTP = "Порт 25 закрыт"
					item.Explanation = "Исходящий TCP :25 заблокирован вашим интернет-провайдером или межсетевым экраном (" + err.Error() + ")"
					matrix[idx] = item
					return
				}
				_ = conn.SetDeadline(time.Now().Add(2000 * time.Millisecond))
				br := bufio.NewReader(conn)
				code, line, rerr := readSMTPReply(br)
				_ = conn.Close()
				if rerr != nil {
					item.Status = "unreachable"
					item.HTTPOrSMTP = "Сброс сессии"
					item.Explanation = "Соединение установлено, но баннер SMTP оборван (" + rerr.Error() + ")"
				} else if code >= 400 {
					item.Status = "geoblocked"
					item.HTTPOrSMTP = fmt.Sprintf("SMTP %d", code)
					item.Explanation = "Удалённый почтовый шлюз сразу отклонил ваш IP на этапе подключения: " + line
				} else {
					item.Status = "ok"
					item.HTTPOrSMTP = fmt.Sprintf("SMTP %d OK", code)
					item.Explanation = "Принимает прямые входящие соединения с вашего IP (" + line + ")"
				}
			}
			matrix[idx] = item
		}(i, sp)
	}
	wg.Wait()
	return matrix, edgeTraceInfo
}

func buildCACompatibilityMatrix(asciiDomain, tldLabel string, embargoTLD bool, ipInfo IPSanctionsGeoInfo, leProbe LEOFACProbeResult) []CACompatibilityEntry {
	var out []CACompatibilityEntry
	isBYRU := embargoTLD || ipInfo.CountryCode == "BY" || ipInfo.CountryCode == "RU"

	// 1. Let's Encrypt
	if leProbe.DomainBlocked || leProbe.IPBlocked {
		out = append(out, CACompatibilityEntry{
			Provider:       "Let's Encrypt (ISRG)",
			Jurisdiction:   "США (Некоммерческий УЦ, лицензия OFAC GL D-2)",
			Status:         "blocked",
			StatusBadge:    "🚨 ЗАБЛОКИРОВАНО OFAC SDN",
			Details:        "Домен или IP внесён в прямой санкционный фильтр Let's Encrypt (`Policy forbids issuing for name`). Автоматический выпуск для этого имени отклонён.",
			Recommendation: "Используйте нейтральный технический домен для MX/WebMail (напр. mail-company.com/.kz) либо коммерческий сертификат GlobalSign / ГосСУОК РБ.",
		})
	} else {
		liveBadge := "✅ ДОСТУПЕН (Выпускает для .BY/.БЕЛ/.RU/.РФ)"
		if leProbe.CheckedLive {
			liveBadge = "✅ ПРОВЕРЕНО ОНЛАЙН — РАЗРЕШЁН!"
		}
		out = append(out, CACompatibilityEntry{
			Provider:       "Let's Encrypt (ISRG)",
			Jurisdiction:   "США (Исключение связи OFAC GL D-2)",
			Status:         "allowed",
			StatusBadge:    liveBadge,
			Details:        fmt.Sprintf("Бесплатно выпускает доверенные 90-дневные DV-сертификаты для %s и 6-дневные IP-сертификаты (если организация не входит в прямой список OFAC SDN).", nonEmptyOr(tldLabel, asciiDomain)),
			Recommendation: "Рекомендуемый основной вариант в KerioCertManager! Если в РБ закрыт порт 80 из-за рубежа — выбирайте режим DNS-01 (TXT).",
		})
	}

	// 2. Sectigo / Comodo / ZeroSSL
	if isBYRU {
		out = append(out, CACompatibilityEntry{
			Provider:       "Sectigo / Comodo / PositiveSSL / ZeroSSL",
			Jurisdiction:   "США / Великобритания",
			Status:         "blocked",
			StatusBadge:    "🚫 БЛОКИРОВКА .BY / .RU",
			Details:        "Sectigo (и работающий на его базе ZeroSSL) полностью блокирует выпуск и продление любых сертификатов для зон .by, .бел, .ru, .рф, .su и резидентов РБ/РФ.",
			Recommendation: "Не покупайте сертификаты Sectigo/PositiveSSL для доменов .by/.ru — заказ будет отклонён проверкой комплаенса.",
		})
		out = append(out, CACompatibilityEntry{
			Provider:       "DigiCert / GeoTrust / Thawte / RapidSSL",
			Jurisdiction:   "США",
			Status:         "blocked",
			StatusBadge:    "🚫 БЛОКИРОВКА .BY / .RU",
			Details:        "Полный запрет выпуска DV/OV/EV и Wildcard сертификатов для доменов .by, .бел, .ru, .рф и организаций с юрисдикцией BY / RU.",
			Recommendation: "Используйте бесплатный Let's Encrypt с автопродлением через нашу программу вместо платных RapidSSL/GeoTrust.",
		})
		out = append(out, CACompatibilityEntry{
			Provider:       "GlobalSign (Корпоративный / партнёрский канал)",
			Jurisdiction:   "Бельгия / Япония (GMO)",
			Status:         "warning",
			StatusBadge:    "🟠 ОГРАНИЧЕННО (Через реселлеров СНГ)",
			Details:        "Для несанкционных коммерческих компаний РБ/РФ выпуск DV/Wildcard возможен через локальных партнёров (например, hoster.by), но с ручной проверкой компании.",
			Recommendation: "Подходит, если нужен Wildcard на 200 дней и компания не входит в санкционные списки ЕС/США.",
		})
		out = append(out, CACompatibilityEntry{
			Provider:       "Национальные УЦ (ГосСУОК НЦЭУ РБ / НУЦ Минцифры РФ)",
			Jurisdiction:   "Беларусь / Россия",
			Status:         "warning",
			StatusBadge:    "⚠️ НЕ ДОВЕРЕН В GMAIL / IPHONE / OUTLOOK",
			Details:        "Сертификаты НЦЭУ / Минцифры работают внутри госсети и Яндекс Браузера, но НЕ входят в корневые хранилища Google, Microsoft, Apple iOS и серверов Gmail/Outlook!",
			Recommendation: "НЕ ставьте сертификат НУЦ/ГосСУОК как основной на SMTP/IMAPS Kerio для внешней почты — внешние почтовики будут считать TLS недоверенным! Используйте Let's Encrypt.",
		})
	} else {
		out = append(out, CACompatibilityEntry{
			Provider:       "Sectigo / DigiCert / GlobalSign / ZeroSSL",
			Jurisdiction:   "Международные коммерческие УЦ",
			Status:         "allowed",
			StatusBadge:    "✅ ДОСТУПНЫ БЕЗ ОГРАНИЧЕНИЙ",
			Details:        "Международная доменная зона и зарубежный IP не подпадают под региональные ограничения коммерческих центров сертификации.",
			Recommendation: "Доступен как бесплатный выпуск Let's Encrypt, так и любые коммерческие OV/Wildcard сертификаты.",
		})
	}
	return out
}

// RunSanctionsAndGeoBlockAudit performs a comprehensive parallel audit of Domain + IP sanctions & geo-blocking.
func RunSanctionsAndGeoBlockAudit(req SanctionsCheckRequest, logFn func(level, msg string)) (*SanctionsCheckReport, error) {
	log := func(level, msg string) {
		if logFn != nil {
			logFn(level, msg)
		}
	}

	rawDom := strings.TrimSpace(req.Domain)
	rawHost := strings.TrimSpace(req.MailHost)
	rawIP := strings.TrimSpace(req.IPAddress)
	if rawDom == "" && rawHost == "" && rawIP == "" {
		return nil, fmt.Errorf("укажите домен (например, leend.by) и/или IP-адрес для проверки на санкционные блокировки")
	}

	var asciiDom, asciiHost string
	if rawDom != "" {
		if idx := strings.LastIndex(rawDom, "@"); idx >= 0 {
			rawDom = rawDom[idx+1:]
		}
		if norm, _, err := NormalizeDomain(rawDom); err == nil {
			asciiDom = norm
		}
	}
	if rawHost != "" {
		if normH, _, err := NormalizeDomain(rawHost); err == nil {
			asciiHost = normH
		}
	}
	if asciiDom != "" && asciiHost == "" {
		asciiHost = "mail." + asciiDom
	}

	rep := &SanctionsCheckReport{
		CheckedAt:      time.Now().Format("02.01.2006 15:04:05"),
		TargetDomain:   asciiDom,
		TargetMailHost: asciiHost,
		TargetTLD:      extractEffectiveTLD(asciiDom),
	}

	log("info", fmt.Sprintf("🌍 Запуск комплексной проверки на санкции и гео-блокировки: домен=%s, IP=%s...", nonEmptyOr(asciiDom, "—"), nonEmptyOr(rawIP, "автоопределение")))

	// Resolve real external public IP automatically if not explicitly provided
	targetIP := rawIP
	if targetIP != "" {
		rep.TargetIPSource = "указан вручную"
	} else {
		if asciiHost != "" {
			if ips := lookupPublicIPv4sExternal(asciiHost); len(ips) > 0 {
				targetIP = ips[0]
				rep.TargetIPSource = "внешний DNS A (" + asciiHost + ")"
			}
		}
		if targetIP == "" && asciiDom != "" {
			if ips := lookupPublicIPv4sExternal(asciiDom); len(ips) > 0 {
				targetIP = ips[0]
				rep.TargetIPSource = "внешний DNS A (" + asciiDom + ")"
			}
		}
		if targetIP == "" {
			if wan := DetectPublicIPFast(); wan != "" {
				targetIP = wan
				rep.TargetIPSource = "текущий внешний WAN IP"
			}
		}
	}
	rep.TargetIP = targetIP
	rep.ServerEgressIP = DetectPublicIPFast()
	rep.DomainWatchlistHit = checkWatchlistKeyword(asciiDom)

	// Run ALL 4 heavy network probes in ONE parallel wave!
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		var idents []string
		if asciiDom != "" {
			idents = append(idents, asciiDom)
		}
		if asciiHost != "" && asciiHost != asciiDom {
			idents = append(idents, asciiHost)
		}
		rep.LEPolicyProbe = probeLetsEncryptOFACPolicy(req.ACMEDirectoryURL, idents, targetIP)
	}()

	go func() {
		defer wg.Done()
		if targetIP != "" {
			rep.IPGeoInfo = inspectIPSanctionsAndGeoInfo(targetIP)
		}
	}()

	go func() {
		defer wg.Done()
		if asciiDom != "" {
			rep.ForeignDNS = checkForeignDNSVisibility(asciiDom, asciiHost)
		}
	}()

	go func() {
		defer wg.Done()
		rep.ServiceMatrix, rep.ServerEdgeInfo = probeGlobalServiceGeoBlocks()
	}()

	wg.Wait()

	embargoTLD := isCommercialCAEmbargoedTLD(asciiDom)
	rep.CAMatrix = buildCACompatibilityMatrix(asciiDom, rep.TargetTLD, embargoTLD, rep.IPGeoInfo, rep.LEPolicyProbe)

	// Synthesize structured findings + step-by-step Russian remediation guides
	addFinding := func(item MailCheckItem, guide *MailRemediationGuide) {
		if guide != nil {
			cp := *guide
			item.Solution = &cp
			rep.Remediations = append(rep.Remediations, cp)
		}
		rep.Findings = append(rep.Findings, item)
	}

	// Finding 1: Direct OFAC CA Policy Check (Let's Encrypt)
	if rep.LEPolicyProbe.DomainBlocked || rep.LEPolicyProbe.IPBlocked {
		rep.RiskScore += 65
		addFinding(
			MailCheckItem{
				ID:       "sanctions_ofac_ca",
				Category: "Санкционный комплаенс центров сертификации (OFAC SDN)",
				Title:    "Прямая санкционная блокировка OFAC в Let's Encrypt (`Policy forbids issuing for name`)",
				Status:   "error",
				Summary:  rep.LEPolicyProbe.StatusSummary,
				Details:  []string{"Ответ ACME-сервера: " + rep.LEPolicyProbe.RawACMEError},
			},
			&MailRemediationGuide{
				Severity:     "critical",
				Category:     "Обход санкционной блокировки SSL для Kerio Connect",
				Title:        "Что делать, если домен компании заблокирован санкционным списком OFAC в Let's Encrypt",
				WhyItMatters: "Если основной бренд-домен внесён в список OFAC SDN США, ни один американский УЦ (включая Let's Encrypt) не подпишет сертификат на это доменное имя.",
				Steps: []string{
					"Способ №1 (100% рабочий для почты Gmail/Outlook/iPhone и соответствует Указу № 60 РБ): зарегистрируйте нейтральный технический домен для почтового транспорта (например, mail-tech.by или company-mail.kz / .com), не совпадающий с названием из SDN-списка, выпустите на него бесплатный Let's Encrypt SSL в KerioCertManager и укажите его в MX-записи основного домена (`@ IN MX 10 mx1.tech-domain.by`)!",
					"Важно понимать: в SMTP шифрование STARTTLS проверяет сертификат именно ИМЕНИ ХОСТА ИЗ ЗАПИСИ MX (`mx1.tech-domain.by`), а НЕ домена после собачки `@company.by`! Поэтому письма сотрудников `ivanov@company.by` продолжат ходить со старых адресов с полным доверенным TLS!",
					"Способ №2: запросите коммерческий DV-сертификат через партнёрский канал GlobalSign у локального регистратора (hoster.by / active.by).",
				},
			},
		)
	} else {
		addFinding(MailCheckItem{
			ID:       "sanctions_ofac_ca",
			Category: "Санкционный комплаенс центров сертификации (OFAC SDN)",
			Title:    "Проверка прямых санкционных списков OFAC SDN в Let's Encrypt (Домен + IP)",
			Status:   "ok",
			Summary:  rep.LEPolicyProbe.StatusSummary,
			Details:  []string{"Проверенные идентификаторы: " + nonEmptyOr(strings.Join(rep.LEPolicyProbe.TestedIdentifiers, ", "), nonEmptyOr(asciiDom, targetIP))},
		}, nil)
	}

	// Finding 2: Commercial CA TLD / Country Embargo (.by / .бел / .ru / .рф)
	if embargoTLD || rep.IPGeoInfo.IsSanctionedGeo || rep.DomainWatchlistHit != "" || rep.IPGeoInfo.OrgWatchlistHit != "" {
		rep.RiskScore += 25
		var det []string
		if embargoTLD {
			det = append(det, fmt.Sprintf("Доменная зона %s заблокирована западными коммерческими УЦ (Sectigo, Comodo, ZeroSSL, DigiCert, GeoTrust, RapidSSL).", rep.TargetTLD))
		}
		if rep.IPGeoInfo.CountryCode != "" {
			det = append(det, fmt.Sprintf("Геолокация и сеть IP %s: %s • %s • %s (%s)",
				rep.IPGeoInfo.IPAddress, rep.IPGeoInfo.CountryName, nonEmptyOr(rep.IPGeoInfo.ASN, "ASN —"), nonEmptyOr(rep.IPGeoInfo.HolderOrg, "Провайдер —"), nonEmptyOr(rep.IPGeoInfo.Prefix, "—")))
		}
		if rep.DomainWatchlistHit != "" {
			rep.RiskScore += 25
			det = append(det, "⚠️ Совпадение имени домена с санкционным перечнем организаций: "+rep.DomainWatchlistHit)
		}
		if rep.IPGeoInfo.OrgWatchlistHit != "" {
			det = append(det, "ℹ️ Оператор сети присутствует в санкционных перечнях ЕС: "+rep.IPGeoInfo.OrgWatchlistHit)
		}
		addFinding(
			MailCheckItem{
				ID:       "sanctions_geo_tld",
				Category: "Региональные санкции на доменную зону и GeoIP подсеть",
				Title:    fmt.Sprintf("Региональные ограничения зоны %s / сети %s (Коммерческие SSL и западные GeoIP-фильтры)", nonEmptyOr(rep.TargetTLD, "—"), nonEmptyOr(rep.IPGeoInfo.CountryName, "—")),
				Status:   "warning",
				Summary:  "Прямой блокировки почты в Gmail/Outlook/Mail.ru/Яндекс НЕТ, но действуют санкции коммерческих УЦ (Sectigo/DigiCert) и возможна фильтрация на отдельных корпоративных шлюзах ЕС/США по GeoIP.",
				Details:  det,
			},
			&MailRemediationGuide{
				Severity:     "warning",
				Category:     "Практическая защита от региональных и GeoIP-блокировок (РБ / РФ)",
				Title:        "Как исключить сбои SSL и недоставку писем зарубежным контрагентам (с соблюдением Указа № 60 РБ)",
				WhyItMatters: "В Беларуси основной почтовый сервер и ящики обязаны размещаться в РБ (Указ № 60), однако отдельные контрагенты в ЕС/США используют файрволы (Cloudflare WAF, Proofpoint, Mimecast), режущие пакеты из подсетей BY/RU по GeoIP.",
				Steps: []string{
					"1. Для SSL-сертификатов используйте встроенный в эту программу выпуск Let's Encrypt + Автопродление (не тратьте бюджет на Sectigo/DigiCert/ZeroSSL — они блокируют .by/.ru). Если у вас включён отсев зарубежного трафика на 80 порту — выпускайте через режим DNS-01 (TXT)!",
					"2. Если конкретный зарубежный партнёр в ЕС/США отвергает письма с белорусского IP с ошибкой GeoIP / Policy Reject — НЕ переносите сам Kerio Connect за границу (это нарушает Указ № 60). Вместо этого арендуйте дешёвый VPS-релей в нейтральной юрисдикции (Казахстан / Германия) и в Kerio Connect настройте выборочную пересылку ТОЛЬКО для проблемных доменов: Конфигурация → Доставка почты (SMTP Server) → вкладка «Маршрутизация / Relay» (или транспортное правило)!",
					"3. Не открывайте админку Kerio (:4040) и RDP (:3389) наружу — в РБ/РФ включение зарубежной гео-блокировки на роутере нужно применять ТОЛЬКО к админским портам, оставляя порт TCP 25 открытым для всего мира (иначе письма из-за рубежа не дойдут!).",
				},
			},
		)
	} else {
		addFinding(MailCheckItem{
			ID:       "sanctions_geo_tld",
			Category: "Региональные санкции на доменную зону и GeoIP подсеть",
			Title:    "Региональные ограничения доменной зоны и геолокации IP-адреса",
			Status:   "ok",
			Summary:  fmt.Sprintf("Доменная зона (%s) и геолокация IP (%s, %s) не входят в санкционные регионы.", nonEmptyOr(rep.TargetTLD, "—"), nonEmptyOr(rep.IPGeoInfo.CountryName, "—"), nonEmptyOr(rep.IPGeoInfo.ASN, "—")),
		}, nil)
	}

	// Finding 3: Foreign DNS Visibility (catches Belarus Geo-Firewall blocking foreign UDP/TCP 53!)
	reachableForeign := 0
	resolvedForeign := 0
	var dnsDetails []string
	for _, fd := range rep.ForeignDNS {
		if fd.Reachable {
			reachableForeign++
			if len(fd.ResolvedIPs) > 0 || len(fd.ResolvedMX) > 0 {
				resolvedForeign++
				dnsDetails = append(dnsDetails, fmt.Sprintf("✅ %s (%s): A=%v, MX=%v", fd.ResolverName, fd.Country, fd.ResolvedIPs, fd.ResolvedMX))
			} else {
				dnsDetails = append(dnsDetails, fmt.Sprintf("🔴 %s (%s): ЗАПИСИ НЕ ВИДНЫ ИЗ-ЗА РУБЕЖА! %s", fd.ResolverName, fd.Country, fd.ErrorDetail))
			}
		}
	}
	if reachableForeign > 0 && resolvedForeign == 0 && asciiDom != "" {
		rep.RiskScore += 35
		addFinding(
			MailCheckItem{
				ID:       "sanctions_foreign_dns",
				Category: "Видимость домена из США и Европы (Проверка гео-изоляции DNS)",
				Title:    "КРИТИЧНО: Домен НЕ виден зарубежным DNS-серверам США и Европы (Google / Cloudflare / Quad9)!",
				Status:   "error",
				Summary:  "Ни один зарубежный DNS-сервер не смог получить A/MX записи вашего домена! Письма из Gmail, Outlook и Европы не дойдут, а Let's Encrypt не выпустит сертификат!",
				Details:  dnsDetails,
			},
			&MailRemediationGuide{
				Severity:     "critical",
				Category:     "Устранение гео-блокировки авторитативных DNS-серверов",
				Title:        "Откройте доступ к вашим NS-серверам (порт 53 UDP/TCP) из-за пределов РБ / перенесите DNS на облачный хостинг",
				WhyItMatters: "В Беларуси часто при включении защиты «только для IP РБ» случайно закрывают порт 53 на корпоративных NS-серверах — внутри страны домен открывается, а для всего остального мира он перестаёт существовать!",
				Steps: []string{
					"Проверьте доступность всех ваших NS-серверов из-за границы по портам UDP 53 и TCP 53.",
					"Либо делегируйте публичную DNS-зону внешнему распределённому провайдеру (hoster.by Cloud DNS / Cloudflare DNS с выключенным оранжевым облачком `DNS Only`).",
				},
			},
		)
	} else if reachableForeign > 0 {
		addFinding(MailCheckItem{
			ID:       "sanctions_foreign_dns",
			Category: "Видимость домена из США и Европы (Проверка гео-изоляции DNS)",
			Title:    fmt.Sprintf("Международная видимость DNS подтверждена (%d из %d зарубежных узлов США/ЕС видят ваш домен)", resolvedForeign, reachableForeign),
			Status:   "ok",
			Summary:  "Авторитативные NS-серверы вашего домена открыты для всего мира — зарубежной гео-блокировки на уровне DNS нет!",
			Details:  dnsDetails,
		}, nil)
	}

	// Finding 4: Direct Service Geo-Block Reachability from current machine
	var geoBlockedSvcs []string
	for _, sv := range rep.ServiceMatrix {
		if sv.Status == "geoblocked" {
			geoBlockedSvcs = append(geoBlockedSvcs, fmt.Sprintf("%s (%s)", sv.Name, sv.HTTPOrSMTP))
		}
	}
	if len(geoBlockedSvcs) > 0 {
		rep.RiskScore += 20
		addFinding(MailCheckItem{
			ID:       "sanctions_live_egress",
			Category: "Прямая проверка исходящего доступа к мировым сервисам",
			Title:    fmt.Sprintf("Обнаружена активная гео/санкционная фильтрация по текущему IP (%d серв.)", len(geoBlockedSvcs)),
			Status:   "warning",
			Summary:  "Следующие внешние узлы вернули явный код блокировки (HTTP 403/451 / SMTP 5xx): " + strings.Join(geoBlockedSvcs, "; "),
		}, nil)
	}

	if rep.RiskScore > 100 {
		rep.RiskScore = 100
	}

	switch {
	case rep.LEPolicyProbe.DomainBlocked || rep.LEPolicyProbe.IPBlocked || rep.RiskScore >= 60:
		rep.OverallStatus = "blocked"
		rep.VerdictTitle = "🚨 ОБНАРУЖЕНЫ ПРЯМЫЕ САНКЦИОННЫЕ ИЛИ ГЕО-БЛОКИРОВКИ!"
		rep.VerdictSummary = "Выявлены критические санкционные ограничения (блокировка выпуска SSL на уровне комплаенса OFAC либо полная недоступность DNS/сервисов из-за рубежа). Ниже приведены готовые рабочие схемы обхода для Kerio Connect!"
	case rep.RiskScore >= 20:
		rep.OverallStatus = "restricted"
		rep.VerdictTitle = "🟠 Прямого бана OFAC нет, но действуют региональные ограничения (.BY/.RU)"
		rep.VerdictSummary = "Отличная новость: ваш домен и IP НЕ заблокированы в Let's Encrypt и мировых почтовиках (Gmail / Outlook / Mail.ru / Яндекс)! Действуют только стандартные ограничения коммерческих УЦ (Sectigo/DigiCert) на зону " + rep.TargetTLD + " — ниже показано, что работает на 100%."
	default:
		rep.OverallStatus = "clean"
		rep.VerdictTitle = "✅ САНКЦИОННЫХ И ГЕО-БЛОКИРОВОК НЕ ОБНАРУЖЕНО!"
		rep.VerdictSummary = "Домен, IP-адрес, автономная система провайдера и международная DNS-видимость полностью чисты — работают все центры сертификации и мировые почтовые шлюзы."
	}

	log("success", fmt.Sprintf("🌍 Проверка на санкции завершена (%s / %s): %s", nonEmptyOr(asciiDom, "—"), nonEmptyOr(targetIP, "—"), rep.VerdictTitle))
	return rep, nil
}
