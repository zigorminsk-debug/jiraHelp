package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

type LocalNICInfo struct {
	InterfaceName string `json:"interfaceName"`
	IP            string `json:"ip"`
	IsIPv6        bool   `json:"isIpv6"`
	IsPrivate     bool   `json:"isPrivate"`
}

type DomainCheckDetail struct {
	RawDomain      string   `json:"rawDomain"`
	ASCIIDomain    string   `json:"asciiDomain"`
	DisplayDomain  string   `json:"displayDomain"`
	IsIDN          bool     `json:"isIdn"`
	ResolvedIPs    []string `json:"resolvedIps"`
	MatchesInputIP bool     `json:"matchesInputIp"`
	LookupError    string   `json:"lookupError,omitempty"`
}

type PortBindCheck struct {
	Port       int    `json:"port"`
	BindTarget string `json:"bindTarget"`
	CanBind    bool   `json:"canBind"`
	StatusText string `json:"statusText"`
	ErrorText  string `json:"errorText,omitempty"`
}

type PreflightResponse struct {
	Valid              bool                `json:"valid"`
	InputIP            string              `json:"inputIp"`
	IPValid            bool                `json:"ipValid"`
	IsIPv6             bool                `json:"isIpv6"`
	IsPrivateIP        bool                `json:"isPrivateIp"`
	IsLocalInterfaceIP bool                `json:"isLocalInterfaceIp"`
	EffectiveBindIP    string              `json:"effectiveBindIp"`
	DetectedExternalIP string              `json:"detectedExternalIp,omitempty"`
	Domains            []DomainCheckDetail `json:"domains"`
	Port80             PortBindCheck       `json:"port80"`
	Port443            PortBindCheck       `json:"port443"`
	Warnings           []string            `json:"warnings"`
	Recommendations    []string            `json:"recommendations"`
}

func ClassifyIP(raw string) (ip net.IP, valid bool, isIPv6 bool, isPrivate bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false, false, false
	}
	parsed := net.ParseIP(trimmed)
	if parsed == nil {
		return nil, false, false, false
	}
	v4 := parsed.To4()
	isIPv6 = v4 == nil
	private := parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified()
	// Also check CGNAT 100.64.0.0/10 and documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
	if v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			private = true
		}
	}
	return parsed, true, isIPv6, private
}

func ListLocalIPs() []LocalNICInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []LocalNICInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			v4 := ip.To4()
			out = append(out, LocalNICInfo{
				InterfaceName: iface.Name,
				IP:            ip.String(),
				IsIPv6:        v4 == nil,
				IsPrivate:     ip.IsPrivate(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsIPv6 != out[j].IsIPv6 {
			return !out[i].IsIPv6
		}
		if out[i].IsPrivate != out[j].IsPrivate {
			return !out[i].IsPrivate
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func IsAssignedToLocalNIC(target net.IP) bool {
	if target == nil {
		return false
	}
	for _, item := range ListLocalIPs() {
		p := net.ParseIP(item.IP)
		if p != nil && p.Equal(target) {
			return true
		}
	}
	return false
}

// ResolveEffectiveBindIP determines the safest local IP address for HTTP-01 / TLS-ALPN-01 listener binding.
func ResolveEffectiveBindIP(inputIP, explicitBindIP string) (bindIP string, isNAT bool) {
	if strings.TrimSpace(explicitBindIP) != "" && explicitBindIP != "auto" {
		return strings.TrimSpace(explicitBindIP), false
	}
	parsed, valid, _, _ := ClassifyIP(inputIP)
	if !valid {
		return "0.0.0.0", false
	}
	if IsAssignedToLocalNIC(parsed) {
		return parsed.String(), false
	}
	// If entered IP is an external WAN IP routed through NAT firewall/router, bind on all local interfaces!
	return "0.0.0.0", true
}

func DetectPublicIP() string {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	for _, u := range endpoints {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		candidate := strings.TrimSpace(string(b))
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	return ""
}

func LookupDomainIPsMultiResolver(asciiDomain string) ([]string, error) {
	seen := map[string]bool{}
	var ips []string

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	// Try system resolver first
	if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, asciiDomain); err == nil {
		for _, a := range addrs {
			s := a.IP.String()
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
		}
	}

	// Also query public DNS resolvers (Google 8.8.8.8 & Cloudflare 1.1.1.1) when reachable
	for _, dnsServer := range []string{"8.8.8.8:53", "1.1.1.1:53"} {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		c2, can2 := context.WithTimeout(context.Background(), 2200*time.Millisecond)
		addrs, err := r.LookupIPAddr(c2, asciiDomain)
		can2()
		if err == nil {
			for _, a := range addrs {
				s := a.IP.String()
				if !seen[s] {
					seen[s] = true
					ips = append(ips, s)
				}
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS A/AAAA записи для %s не найдены (или DNS недоступен)", asciiDomain)
	}
	sort.Strings(ips)
	return ips, nil
}

func LookupDNSTXTRecords(fqdn string) ([]string, error) {
	seen := map[string]bool{}
	var records []string

	for _, dnsServer := range []string{"", "8.8.8.8:53", "1.1.1.1:53"} {
		var r *net.Resolver
		if dnsServer == "" {
			r = net.DefaultResolver
		} else {
			srv := dnsServer
			r = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 2 * time.Second}
					return d.DialContext(ctx, "udp", srv)
				},
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		txts, err := r.LookupTXT(ctx, fqdn)
		cancel()
		if err == nil {
			for _, t := range txts {
				if !seen[t] {
					seen[t] = true
					records = append(records, t)
				}
			}
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("TXT-запись %s пока не найдена в DNS", fqdn)
	}
	return records, nil
}

func TestPortBind(bindIP string, port int) PortBindCheck {
	if port <= 0 {
		port = 80
	}
	if strings.TrimSpace(bindIP) == "" {
		bindIP = "0.0.0.0"
	}
	addr := net.JoinHostPort(bindIP, fmt.Sprintf("%d", port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		msg := fmt.Sprintf("Порт %d на %s занят или требует прав Администратора (%v)", port, bindIP, err)
		return PortBindCheck{
			Port:       port,
			BindTarget: addr,
			CanBind:    false,
			StatusText: msg,
			ErrorText:  err.Error(),
		}
	}
	_ = ln.Close()
	return PortBindCheck{
		Port:       port,
		BindTarget: addr,
		CanBind:    true,
		StatusText: fmt.Sprintf("Порт %d (%s) свободен и готов для проверки Let's Encrypt", port, bindIP),
	}
}

func RunPreflightCheck(req IssueRequest) PreflightResponse {
	var res PreflightResponse
	res.InputIP = strings.TrimSpace(req.IPAddress)

	parsedIP, ipValid, isIPv6, isPrivate := ClassifyIP(res.InputIP)
	res.IPValid = ipValid
	res.IsIPv6 = isIPv6
	res.IsPrivateIP = isPrivate
	res.IsLocalInterfaceIP = IsAssignedToLocalNIC(parsedIP)

	bindIP, isNAT := ResolveEffectiveBindIP(res.InputIP, req.BindIP)
	res.EffectiveBindIP = bindIP
	res.DetectedExternalIP = DetectPublicIP()

	if isNAT && ipValid && !isPrivate {
		res.Recommendations = append(res.Recommendations,
			fmt.Sprintf("Введённый публичный IP %s находится на внешнем маршрутизаторе (NAT). Встроенный сервер проверки автоматически будет слушать %s — убедитесь, что на роутере проброшен TCP порт 80 (или 443) на этот сервер Windows.", res.InputIP, bindIP))
	}
	if ipValid && isPrivate {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("Введён локальный (серый) IP %s. Let's Encrypt проверяет сервер по публичному внешнему IP — убедитесь, что DNS A-запись домена указывает на ваш внешний белый IP, а порт 80 проброшен на %s.", res.InputIP, res.InputIP))
		if req.IncludeIPSAN && req.Mode != "selfsigned" {
			res.Warnings = append(res.Warnings,
				"Публичный сертификат Let's Encrypt нельзя выпустить на частный (RFC1918) IP-адрес в поле SAN. Для выпуска с частным IP используйте режим «Самоподписанный для Kerio» или отключите опцию включения IP в SAN Let's Encrypt.")
		}
	}

	rawDomains := []string{}
	if strings.TrimSpace(req.Domain) != "" {
		rawDomains = append(rawDomains, req.Domain)
	}
	rawDomains = append(rawDomains, req.ExtraDomains...)

	seenDom := map[string]bool{}
	for _, rawD := range rawDomains {
		if strings.TrimSpace(rawD) == "" {
			continue
		}
		ascii, disp, err := NormalizeDomain(rawD)
		if err != nil {
			res.Domains = append(res.Domains, DomainCheckDetail{
				RawDomain:   rawD,
				LookupError: err.Error(),
			})
			res.Warnings = append(res.Warnings, err.Error())
			continue
		}
		if seenDom[ascii] {
			continue
		}
		seenDom[ascii] = true

		det := DomainCheckDetail{
			RawDomain:     rawD,
			ASCIIDomain:   ascii,
			DisplayDomain: disp,
			IsIDN:         ascii != disp,
		}
		ips, lerr := LookupDomainIPsMultiResolver(ascii)
		if lerr != nil {
			det.LookupError = lerr.Error()
			res.Warnings = append(res.Warnings, lerr.Error())
		} else {
			det.ResolvedIPs = ips
			for _, rip := range ips {
				if parsedIP != nil && net.ParseIP(rip) != nil && net.ParseIP(rip).Equal(parsedIP) {
					det.MatchesInputIP = true
				}
				if res.DetectedExternalIP != "" && rip == res.DetectedExternalIP && isPrivate {
					det.MatchesInputIP = true
				}
			}
			if ipValid && !isPrivate && !det.MatchesInputIP {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("Внимание: домен %s в DNS указывает на [%s], а в форме указан IP %s!", disp, strings.Join(ips, ", "), res.InputIP))
			}
		}
		res.Domains = append(res.Domains, det)
	}

	httpPort := req.HTTPPort
	if httpPort <= 0 {
		httpPort = 80
	}
	tlsPort := req.TLSPort
	if tlsPort <= 0 {
		tlsPort = 443
	}
	res.Port80 = TestPortBind(bindIP, httpPort)
	res.Port443 = TestPortBind(bindIP, tlsPort)

	if !res.Port80.CanBind && (req.ChallengeType == "" || req.ChallengeType == "http-01") && req.Mode != "selfsigned" {
		res.Recommendations = append(res.Recommendations,
			"Если порт 80 занят службой KerioMailServer, включите галочку «Автоматически остановить KerioMailServer на время проверки порта 80 (5–15 сек)» или выберите подтверждение через DNS-01 (TXT-запись).")
	}

	res.Valid = len(res.Domains) > 0 || (ipValid && (!isPrivate || req.Mode == "selfsigned"))
	return res
}
