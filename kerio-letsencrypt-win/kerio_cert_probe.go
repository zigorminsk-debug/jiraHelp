package main

// kerio_cert_probe.go — «🧪 Проверить API сертификатов».
//
// Зачем это нужно. У Kerio Connect два разных набора методов для SSL:
//   - Certificates.*        — Kerio Connect 9.2+ и 10.x (его использует
//                             веб-админка новых сборок: имя, тип сертификата,
//                             импорт PEM + отдельный приватный ключ);
//   - ConnectCertificate.*  — Kerio Connect 8.5–9.1 (без имени и типа).
//
// Набор зависит от сборки, а формальная документация описывает сразу оба,
// поэтому «угадать» интерфейс нельзя — нужно спросить сам сервер. Этот модуль
// спрашивает: перебирает варианты запроса списка сертификатов и проверяет,
// какие методы импорта на сервере вообще существуют. Всё это попадает в
// готовый текстовый отчёт, который пользователь может скопировать одной
// кнопкой и приложить к заявке — без догадок «наверное, нет прав».

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// KerioCertProbeRow — одна проверка (метод + параметры + ответ сервера).
type KerioCertProbeRow struct {
	Method string `json:"method"`
	Params string `json:"params,omitempty"`
	OK     bool   `json:"ok"`
	Kind   string `json:"kind,omitempty"`
	Count  int    `json:"count,omitempty"`
	Note   string `json:"note,omitempty"`
	Error  string `json:"error,omitempty"`
	Raw    string `json:"raw,omitempty"`
}

// KerioCertProbeResult — ответ карточке и готовый отчёт для копирования.
type KerioCertProbeResult struct {
	OK        bool                `json:"ok"`
	Host      string              `json:"host"`
	Port      int                 `json:"port"`
	User      string              `json:"user,omitempty"`
	Product   string              `json:"product,omitempty"`
	Version   string              `json:"version,omitempty"`
	Role      string              `json:"role,omitempty"`
	Interface string              `json:"interface,omitempty"`
	Rows      []KerioCertProbeRow `json:"rows"`
	Summary   string              `json:"summary"`
	Report    string              `json:"report"`
}

// certProbeParams печатает параметры запроса в человекочитаемом виде.
func certProbeParams(params any) string {
	if params == nil {
		return "без параметров"
	}
	b, err := json.Marshal(params)
	if err != nil {
		return fmt.Sprint(params)
	}
	return truncateText(string(b), 120)
}

// ProbeKerioCertificateAPI проверяет, какие методы сертификатов реально есть
// на сервере, и возвращает сырые ответы Kerio. Ничего не меняет на сервере:
// методы импорта вызываются без параметров — сервер отвечает «invalid params»,
// если метод существует, и «method not found», если его нет.
func ProbeKerioCertificateAPI(host string, port int, user, password, domainHint string) KerioCertProbeResult {
	host, port = NormalizeKerioHost(host, port)
	res := KerioCertProbeResult{Host: host, Port: port, User: strings.TrimSpace(user)}
	ep := KerioEndpoint{Host: host, Port: port}

	cli := NewKerioClient(ep)
	if err := cli.Login(user, password, domainHint); err != nil {
		res.Summary = "Вход администратора Kerio не выполнен: " + err.Error()
		res.Report = buildCertProbeReport(res, err.Error())
		return res
	}
	defer cli.Logout()
	res.OK = true
	res.User = cli.User

	if who, err := cli.WhoAmI(); err == nil {
		res.User = firstNonEmpty(who.LoginName, res.User)
		res.Role = who.Role
	}
	if pv, err := cli.ProductVersion(); err == nil {
		res.Product = pv.Product
		res.Version = pv.Version
	}

	// 1. Варианты чтения списка — ровно те же, что использует установка.
	for _, cand := range kerioCertListCandidates() {
		raw, err := cli.rpc(cand.Method, cand.Params)
		row := KerioCertProbeRow{Method: cand.Method, Params: certProbeParams(cand.Params), Note: cand.Note}
		if err != nil {
			row.Kind = kerioErrKind(err)
			row.Error = err.Error()
			row.Raw = truncateText(probeRawOf(err), 400)
			res.Rows = append(res.Rows, row)
			continue
		}
		row.Raw = truncateText(string(raw), 400)
		if certs, ok := parseKerioCertList(raw); ok {
			row.OK = true
			row.Count = len(certs)
			if res.Interface == "" {
				res.Interface = cand.Iface
			}
		} else {
			row.Kind = "protocol"
			row.Error = "ответ не содержит поля certificates"
		}
		res.Rows = append(res.Rows, row)
	}

	// 2. Какие методы импорта существуют. Вызов без параметров безопасен:
	//    сервер либо ругается на параметры (метод есть), либо говорит,
	//    что метода нет. Ни один сертификат при этом не меняется.
	presence := []struct{ method, note string }{
		{"Certificates.importPrivateKey", "современный импорт ключа (Kerio 9.2+/10)"},
		{"Certificates.importCertificate", "современный импорт сертификата"},
		{"Certificates.setActive", "включение сертификата в новом интерфейсе"},
		{"ConnectCertificate.importPrivateKey", "старый импорт ключа (8.5–9.1)"},
		{"ConnectCertificate.importCertificate", "старый импорт сертификата"},
		{"ConnectCertificate.setActive", "включение сертификата в старом интерфейсе"},
	}
	for _, p := range presence {
		_, err := cli.rpc(p.method, nil)
		row := KerioCertProbeRow{Method: p.method, Params: "без параметров (проверка существования)", Note: p.note}
		if err == nil {
			// Метод ответил успехом без параметров — маловероятно, но значит он есть.
			row.OK = true
			row.Raw = "(метод ответил без ошибки)"
			res.Rows = append(res.Rows, row)
			continue
		}
		row.Kind = kerioErrKind(err)
		row.Error = err.Error()
		row.Raw = truncateText(probeRawOf(err), 400)
		if row.Kind == "method" {
			row.Note += " — МЕТОДА НЕТ на этом сервере"
		} else {
			row.OK = true // ... метод есть, просто не хватает параметров
			row.Note += " — метод есть"
		}
		res.Rows = append(res.Rows, row)
	}

	res.Summary = "Проверено " + fmt.Sprint(len(res.Rows)) + " запросов."
	if res.Interface != "" {
		res.Summary += " Рабочий интерфейс списка: " + res.Interface + "."
	} else {
		res.Summary += " Ни один вариант списка сертификатов не сработал."
	}
	res.Report = buildCertProbeReport(res, "")
	return res
}

// probeRawOf достаёт сырой ответ сервера из ошибки Kerio.
func probeRawOf(err error) string {
	var ke *KerioAPIError
	if errors.As(err, &ke) && ke != nil {
		return ke.Raw
	}
	return ""
}

// buildCertProbeReport собирает текст отчёта: его копируют в заявку, поэтому
// он должен читаться без программы и без догадок.
func buildCertProbeReport(res KerioCertProbeResult, loginErr string) string {
	var b strings.Builder
	b.WriteString("KerioCertManager v" + appVersion + " — отчёт по API SSL-сертификатов\n")
	b.WriteString("Сервер: https://" + fmt.Sprintf("%s:%d", res.Host, res.Port) + kerioAdminPath + "\n")
	if res.User != "" {
		b.WriteString("Учётка: " + res.User)
		if res.Role != "" {
			b.WriteString(" (роль: " + res.Role + ")")
		}
		b.WriteString("\n")
	}
	if res.Product != "" || res.Version != "" {
		b.WriteString("Продукт: " + strings.TrimSpace(res.Product+" "+res.Version) + "\n")
	}
	if loginErr != "" {
		b.WriteString("Вход не выполнен: " + loginErr + "\n")
		return b.String()
	}
	b.WriteString("Рабочий интерфейс: " + firstNonEmpty(res.Interface, "не найден") + "\n")
	b.WriteString("──────────────────────────────────────────\n")
	for _, row := range res.Rows {
		mark := "FAIL"
		if row.OK {
			mark = " OK "
		}
		line := fmt.Sprintf("[%s] %s", mark, row.Method)
		if row.Params != "" {
			line += " {" + row.Params + "}"
		}
		if row.Count > 0 {
			line += fmt.Sprintf(" — сертификатов: %d", row.Count)
		}
		b.WriteString(line + "\n")
		if row.Note != "" {
			b.WriteString("       " + row.Note + "\n")
		}
		if row.Error != "" {
			b.WriteString("       ошибка: " + firstLine(row.Error) + "\n")
		}
		if row.Raw != "" && row.Raw != row.Error {
			b.WriteString("       ответ Kerio: " + firstLine(row.Raw) + "\n")
		}
	}
	b.WriteString("──────────────────────────────────────────\n")
	b.WriteString("Итог: " + res.Summary + "\n")
	return b.String()
}

// firstLine оставляет первую строку: отчёты копируют в чат/заявку, и
// многострочные простыни там превращаются в кашу.
func firstLine(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	return truncateText(s, 300)
}
