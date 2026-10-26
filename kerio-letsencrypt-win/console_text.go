package main

// console_text.go — декодирование вывода консольных программ Windows.
//
// Зачем: net.exe, sc.exe и schtasks.exe пишут в OEM-кодировке консоли
// (на русской Windows это CP866), а интерфейс у нас в UTF-8. Раньше такие
// сообщения попадали в UI как есть — пользователь видел «Служба ─ ─ ─» и
// ромбики вместо букв. Здесь мы приводим вывод к нормальному тексту.
//
// Декодер нарочно «мягкий»: если в байтах уже валидный UTF-8 (PowerShell 7,
// chcp 65001, современные утилиты) — возвращаем строку без изменений.

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// cp866High и cp1251High — таблицы для байтов 0x80..0xFF.
const (
	cp866High  = `АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№¤■\u00A0`
	cp1251High = `ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—\uFFFD™љ›њќћџ\u00A0ЎўЈ¤Ґ¦§Ё©Є«¬­®Ї°±Ііґµ¶·ё№є»јЅѕїАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя`
)

// decodeByteTable переводит «верхнюю половину» таблицы в строку.
func decodeByteTable(b []byte, table string) string {
	runes := []rune(table)
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		switch {
		case c < 0x80:
			sb.WriteByte(c)
		case int(c)-0x80 < len(runes):
			sb.WriteRune(runes[int(c)-0x80])
		default:
			sb.WriteRune('\uFFFD')
		}
	}
	return sb.String()
}

// isMostlyCP866 — эвристика на случай, когда байты не сложились в UTF-8:
// в CP866 русский текст занимает 0x80–0xAF и 0xE0–0xEF, а в CP1251 —
// в основном 0xC0–0xFF. Считаем, какая таблица даст больше кириллицы.
func isMostlyCP866(b []byte) bool {
	high866, high1251 := 0, 0
	for _, c := range b {
		switch {
		case c >= 0xE0:
			high866++
		case c >= 0xC0:
			high1251++
		case c >= 0x80:
			high866++
		}
	}
	return high866 > high1251
}

// DecodeWindowsConsole превращает вывод консольной утилиты Windows в UTF-8.
//
// Правило простое и безопасное: если байты уже складываются в валидный UTF-8,
// возвращаем их как есть (ничего не портим). Иначе выбираем OEM-таблицу по
// эвристике выше — на русской Windows консоль отдаёт CP866.
func DecodeWindowsConsole(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	trimmed := strings.TrimRight(string(raw), "\x00")
	if utf8.ValidString(trimmed) {
		return trimmed
	}
	if isMostlyCP866(raw) {
		return decodeByteTable(raw, cp866High)
	}
	return decodeByteTable(raw, cp1251High)
}

// CleanConsoleOutput — декодирует вывод и убирает служебные хвосты, которые
// Windows добавляет к ошибкам («Дополнительная справка: NET HELPMSG 2185»),
// чтобы в интерфейсе не было мусора.
func CleanConsoleOutput(raw []byte) string {
	s := DecodeWindowsConsole(raw)
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		low := strings.ToLower(l)
		if strings.Contains(low, "net helpmsg") ||
			strings.Contains(low, "more help is available") ||
			strings.Contains(low, "дополнительная справка") ||
			strings.Contains(low, "дополнительную справку") {
			continue
		}
		kept = append(kept, l)
	}
	out := strings.Join(kept, " ")
	out = strings.Join(strings.Fields(out), " ")
	if len([]rune(out)) > 400 {
		out = string([]rune(out)[:400]) + "…"
	}
	return out
}

// parseScStateCode достаёт числовой код состояния из вывода `sc query`
// («STATE : 4 RUNNING»). Код, а не слово: на разных локалях sc.exe печатает
// подпись по-разному, а цифра одна и та же (1 STOPPED, 4 RUNNING, 7 PAUSED).
// Функция живёт в переносимом файле, чтобы её можно было проверить тестами
// на любой ОС — CI собирает и прогоняет тесты на Linux.
func parseScStateCode(out string) (int, bool) {
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "STATE") {
			continue
		}
		colon := strings.Index(trimmed, ":")
		if colon < 0 {
			continue
		}
		fields := strings.Fields(trimmed[colon+1:])
		if len(fields) == 0 {
			continue
		}
		code, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		return code, true
	}
	return 0, false
}
