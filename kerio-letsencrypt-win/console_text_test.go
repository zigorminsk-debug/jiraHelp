package main

// console_text_test.go — проверки расшифровки вывода консольных программ
// Windows и разбора числовых состояний службы.
//
// Зачем: именно здесь раньше появлялись «ромбики» в интерфейсе и ложные
// «exit status 2». Тесты работают на любой ОС (CI гоняет их на Linux), потому
// что декодер и разбор кодов состояний лежат в переносимых файлах.

import (
	"strings"
	"testing"
)

// toCP866 кодирует строку в OEM-кодировку русской консоли Windows — тем же
// способом, каким её печатает net.exe/sc.exe. Нужен, чтобы тест не зависел от
// «магических» байтовых констант.
func toCP866(s string) []byte {
	high := []rune(cp866High)
	index := make(map[rune]byte, len(high))
	for i, r := range high {
		index[r] = byte(0x80 + i)
	}
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 0x80 {
			out = append(out, byte(r))
			continue
		}
		if b, ok := index[r]; ok {
			out = append(out, b)
			continue
		}
		out = append(out, '?')
	}
	return out
}

func TestDecodeWindowsConsoleCP866(t *testing.T) {
	raw := toCP866("Служба KerioMailServer остановлена.")
	got := DecodeWindowsConsole(raw)
	if got != "Служба KerioMailServer остановлена." {
		t.Fatalf("CP866 расшифрован неверно: %q", got)
	}
	if strings.ContainsRune(got, '\uFFFD') {
		t.Fatalf("в результате остались символы-заменители: %q", got)
	}
}

func TestDecodeWindowsConsoleUTF8PassThrough(t *testing.T) {
	const s = "Служба уже запущена"
	if got := DecodeWindowsConsole([]byte(s)); got != s {
		t.Fatalf("валидный UTF-8 не должен перекодироваться: %q", got)
	}
	if got := DecodeWindowsConsole(nil); got != "" {
		t.Fatalf("пустой ввод должен давать пустую строку, получено %q", got)
	}
}

func TestCleanConsoleOutputStripsNetHelpMsg(t *testing.T) {
	raw := append(toCP866("Служба не запущена.\r\n"), toCP866("Дополнительная справка: NET HELPMSG 2185\r\n")...)
	got := CleanConsoleOutput(raw)
	if strings.Contains(strings.ToLower(got), "helpmsg") {
		t.Fatalf("подсказка NET HELPMSG не убрана: %q", got)
	}
	if strings.Contains(got, "Дополнительная справка") {
		t.Fatalf("служебная строка не убрана: %q", got)
	}
	if !strings.Contains(got, "Служба не запущена") {
		t.Fatalf("потерялся основной текст ошибки: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Fatalf("результат должен быть одной строкой для интерфейса: %q", got)
	}
}

func TestCleanConsoleOutputTruncatesLongText(t *testing.T) {
	long := strings.Repeat("очень длинное сообщение службы ", 40)
	got := CleanConsoleOutput([]byte(long))
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("длинный вывод должен обрезаться многоточием, получено %d символов", len([]rune(got)))
	}
	if n := len([]rune(got)); n > 401 {
		t.Fatalf("после обрезки %d рун — больше 401", n)
	}
}

func TestParseScStateCode(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		want   int
		wantOK bool
	}{
		{"running", "SERVICE_NAME: KerioMailServer\n        TYPE               : 110  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n", 4, true},
		{"stopped", "  STATE : 1 STOPPED", 1, true},
		{"paused", "STATE : 7  PAUSED", 7, true},
		{"localized words ignored", "STATE : 4  РАБОТАЕТ", 4, true},
		{"no state line", "SERVICE_NAME: KerioMailServer", 0, false},
		{"garbage", "STATE : RUNNING", 0, false},
	}
	for _, c := range cases {
		got, ok := parseScStateCode(c.input)
		if ok != c.wantOK || got != c.want {
			t.Errorf("%s: parseScStateCode(%q) = (%d,%v), ожидалось (%d,%v)", c.name, c.input, got, ok, c.want, c.wantOK)
		}
	}
}
