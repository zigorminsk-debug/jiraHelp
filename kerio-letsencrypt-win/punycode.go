package main

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 0x80
)

// NormalizeDomain cleans a user-entered domain name and converts IDN labels (e.g. .бел, .рф) to ASCII Punycode.
func NormalizeDomain(raw string) (ascii string, unicodeDisplay string, err error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexAny(s, "/:?#"); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" {
		return "", "", nil
	}

	labels := strings.Split(s, ".")
	asciiLabels := make([]string, 0, len(labels))
	displayLabels := make([]string, 0, len(labels))

	for _, label := range labels {
		if label == "" {
			return "", "", fmt.Errorf("некорректное доменное имя %q (пустая метка)", raw)
		}
		displayLabels = append(displayLabels, label)
		if isASCII(label) {
			if !validLDHLabel(label) {
				return "", "", fmt.Errorf("недопустимые символы в доменном имени %q", raw)
			}
			asciiLabels = append(asciiLabels, label)
			continue
		}
		encoded, err := punycodeEncode(label)
		if err != nil {
			return "", "", fmt.Errorf("ошибка Punycode-кодирования %q: %w", label, err)
		}
		asciiLabel := "xn--" + encoded
		if !validLDHLabel(asciiLabel) {
			return "", "", fmt.Errorf("некорректная IDN-метка %q", label)
		}
		asciiLabels = append(asciiLabels, asciiLabel)
	}

	if len(asciiLabels) < 2 {
		return "", "", fmt.Errorf("укажите полное доменное имя (например, mail.company.by), получено %q", raw)
	}
	return strings.Join(asciiLabels, "."), strings.Join(displayLabels, "."), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func validLDHLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if label == "*" {
		return true
	}
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

func adaptBias(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (((punyBase-punyTMin+1)*delta)/(delta+punySkew))
}

func encodeDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + (d - 26))
}

func punycodeEncode(input string) (string, error) {
	runes := []rune(input)
	var output []byte
	for _, r := range runes {
		if r < 0x80 {
			output = append(output, byte(r))
		}
	}
	basicLen := len(output)
	handled := basicLen
	if basicLen > 0 {
		output = append(output, '-')
	}

	n := punyInitialN
	delta := 0
	bias := punyInitialBias

	for handled < len(runes) {
		m := math.MaxInt32
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if m-n > (math.MaxInt32-delta)/(handled+1) {
			return "", fmt.Errorf("переполнение буфера Punycode")
		}
		delta += (m - n) * (handled + 1)
		n = m

		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := punyBase; ; k += punyBase {
					t := k - bias
					if t < punyTMin {
						t = punyTMin
					} else if t > punyTMax {
						t = punyTMax
					}
					if q < t {
						break
					}
					digit := t + ((q - t) % (punyBase - t))
					output = append(output, encodeDigit(digit))
					q = (q - t) / (punyBase - t)
				}
				output = append(output, encodeDigit(q))
				bias = adaptBias(delta, handled+1, handled == basicLen)
				delta = 0
				handled++
			}
		}
		delta++
		n++
	}
	return string(output), nil
}
