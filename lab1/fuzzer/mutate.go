package main

import "fmt"

// Change описывает одну правку конфига так, чтобы её можно было записать в лог.
type Change struct {
	Text string
}

func BoundaryValues(width int) [][]byte {
	if width < 1 || width > 4 {
		return nil
	}
	max := (uint64(1) << (8 * uint(width))) - 1
	half := max / 2
	raw := []uint64{0, max, half, half + 1, half - 1}
	out := make([][]byte, 0, len(raw))
	seen := map[uint64]bool{}
	for _, v := range raw {
		if seen[v] {
			continue
		}
		seen[v] = true
		b := make([]byte, width)
		for i := 0; i < width; i++ {
			b[i] = byte(v >> (8 * uint(i)))
		}
		out = append(out, b)
	}
	return out
}

func replaceAt(buf []byte, offset int, value []byte) ([]byte, error) {
	if offset < 0 || offset+len(value) > len(buf) {
		return nil, fmt.Errorf("смещение %d и длина %d не входят в файл размера %d", offset, len(value), len(buf))
	}
	out := append([]byte(nil), buf...)
	copy(out[offset:], value)
	return out, nil
}

func ReplaceOne(buf []byte, offset int, b byte) ([]byte, Change, error) {
	next, err := replaceAt(buf, offset, []byte{b})
	if err != nil {
		return nil, Change{}, err
	}
	return next, Change{Text: fmt.Sprintf("один байт: смещение %d, было %02X, стало %02X", offset, buf[offset], b)}, nil
}

func ReplaceMany(buf []byte, offset int, value []byte) ([]byte, Change, error) {
	if len(value) == 0 {
		return nil, Change{}, fmt.Errorf("пустая замена")
	}
	before := append([]byte(nil), buf[offset:offset+len(value)]...)
	next, err := replaceAt(buf, offset, value)
	if err != nil {
		return nil, Change{}, err
	}
	return next, Change{Text: fmt.Sprintf("несколько байт: смещение %d, длина %d, было %X, стало %X", offset, len(value), before, value)}, nil
}

func AppendBytes(buf, extra []byte) ([]byte, Change) {
	out := append(append([]byte(nil), buf...), extra...)
	return out, Change{Text: fmt.Sprintf("допись в конец: %d байт", len(extra))}
}

func FindSeparators(buf []byte) map[byte][]int {
	hits := map[byte][]int{}
	for _, sep := range []byte{',', ':', '=', ';'} {
		hits[sep] = nil
	}
	for i, b := range buf {
		if _, ok := hits[b]; ok {
			hits[b] = append(hits[b], i)
		}
	}
	return hits
}

// ExpandField удлиняет данные, которые программа читает после маркера /start.
// Если после маркера есть разделитель поля, байты вставляются в это поле.
// Иначе они вставляются сразу после /start, а не в хвост файла.
func ExpandField(buf, extra []byte) ([]byte, Change, error) {
	if len(extra) == 0 {
		return nil, Change{}, fmt.Errorf("нечем расширять поле")
	}
	const marker = "/start"
	at := indexOf(buf, []byte(marker))
	if at < 0 {
		return nil, Change{}, fmt.Errorf("в конфиге нет маркера /start")
	}
	insert := at + len(marker)
	seps := FindSeparators(buf[insert:])
	for _, sep := range []byte{',', ':', '=', ';'} {
		if len(seps[sep]) == 0 {
			continue
		}
		insert = insert + seps[sep][0] + 1
		break
	}
	out := make([]byte, 0, len(buf)+len(extra))
	out = append(out, buf[:insert]...)
	out = append(out, extra...)
	out = append(out, buf[insert:]...)
	return out, Change{Text: fmt.Sprintf("расширение поля: %d байт со смещения %d", len(extra), insert)}, nil
}

func indexOf(buf, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(buf) {
		return -1
	}
	for i := 0; i+len(needle) <= len(buf); i++ {
		match := true
		for j := range needle {
			if buf[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
