package main

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	drRoot     = `C:\tools\DynamoRIO`
	drRun      = `C:\tools\DynamoRIO\bin32\drrun.exe`
	targetName = "vuln3.exe"
	configName = "config_3"
	runTimeout = 15 * time.Second
)

func main() {
	if runtime.GOARCH != "386" {
		fmt.Println("Фаззер собран не как 32-битный. Нужна сборка GOARCH=386, иначе регистры цели читаются неверно.")
		os.Exit(1)
	}
	root, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	exe := filepath.Join(root, targetName)
	cfg := filepath.Join(root, configName)
	original := filepath.Join(root, "..", "source", configName)
	if _, err := os.Stat(cfg); err != nil {
		if err := copyFile(original, cfg); err != nil {
			fmt.Println("нет рабочего config_3:", err)
			os.Exit(1)
		}
	}
	app := &app{
		root:     root,
		exe:      exe,
		cfg:      cfg,
		original: original,
		store:    NewStore(root),
		in:       bufio.NewReader(os.Stdin),
	}
	if err := app.loop(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type app struct {
	root     string
	exe      string
	cfg      string
	original string
	store    *Store
	in       *bufio.Reader
	buf      []byte
}

func (a *app) loop() error {
	var err error
	a.buf, err = loadFile(a.cfg)
	if err != nil {
		return err
	}
	fmt.Println("Фаззер vuln3. Исходный конфиг можно вернуть пунктом 10.")
	for {
		fmt.Print(`
1  показать конфиг
2  заменить один байт
3  заменить несколько байт
4  дописать байты в конец
5  авторежим: последовательная замена граничными значениями
6  один запуск цели
7  найти разделители , : = ;
8  расширить поле после /start
9  режим с покрытием
10 вернуть исходный config_3
11 выход
> `)
		line, err := a.readLine()
		if err != nil {
			return err
		}
		switch strings.TrimSpace(line) {
		case "1":
			a.show()
		case "2":
			a.oneByte()
		case "3":
			a.manyBytes()
		case "4":
			a.appendBytes()
		case "5":
			a.autoMode()
		case "6":
			a.oneRun()
		case "7":
			a.separators()
		case "8":
			a.expand()
		case "9":
			a.coverageMode()
		case "10":
			a.restore()
		case "11":
			return nil
		default:
			fmt.Println("нет такого пункта")
		}
	}
}

func (a *app) show() {
	at := indexOf(a.buf, []byte("/start"))
	fmt.Printf("размер %d байт, /start смещение %d\n", len(a.buf), at)
	n := len(a.buf)
	if n > 64 {
		n = 64
	}
	fmt.Printf("первые %d байт: %X\n", n, a.buf[:n])
}

func (a *app) oneByte() {
	off, ok := a.askInt("смещение")
	if !ok {
		return
	}
	b, ok := a.askByte("байт (например FF)")
	if !ok {
		return
	}
	next, change, err := ReplaceOne(a.buf, off, b)
	if err != nil {
		fmt.Println(err)
		return
	}
	a.commit(next, change)
}

func (a *app) manyBytes() {
	off, ok := a.askInt("смещение")
	if !ok {
		return
	}
	n, ok := a.askInt("сколько байт")
	if !ok || n < 1 {
		fmt.Println("нужна длина больше нуля")
		return
	}
	value := make([]byte, n)
	for i := 0; i < n; i++ {
		b, ok := a.askByte(fmt.Sprintf("байт %d", i))
		if !ok {
			return
		}
		value[i] = b
	}
	next, change, err := ReplaceMany(a.buf, off, value)
	if err != nil {
		fmt.Println(err)
		return
	}
	a.commit(next, change)
}

func (a *app) appendBytes() {
	n, ok := a.askInt("сколько байт дописать")
	if !ok || n < 1 {
		return
	}
	b, ok := a.askByte("каким байтом")
	if !ok {
		return
	}
	extra := make([]byte, n)
	for i := range extra {
		extra[i] = b
	}
	next, change := AppendBytes(a.buf, extra)
	a.commit(next, change)
}

func (a *app) autoMode() {
	width, ok := a.askInt("ширина граничного значения 1..4, 0 = все")
	if !ok {
		return
	}
	limit, ok := a.askInt("максимум запусков, 0 = весь проход")
	if !ok {
		return
	}
	original := cloneBytes(a.buf)
	runs := 0
	widths := []int{width}
	if width == 0 {
		widths = []int{1, 2, 3, 4}
	}
	for _, w := range widths {
		if w < 1 || w > 4 {
			fmt.Println("ширина должна быть от 1 до 4")
			return
		}
		for _, value := range BoundaryValues(w) {
			for off := 0; off+len(value) <= len(original); off++ {
				if limit > 0 && runs >= limit {
					a.finishPass(original, runs)
					return
				}
				next, change, err := ReplaceMany(original, off, value)
				if err != nil {
					fmt.Println(err)
					return
				}
				if err := a.tryOnce(next, change, false); err != nil {
					fmt.Println(err)
				}
				runs++
				if runs%20 == 0 {
					fmt.Printf("авторежим: %d запусков\n", runs)
				}
			}
		}
	}
	a.finishPass(original, runs)
}

func (a *app) finishPass(original []byte, runs int) {
	a.buf = original
	if err := writeFile(a.cfg, original); err != nil {
		fmt.Println(err)
	}
	fmt.Printf("авторежим закончен, запусков %d, рабочий конфиг возвращён\n", runs)
}

func (a *app) oneRun() {
	change := Change{Text: "ручной запуск текущего конфига"}
	if err := a.tryOnce(a.buf, change, true); err != nil {
		fmt.Println(err)
	}
}

func (a *app) separators() {
	hits := FindSeparators(a.buf)
	any := false
	for _, sep := range []byte{',', ':', '=', ';'} {
		if len(hits[sep]) == 0 {
			fmt.Printf("%q не найден\n", sep)
			continue
		}
		any = true
		fmt.Printf("%q смещения:", sep)
		for _, off := range hits[sep] {
			fmt.Printf(" %d", off)
		}
		fmt.Println()
	}
	if !any {
		fmt.Println("в текущем конфиге разделителей полей нет")
	}
}

func (a *app) expand() {
	n, ok := a.askInt("на сколько байт удлинить поле")
	if !ok || n < 1 {
		return
	}
	extra := make([]byte, n)
	for i := range extra {
		extra[i] = 'A'
	}
	next, change, err := ExpandField(a.buf, extra)
	if err != nil {
		fmt.Println(err)
		return
	}
	a.commit(next, change)
}

func (a *app) coverageMode() {
	n, ok := a.askInt("сколько итераций")
	if !ok || n < 1 {
		return
	}
	original := cloneBytes(a.buf)
	if err := writeFile(a.cfg, original); err != nil {
		fmt.Println(err)
		return
	}
	base, err := measureCoverage(a.exe, a.root, filepath.Join(a.root, "cov"))
	if err != nil {
		fmt.Println(err)
		return
	}
	a.store.Remember(base)
	fmt.Printf("базовое покрытие: %d блоков vuln3.exe\n", len(base))
	seeds := [][]byte{original}
	for i := 0; i < n; i++ {
		parent := seeds[rand.IntN(len(seeds))]
		next, change := randomMutation(parent)
		crashed, err := a.exec(next, change)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if crashed {
			continue
		}
		blocks, err := measureCoverage(a.exe, a.root, filepath.Join(a.root, "cov"))
		if err != nil {
			fmt.Println(err)
			continue
		}
		fresh := a.store.Remember(blocks)
		if len(fresh) == 0 {
			continue
		}
		saved := cloneBytes(next)
		seeds = append(seeds, saved)
		path, err := a.store.SaveSeed(saved, len(fresh))
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("новые блоки +%d, всего %d, сид %s\n", len(fresh), a.store.SeenCount(), path)
	}
	a.buf = original
	if err := writeFile(a.cfg, original); err != nil {
		fmt.Println(err)
	}
	fmt.Printf("режим покрытия закончен, уникальных блоков %d\n", a.store.SeenCount())
}

func randomMutation(buf []byte) ([]byte, Change) {
	switch rand.IntN(3) {
	case 0:
		values := BoundaryValues(1 + rand.IntN(4))
		value := values[rand.IntN(len(values))]
		if len(buf) < len(value) {
			return AppendBytes(buf, []byte{'A'})
		}
		off := rand.IntN(len(buf) - len(value) + 1)
		next, change, err := ReplaceMany(buf, off, value)
		if err != nil {
			return AppendBytes(buf, []byte{'A'})
		}
		return next, change
	case 1:
		n := 1 + rand.IntN(32)
		extra := make([]byte, n)
		for i := range extra {
			extra[i] = byte(1 + rand.IntN(255))
		}
		return AppendBytes(buf, extra)
	default:
		n := 1 + rand.IntN(24)
		extra := make([]byte, n)
		for i := range extra {
			extra[i] = 'A'
		}
		next, change, err := ExpandField(buf, extra)
		if err != nil {
			return AppendBytes(buf, extra)
		}
		return next, change
	}
}

func (a *app) commit(next []byte, change Change) {
	a.buf = next
	if err := writeFile(a.cfg, next); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(change.Text)
}

func (a *app) tryOnce(data []byte, change Change, withCoverage bool) error {
	_, err := a.exec(data, change)
	if err != nil || !withCoverage {
		return err
	}
	blocks, err := measureCoverage(a.exe, a.root, filepath.Join(a.root, "cov"))
	if err != nil {
		return err
	}
	fresh := a.store.Remember(blocks)
	fmt.Printf("покрытие %d блоков, новых %d\n", len(blocks), len(fresh))
	return nil
}

func (a *app) exec(data []byte, change Change) (bool, error) {
	if err := writeFile(a.cfg, data); err != nil {
		return false, err
	}
	if err := a.store.Log(change.Text); err != nil {
		return false, err
	}
	crash, err := RunDebug(a.exe, a.root, runTimeout)
	if err != nil {
		return false, err
	}
	if crash == nil {
		return false, nil
	}
	path, err := a.store.SaveCrash(data, crash, change.Text)
	if err != nil {
		return true, err
	}
	fmt.Printf("падение %08X, лог %s.log\n", crash.Code, path)
	return true, nil
}

func (a *app) restore() {
	data, err := loadFile(a.original)
	if err != nil {
		fmt.Println(err)
		return
	}
	a.buf = data
	if err := writeFile(a.cfg, data); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("config_3 возвращён из source")
}

func (a *app) askInt(label string) (int, bool) {
	fmt.Printf("%s: ", label)
	line, err := a.readLine()
	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		fmt.Println("нужно целое число")
		return 0, false
	}
	return n, true
}

func (a *app) askByte(label string) (byte, bool) {
	fmt.Printf("%s: ", label)
	line, err := a.readLine()
	if err != nil {
		fmt.Println(err)
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(line), 16, 8)
	if err != nil {
		fmt.Println("нужен байт в шестнадцатеричном виде, например FF")
		return 0, false
	}
	return byte(n), true
}

func (a *app) readLine() (string, error) {
	line, err := a.in.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}
