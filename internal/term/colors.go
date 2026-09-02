package term

import (
	"fmt"
	"os"
)

type palette struct {
	reset, yellow, cyan, green, red, dim, bold string
}

var p = palette{
	reset:  "\033[0m",
	yellow: "\033[1;33m",
	cyan:   "\033[0;36m",
	green:  "\033[0;32m",
	red:    "\033[0;31m",
	dim:    "\033[2m",
	bold:   "\033[1m",
}

func init() {
	if os.Getenv("NO_COLOR") != "" {
		p = palette{}
	}
}

func Yellow(format string, args ...any) {
	fmt.Printf(p.yellow+format+p.reset, args...)
}

func Cyan(format string, args ...any) {
	fmt.Printf(p.cyan+format+p.reset, args...)
}

func Green(format string, args ...any) {
	fmt.Printf(p.green+format+p.reset, args...)
}

func Red(format string, args ...any) {
	fmt.Printf(p.red+format+p.reset, args...)
}

func Dim(format string, args ...any) {
	fmt.Printf(p.dim+format+p.reset, args...)
}

func YellowBold(format string, args ...any) {
	fmt.Printf(p.bold+p.yellow+format+p.reset, args...)
}

func YellowPrintln(s string) {
	fmt.Println(p.yellow + s + p.reset)
}

func CyanPrintln(s string) {
	fmt.Println(p.cyan + s + p.reset)
}

func GreenPrintln(s string) {
	fmt.Println(p.green + s + p.reset)
}

func RedPrintln(s string) {
	fmt.Println(p.red + s + p.reset)
}

func DimPrintln(s string) {
	fmt.Println(p.dim + s + p.reset)
}
