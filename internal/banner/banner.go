package banner

import (
	"fmt"
	"strings"

	"github.com/kiurakku/GramFuzz/internal/term"
)

const Version = "0.3.0"

const asciiLogo = `
   ██████╗ ██████╗  █████╗ ███╗   ███╗███████╗██╗   ██╗███████╗███████╗
  ██╔════╝ ██╔══██╗██╔══██╗████╗ ████║██╔════╝██║   ██║╚══███╔╝██╔════╝
  ██║  ███╗██████╔╝███████║██╔████╔██║█████╗  ██║   ██║  ███╔╝ █████╗  
  ██║   ██║██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║   ██║ ███╔╝  ██╔══╝  
  ╚██████╔╝██║  ██║██║  ██║██║ ╚═╝ ██║██║     ╚██████╔╝███████╗███████╗
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝`

const tagline = "Ethical DAST Framework for Telegram Bots & Mini Apps"

func Print() {
	term.YellowPrintln(asciiLogo)
	fmt.Println()
	term.CyanPrintln("  " + tagline)
	term.Dim("  v%s  •  github.com/kiurakku/GramFuzz  •  Authorized Testing Only\n", Version)
	fmt.Println()
	term.DimPrintln("  ─────────────────────────────────────────────────────────────────")
	fmt.Println()
}

func Compact() string {
	return fmt.Sprintf("GramFuzz v%s", Version)
}

func Divider(title string) {
	padding := 62 - len(title)
	if padding < 4 {
		padding = 4
	}
	left := padding / 2
	right := padding - left
	line := strings.Repeat("─", left) + " " + title + " " + strings.Repeat("─", right)
	term.YellowBold("%s\n", line)
	fmt.Println()
}
