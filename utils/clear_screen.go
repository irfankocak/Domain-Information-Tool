package utils

import (
	"os"
	"os/exec"
	"runtime"
)

// ClearScreen clears the console screen based on the operating system
func ClearScreen() {
	clear := map[string]func(){
		"linux": func() {
			cmd := exec.Command("clear")
			cmd.Stdout = os.Stdout
			cmd.Run()
		},
		"windows": func() {
			cmd := exec.Command("cmd", "/c", "cls")
			cmd.Stdout = os.Stdout
			cmd.Run()
		},
	}

	if clearFunc, ok := clear[runtime.GOOS]; ok {
		clearFunc()
	} else {
		panic("unsupported platform")
	}
}
