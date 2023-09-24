package output

import (
	"fmt"
)

const (
	reset  = "\033[0m"
	red    = "\033[31m"
	yellow = "\033[33m"
)

// Print to Stdout.
func Print(a any) (int, error) {
	return fmt.Print(a)
}

// Print to Stdout with an added newline.
func Println(a any) (int, error) {
	return fmt.Println(a)
}

// PrintError prints colour coded to Stdout.
func PrintError(a any) (int, error) {
	return fmt.Println(red, a, reset)
}

// PrintErrorln prints colour coded to Stdout with an added newline.
func PrintErrorln(a any) (int, error) {
	return fmt.Println(red, a, reset)
}

// PrintEmptyln prints an empty line.
func PrintEmptyln() (int, error) {
	return fmt.Println()
}
