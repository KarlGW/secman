package output

import (
	"io"
	"os"
)

// output is a structure containing a writer.
type output struct {
	writer io.Writer
}

// Print the provided bytes to the configured io.Writer.
func (o output) Print(b []byte) (int, error) {
	return o.writer.Write(append(b, '\n'))
}

// defaultOutput is the default package level output handler.
var defaultOutput = output{
	writer: os.Stdout,
}

// Print the provided bytes to Stdout.
func Print(b []byte) (int, error) {
	return defaultOutput.Print(b)
}
