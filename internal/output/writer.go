package output

import (
	"fmt"
	"io"
	"os"
)

// Writer writes subdomains to stdout and optionally to a file (tee-like).
type Writer struct {
	file *os.File
}

func NewWriter(path string) (*Writer, error) {
	if path == "" {
		return &Writer{}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &Writer{file: f}, nil
}

func (w *Writer) Write(subdomain string) {
	fmt.Println(subdomain)
	if w.file != nil {
		fmt.Fprintln(w.file, subdomain)
	}
}

func (w *Writer) WriteAll(subdomains []string) {
	for _, s := range subdomains {
		w.Write(s)
	}
}

func (w *Writer) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// WriteTo writes lines to an arbitrary writer.
func WriteTo(w io.Writer, lines []string) error {
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}
