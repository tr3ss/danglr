package output

import (
	"encoding/json"
	"os"
	"sync"
)

type Writer interface {
	Write(v any) error
	Close() error
}

type DiscardWriter struct{}

type JSONLWriter struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

type StdoutWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewJSONLWriter(path string) (*JSONLWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &JSONLWriter{file: f, enc: enc}, nil
}

func NewStdoutWriter() *StdoutWriter {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return &StdoutWriter{enc: enc}
}

func NewDiscardWriter() *DiscardWriter {
	return &DiscardWriter{}
}

func (w *DiscardWriter) Write(v any) error {
	return nil
}

func (w *DiscardWriter) Close() error {
	return nil
}

func (w *StdoutWriter) Write(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(v)
}

func (w *StdoutWriter) Close() error {
	return nil
}

func (w *JSONLWriter) Write(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(v)
}

func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
