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

type JSONLWriter struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
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
