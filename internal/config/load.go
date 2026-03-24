package config

import (
	"bytes"
	"fmt"
	"os"

	"danglr/internal/providers"

	"gopkg.in/yaml.v3"
)

func LoadProviders(path string, strict bool) (providers.Root, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return providers.Root{}, err
	}
	return ParseProviders(data, strict)
}

func ParseProviders(data []byte, strict bool) (providers.Root, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(strict)

	var root providers.Root
	if err := decoder.Decode(&root); err != nil {
		return providers.Root{}, fmt.Errorf("decode providers yaml: %w", err)
	}
	if err := root.Validate(); err != nil {
		return providers.Root{}, err
	}
	return root, nil
}

func MarshalProviders(root providers.Root) ([]byte, error) {
	return yaml.Marshal(root)
}
