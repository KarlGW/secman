package gob

import (
	"bytes"
	"encoding/gob"
)

// Encode encodes the provided value to a gob.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode decodes the provided data to the provided value.
func Decode(data []byte, v any) error {
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)
	return decoder.Decode(v)
}
