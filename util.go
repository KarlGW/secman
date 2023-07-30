package secman

import (
	"bytes"
	"encoding/gob"
)

// encodeToGob encodes the provided value to a gob.
func encodeToGob(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeFromGob decodes the provided data to the provided value.
func decodeFromGob(data []byte, v any) error {
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)
	return decoder.Decode(v)
}
