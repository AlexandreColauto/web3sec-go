package validation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// ParseOrdered decodes JSON into an ordered Value, preserving object key
// order (the on-disk writer and the schema file-order walk depend on it)
// and the int vs float distinction (json.Number, as in CPython's json.load).
func ParseOrdered(data []byte) (Value, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return VNull(), fmt.Errorf("json: %w", err)
	}
	v, err := parseValue(dec, tok)
	if err != nil {
		return VNull(), err
	}
	if _, err := dec.Token(); err != io.EOF {
		return VNull(), fmt.Errorf("json: data after top-level value")
	}
	return v, nil
}

// parseValue consumes a value whose first token is already known.
func parseValue(dec *json.Decoder, tok json.Token) (Value, error) {
	switch t := tok.(type) {
	case nil:
		return VNull(), nil
	case bool:
		return VBool(t), nil
	case string:
		return VStr(t), nil
	case json.Number:
		s := string(t)
		if isJSONInt(s) {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return VInt(i), nil
			}
			// exceeds int64: Python ints are arbitrary precision, keep
			// the exact decimal text
			return VBigInt(s), nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return VNull(), fmt.Errorf("json: cannot parse number %q", s)
		}
		return VFloat(f), nil
	case json.Delim:
		switch t {
		case '{':
			v := Value{Kind: Obj}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return VNull(), err
				}
				key, ok := keyTok.(string)
				if !ok {
					return VNull(), fmt.Errorf("json: object key is %v, not string", keyTok)
				}
				valTok, err := dec.Token()
				if err != nil {
					return VNull(), err
				}
				val, err := parseValue(dec, valTok)
				if err != nil {
					return VNull(), err
				}
				v.O = append(v.O, KV{K: key, V: val})
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return VNull(), err
			}
			return v, nil
		case '[':
			v := Value{Kind: Arr}
			for dec.More() {
				itemTok, err := dec.Token()
				if err != nil {
					return VNull(), err
				}
				item, err := parseValue(dec, itemTok)
				if err != nil {
					return VNull(), err
				}
				v.A = append(v.A, item)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return VNull(), err
			}
			return v, nil
		}
	}
	return VNull(), fmt.Errorf("json: unexpected token %v", tok)
}
