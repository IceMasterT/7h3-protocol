// Package protocol7h3 — minimal deterministic CBOR encoder/decoder for ProtocolEnvelope.
// No external dependencies. Follows RFC 8949 §4.2 deterministic encoding.
//
// Envelope numeric field key scheme (matches TypeScript envelopeCbor.ts):
//   Top-level: 1=header, 2=body, 3=signature(optional)
//   Header:    1=version, 2=messageId, 3=timestampMs, 4=ttlMs, 5=sender, 6=recipient(opt), 7=nonce
//   Body:      1=intent, 2=content, 3=capability(opt), 4=correlationId(opt)
//   Signature: 1=alg, 2=keyId, 3=value
package protocol7h3

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

// CBOR major types
const (
	cborMTUint   = 0
	cborMTNint   = 1
	cborMTBstr   = 2
	cborMTTstr   = 3
	cborMTArray  = 4
	cborMTMap    = 5
	cborMTSimple = 7
)

// Additional info values
const (
	cborAI1Byte = 24
	cborAI2Byte = 25
	cborAI4Byte = 26
	cborAI8Byte = 27
)

// Simple values
const (
	cborFalse   = 0xf4
	cborTrue    = 0xf5
	cborNull    = 0xf6
	cborFloat64 = 0xfb
)

// ─── encoder ────────────────────────────────────────────────────────────────

type cborEncoder struct {
	buf []byte
}

func (e *cborEncoder) encodeHead(mt int, val uint64) {
	base := byte(mt << 5)
	switch {
	case val <= 23:
		e.buf = append(e.buf, base|byte(val))
	case val <= 0xff:
		e.buf = append(e.buf, base|cborAI1Byte, byte(val))
	case val <= 0xffff:
		e.buf = append(e.buf, base|cborAI2Byte, byte(val>>8), byte(val))
	case val <= 0xffffffff:
		b := [4]byte{}
		binary.BigEndian.PutUint32(b[:], uint32(val))
		e.buf = append(e.buf, base|cborAI4Byte)
		e.buf = append(e.buf, b[:]...)
	default:
		b := [8]byte{}
		binary.BigEndian.PutUint64(b[:], val)
		e.buf = append(e.buf, base|cborAI8Byte)
		e.buf = append(e.buf, b[:]...)
	}
}

func (e *cborEncoder) encodeUint(v uint64) {
	e.encodeHead(cborMTUint, v)
}

func (e *cborEncoder) encodeText(s string) {
	b := []byte(s)
	e.encodeHead(cborMTTstr, uint64(len(b)))
	e.buf = append(e.buf, b...)
}

func (e *cborEncoder) encodeFloat64(f float64) {
	e.buf = append(e.buf, cborFloat64)
	b := [8]byte{}
	binary.BigEndian.PutUint64(b[:], math.Float64bits(f))
	e.buf = append(e.buf, b[:]...)
}

// encodedKeyForUint returns the CBOR encoding of an unsigned integer key (for sorting).
func encodedKeyForUint(v uint64) []byte {
	tmp := &cborEncoder{}
	tmp.encodeHead(cborMTUint, v)
	return tmp.buf
}

// encodedKeyForText returns the CBOR encoding of a text string key (for sorting).
func encodedKeyForText(s string) []byte {
	tmp := &cborEncoder{}
	tmp.encodeText(s)
	return tmp.buf
}

type intKV struct {
	key     uint64
	keyEnc  []byte
	value   interface{}
}

// encodeIntMap encodes a map with integer keys deterministically (RFC 8949 §4.2).
func (e *cborEncoder) encodeIntMap(pairs []intKV) {
	// Sort by encoded key bytes (lexicographic)
	sort.Slice(pairs, func(i, j int) bool {
		a, b := pairs[i].keyEnc, pairs[j].keyEnc
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})

	e.encodeHead(cborMTMap, uint64(len(pairs)))
	for _, kv := range pairs {
		e.encodeHead(cborMTUint, kv.key)
		e.encodeAny(kv.value)
	}
}

func (e *cborEncoder) encodeAny(v interface{}) {
	switch val := v.(type) {
	case nil:
		e.buf = append(e.buf, cborNull)
	case bool:
		if val {
			e.buf = append(e.buf, cborTrue)
		} else {
			e.buf = append(e.buf, cborFalse)
		}
	case int:
		if val >= 0 {
			e.encodeHead(cborMTUint, uint64(val))
		} else {
			e.encodeHead(cborMTNint, uint64(-1-val))
		}
	case int64:
		if val >= 0 {
			e.encodeHead(cborMTUint, uint64(val))
		} else {
			e.encodeHead(cborMTNint, uint64(-1-val))
		}
	case uint64:
		e.encodeHead(cborMTUint, val)
	case float64:
		e.encodeFloat64(val)
	case string:
		e.encodeText(val)
	case []byte:
		e.encodeHead(cborMTBstr, uint64(len(val)))
		e.buf = append(e.buf, val...)
	default:
		panic(fmt.Sprintf("cborEncoder: unsupported type %T", v))
	}
}

// ─── decoder ────────────────────────────────────────────────────────────────

type cborDecoder struct {
	data   []byte
	offset int
}

func (d *cborDecoder) remaining() int {
	return len(d.data) - d.offset
}

func (d *cborDecoder) readByte() (byte, error) {
	if d.remaining() < 1 {
		return 0, fmt.Errorf("cbor: unexpected end of data")
	}
	b := d.data[d.offset]
	d.offset++
	return b, nil
}

func (d *cborDecoder) readN(n int) ([]byte, error) {
	if d.remaining() < n {
		return nil, fmt.Errorf("cbor: unexpected end of data")
	}
	out := d.data[d.offset : d.offset+n]
	d.offset += n
	return out, nil
}

func (d *cborDecoder) decodeHead() (mt int, val uint64, err error) {
	b, err := d.readByte()
	if err != nil {
		return 0, 0, err
	}
	mt = int(b >> 5)
	ai := b & 0x1f

	switch {
	case ai <= 23:
		val = uint64(ai)
	case ai == cborAI1Byte:
		nb, err := d.readByte()
		if err != nil {
			return 0, 0, err
		}
		val = uint64(nb)
	case ai == cborAI2Byte:
		nb, err := d.readN(2)
		if err != nil {
			return 0, 0, err
		}
		val = uint64(binary.BigEndian.Uint16(nb))
	case ai == cborAI4Byte:
		nb, err := d.readN(4)
		if err != nil {
			return 0, 0, err
		}
		val = uint64(binary.BigEndian.Uint32(nb))
	case ai == cborAI8Byte:
		nb, err := d.readN(8)
		if err != nil {
			return 0, 0, err
		}
		val = binary.BigEndian.Uint64(nb)
	default:
		return 0, 0, fmt.Errorf("cbor: unsupported additional info %d", ai)
	}
	return mt, val, nil
}

// decodeStringValue decodes a text string from the already-consumed initial byte context.
// The caller has already called decodeHead and got mt=3, val=length.
func (d *cborDecoder) readString(length uint64) (string, error) {
	nb, err := d.readN(int(length))
	if err != nil {
		return "", err
	}
	return string(nb), nil
}

// decodeIntMapFlat decodes a CBOR map with integer keys and string values.
// Returns a map[uint64]string. Handles int and string typed values.
func (d *cborDecoder) decodeIntStringMap() (map[uint64]string, error) {
	mt, count, err := d.decodeHead()
	if err != nil {
		return nil, err
	}
	if mt != cborMTMap {
		return nil, fmt.Errorf("cbor: expected map (mt=5) got mt=%d", mt)
	}

	result := make(map[uint64]string, count)
	for i := uint64(0); i < count; i++ {
		// Decode key (must be uint)
		kmt, kval, err := d.decodeHead()
		if err != nil {
			return nil, err
		}
		if kmt != cborMTUint {
			return nil, fmt.Errorf("cbor: expected uint key got mt=%d", kmt)
		}
		// Decode value — strings or ints
		vmt, vval, err := d.decodeHead()
		if err != nil {
			return nil, err
		}
		switch vmt {
		case cborMTTstr:
			s, err := d.readString(vval)
			if err != nil {
				return nil, err
			}
			result[kval] = s
		case cborMTUint:
			result[kval] = fmt.Sprintf("%d", vval)
		case cborMTNint:
			result[kval] = fmt.Sprintf("%d", -int64(1)-int64(vval))
		default:
			return nil, fmt.Errorf("cbor: unsupported value type mt=%d at key %d", vmt, kval)
		}
	}
	return result, nil
}

// decodeIntMixedMap decodes a CBOR map with uint keys and mixed value types (string or int64).
func (d *cborDecoder) decodeIntMixedMap() (map[uint64]interface{}, error) {
	mt, count, err := d.decodeHead()
	if err != nil {
		return nil, err
	}
	if mt != cborMTMap {
		return nil, fmt.Errorf("cbor: expected map (mt=5) got mt=%d", mt)
	}

	result := make(map[uint64]interface{}, count)
	for i := uint64(0); i < count; i++ {
		kmt, kval, err := d.decodeHead()
		if err != nil {
			return nil, err
		}
		if kmt != cborMTUint {
			return nil, fmt.Errorf("cbor: expected uint key got mt=%d", kmt)
		}
		vmt, vval, err := d.decodeHead()
		if err != nil {
			return nil, err
		}
		switch vmt {
		case cborMTTstr:
			s, err := d.readString(vval)
			if err != nil {
				return nil, err
			}
			result[kval] = s
		case cborMTUint:
			result[kval] = int64(vval)
		case cborMTNint:
			result[kval] = -int64(1) - int64(vval)
		default:
			return nil, fmt.Errorf("cbor: unsupported value type mt=%d at key %d", vmt, kval)
		}
	}
	return result, nil
}

// decodeTopMap decodes the top-level envelope map (uint keys → sub-maps).
// Returns the raw offsets for each sub-map so we can decode them individually.
func (d *cborDecoder) decodeTopLevel() (header map[uint64]interface{}, body map[uint64]interface{}, sig map[uint64]string, err error) {
	mt, count, err := d.decodeHead()
	if err != nil {
		return nil, nil, nil, err
	}
	if mt != cborMTMap {
		return nil, nil, nil, fmt.Errorf("cbor: expected map at top level")
	}

	for i := uint64(0); i < count; i++ {
		kmt, kval, err := d.decodeHead()
		if err != nil {
			return nil, nil, nil, err
		}
		if kmt != cborMTUint {
			return nil, nil, nil, fmt.Errorf("cbor: expected uint key at top level")
		}
		switch kval {
		case 1: // header
			header, err = d.decodeIntMixedMap()
			if err != nil {
				return nil, nil, nil, fmt.Errorf("cbor: decode header: %w", err)
			}
		case 2: // body
			body, err = d.decodeIntMixedMap()
			if err != nil {
				return nil, nil, nil, fmt.Errorf("cbor: decode body: %w", err)
			}
		case 3: // signature (optional)
			sig, err = d.decodeIntStringMap()
			if err != nil {
				return nil, nil, nil, fmt.Errorf("cbor: decode signature: %w", err)
			}
		default:
			return nil, nil, nil, fmt.Errorf("cbor: unknown top-level key %d", kval)
		}
	}
	return header, body, sig, nil
}

// ─── public API ─────────────────────────────────────────────────────────────

// EncodeEnvelopeCBOR encodes a ProtocolEnvelope to CBOR bytes using numeric field keys.
func EncodeEnvelopeCBOR(env ProtocolEnvelope) ([]byte, error) {
	e := &cborEncoder{}

	// Count top-level entries: always header(1) + body(2), optionally sig(3)
	topCount := 2
	if env.Signature != nil {
		topCount = 3
	}
	e.encodeHead(cborMTMap, uint64(topCount))

	// Key 1: header
	e.encodeHead(cborMTUint, 1)
	{
		headerCount := 6 // version, messageId, timestampMs, ttlMs, sender, nonce (always)
		if env.Header.Recipient != "" {
			headerCount = 7
		}
		headerPairs := []intKV{
			{key: 1, keyEnc: encodedKeyForUint(1), value: env.Header.Version},
			{key: 2, keyEnc: encodedKeyForUint(2), value: env.Header.MessageID},
			{key: 3, keyEnc: encodedKeyForUint(3), value: env.Header.TimestampMs},
			{key: 4, keyEnc: encodedKeyForUint(4), value: env.Header.TTLMs},
			{key: 5, keyEnc: encodedKeyForUint(5), value: env.Header.Sender},
			{key: 7, keyEnc: encodedKeyForUint(7), value: env.Header.Nonce},
		}
		if env.Header.Recipient != "" {
			headerPairs = append(headerPairs, intKV{key: 6, keyEnc: encodedKeyForUint(6), value: env.Header.Recipient})
		}
		_ = headerCount
		e.encodeIntMap(headerPairs)
	}

	// Key 2: body
	e.encodeHead(cborMTUint, 2)
	{
		bodyPairs := []intKV{
			{key: 1, keyEnc: encodedKeyForUint(1), value: env.Body.Intent},
			{key: 2, keyEnc: encodedKeyForUint(2), value: env.Body.Content},
		}
		if env.Body.Capability != "" {
			bodyPairs = append(bodyPairs, intKV{key: 3, keyEnc: encodedKeyForUint(3), value: env.Body.Capability})
		}
		if env.Body.CorrelationID != "" {
			bodyPairs = append(bodyPairs, intKV{key: 4, keyEnc: encodedKeyForUint(4), value: env.Body.CorrelationID})
		}
		e.encodeIntMap(bodyPairs)
	}

	// Key 3: signature (optional)
	if env.Signature != nil {
		e.encodeHead(cborMTUint, 3)
		sigPairs := []intKV{
			{key: 1, keyEnc: encodedKeyForUint(1), value: env.Signature.Alg},
			{key: 2, keyEnc: encodedKeyForUint(2), value: env.Signature.KeyID},
			{key: 3, keyEnc: encodedKeyForUint(3), value: env.Signature.Value},
		}
		e.encodeIntMap(sigPairs)
	}

	return e.buf, nil
}

// DecodeEnvelopeCBOR decodes CBOR bytes into a ProtocolEnvelope.
func DecodeEnvelopeCBOR(data []byte) (ProtocolEnvelope, error) {
	d := &cborDecoder{data: data}

	header, body, sig, err := d.decodeTopLevel()
	if err != nil {
		return ProtocolEnvelope{}, fmt.Errorf("DecodeEnvelopeCBOR: %w", err)
	}

	if header == nil {
		return ProtocolEnvelope{}, fmt.Errorf("DecodeEnvelopeCBOR: missing header (key 1)")
	}
	if body == nil {
		return ProtocolEnvelope{}, fmt.Errorf("DecodeEnvelopeCBOR: missing body (key 2)")
	}

	getString := func(m map[uint64]interface{}, key uint64, field string) (string, error) {
		v, ok := m[key]
		if !ok {
			return "", fmt.Errorf("DecodeEnvelopeCBOR: missing field %s (key %d)", field, key)
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("DecodeEnvelopeCBOR: field %s (key %d) is not a string", field, key)
		}
		return s, nil
	}

	getInt64 := func(m map[uint64]interface{}, key uint64, field string) (int64, error) {
		v, ok := m[key]
		if !ok {
			return 0, fmt.Errorf("DecodeEnvelopeCBOR: missing field %s (key %d)", field, key)
		}
		n, ok := v.(int64)
		if !ok {
			return 0, fmt.Errorf("DecodeEnvelopeCBOR: field %s (key %d) is not an int", field, key)
		}
		return n, nil
	}

	getOptString := func(m map[uint64]interface{}, key uint64) string {
		v, ok := m[key]
		if !ok {
			return ""
		}
		s, _ := v.(string)
		return s
	}

	version, err := getString(header, 1, "version")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	messageID, err := getString(header, 2, "messageId")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	timestampMs, err := getInt64(header, 3, "timestampMs")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	ttlMs, err := getInt64(header, 4, "ttlMs")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	sender, err := getString(header, 5, "sender")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	nonce, err := getString(header, 7, "nonce")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	recipient := getOptString(header, 6)

	intent, err := getString(body, 1, "intent")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	content, err := getString(body, 2, "content")
	if err != nil {
		return ProtocolEnvelope{}, err
	}
	capability := getOptString(body, 3)
	correlationID := getOptString(body, 4)

	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     version,
			MessageID:   messageID,
			TimestampMs: timestampMs,
			TTLMs:       ttlMs,
			Sender:      sender,
			Recipient:   recipient,
			Nonce:       nonce,
		},
		Body: ProtocolBody{
			Intent:        intent,
			Content:       content,
			Capability:    capability,
			CorrelationID: correlationID,
		},
	}

	if sig != nil {
		env.Signature = &ProtocolSignature{
			Alg:   sig[1],
			KeyID: sig[2],
			Value: sig[3],
		}
	}

	return env, nil
}
