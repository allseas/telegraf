package socket

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"regexp"
	"strconv"
	"strings"
)

type lengthFieldSpec struct {
	Offset       int64  `toml:"offset"`
	Bytes        int64  `toml:"bytes"`
	Endianness   string `toml:"endianness"`
	HeaderLength int64  `toml:"header_length"`
	converter    func([]byte) int
}

func (spec *lengthFieldSpec) setConverter() error {
	var order binary.ByteOrder
	switch strings.ToLower(spec.Endianness) {
	case "", "be":
		order = binary.BigEndian
	case "le":
		order = binary.LittleEndian
	default:
		return fmt.Errorf("invalid 'endianness' %q", spec.Endianness)
	}

	switch spec.Bytes {
	case 1:
		spec.converter = func(b []byte) int {
			return int(b[0])
		}
	case 2:
		spec.converter = func(b []byte) int {
			return int(order.Uint16(b))
		}
	case 4:
		spec.converter = func(b []byte) int {
			return int(order.Uint32(b))
		}
	case 8:
		spec.converter = func(b []byte) int {
			return int(order.Uint64(b))
		}
	default:
		spec.converter = func(b []byte) int {
			buf := make([]byte, 8)
			start := 0
			if order == binary.BigEndian {
				start = 8 - len(b)
			}
			for i := 0; i < len(b); i++ {
				buf[start+i] = b[i]
			}
			return int(order.Uint64(buf))
		}
	}

	return nil
}

type headerFieldSpec struct {
	ConstBytes map[string]string `toml:"const_bytes"`
	Checksum   checksumSpec      `toml:"checksum"`
	Length     lengthFieldSpec   `toml:"length_field"`
}

type checksumSpec struct {
	Strategy string `toml:"strategy"`
	Range    []int  `toml:"range"`
	Offset   int    `toml:"offset"`
	Bytes    int    `toml:"bytes"`
}

type SplitConfig struct {
	SplittingStrategy     string          `toml:"splitting_strategy"`
	SplittingDelimiter    string          `toml:"splitting_delimiter"`
	SplittingLength       int             `toml:"splitting_length"`
	SplittingLengthField  lengthFieldSpec `toml:"splitting_length_field"`
	SplittingCustomHeader headerFieldSpec `toml:"splitting_custom_header"`
}

func (cfg *SplitConfig) NewSplitter() (bufio.SplitFunc, error) {
	switch cfg.SplittingStrategy {
	case "", "newline":
		return bufio.ScanLines, nil
	case "null":
		return scanNull, nil
	case "delimiter":
		re := regexp.MustCompile(`(\s*0?x)`)
		d := re.ReplaceAllString(strings.ToLower(cfg.SplittingDelimiter), "")
		delimiter, err := hex.DecodeString(d)
		if err != nil {
			return nil, fmt.Errorf("decoding delimiter failed: %w", err)
		}
		return createScanDelimiter(delimiter), nil
	case "fixed length":
		return createScanFixedLength(cfg.SplittingLength), nil
	case "variable length":
		// Create the converter function
		if err := cfg.SplittingLengthField.setConverter(); err != nil {
			return nil, err
		}

		// Check if we have enough bytes in the header
		return createScanVariableLength(cfg.SplittingLengthField), nil
	case "custom header":
		return createScanCustomHeader(cfg.SplittingCustomHeader)
	}

	return nil, fmt.Errorf("unknown 'splitting_strategy' %q", cfg.SplittingStrategy)
}

func scanNull(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

func createScanDelimiter(delimiter []byte) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.Index(data, delimiter); i >= 0 {
			return i + len(delimiter), data[:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		// Request more data.
		return 0, nil, nil
	}
}

func createScanFixedLength(length int) bufio.SplitFunc {
	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if len(data) >= length {
			return length, data[:length], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		// Request more data.
		return 0, nil, nil
	}
}

func createScanVariableLength(spec lengthFieldSpec) bufio.SplitFunc {
	minlen := int(spec.Offset)
	minlen += int(spec.Bytes)
	headerLen := int(spec.HeaderLength)

	return func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		dataLen := len(data)
		if dataLen >= minlen {
			// Extract the length field and convert it to a number
			lf := data[spec.Offset : spec.Offset+spec.Bytes]
			length := spec.converter(lf)
			start := headerLen
			end := length + headerLen
			// If we have enough data return it without the header
			if end <= dataLen {
				return end, data[start:end], nil
			}
		}
		if atEOF {
			return len(data), data, nil
		}
		// Request more data.
		return 0, nil, nil
	}
}

func createScanCustomHeader(spec headerFieldSpec) (bufio.SplitFunc, error) {
	headerLen := int(spec.Length.HeaderLength)

	// Parse the constant bytes into an offset -> value map
	constBytes := make(map[int]byte, len(spec.ConstBytes))
	for k, v := range spec.ConstBytes {
		offset, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("invalid const byte offset %q: %w", k, err)
		}
		if offset < 0 {
			return nil, fmt.Errorf("const byte offset %d must not be negative", offset)
		}
		if headerLen > 0 && offset >= headerLen {
			return nil, fmt.Errorf("const byte offset %d is past the header length %d", offset, headerLen)
		}
		// Decode the hex value, accepting an optional "0x"/"x" prefix.
		h := strings.ToLower(v)
		h = strings.TrimPrefix(h, "0x")
		h = strings.TrimPrefix(h, "x")
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("invalid const byte value %q at offset %d: %w", v, offset, err)
		}
		if len(b) != 1 {
			return nil, fmt.Errorf("const byte value %q at offset %d is not a single byte", v, offset)
		}
		constBytes[offset] = b[0]
	}

	// Build the length-field converter, if a length field is configured.
	lf := spec.Length
	var lengthConv func([]byte) int
	if lf.Bytes > 0 {
		if err := spec.Length.setConverter(); err != nil {
			return nil, err
		}
		lengthConv = spec.Length.converter
	}

	// Build the checksum function, if a checksum is configured.
	cs := spec.Checksum
	checksumFn, err := makeChecksum(cs.Strategy, cs.Bytes)
	if err != nil {
		return nil, err
	}
	if checksumFn != nil {
		if len(cs.Range) != 2 {
			return nil, fmt.Errorf("checksum requires a range [start, end]")
		}
		if cs.Range[0] < 0 || cs.Range[1] < cs.Range[0] {
			return nil, fmt.Errorf("invalid checksum range %v", cs.Range)
		}
	}

	// Without a length field, boundaries are found by scanning for the next
	// header, so we need something to recognize a header by.
	if lf.Bytes <= 0 && len(constBytes) == 0 && checksumFn == nil {
		return nil, fmt.Errorf("cannot determine message boundaries: configure a length field, constant bytes, or a checksum")
	}

	// Bytes needed before a header can be validated at a given position.
	minlen := 0
	if lf.Bytes > 0 {
		minlen = max(minlen, int(lf.Offset+lf.Bytes))
	}
	for offset := range constBytes {
		minlen = max(minlen, offset+1)
	}
	if checksumFn != nil {
		minlen = max(minlen, cs.Offset+cs.Bytes)
		minlen = max(minlen, cs.Range[1])
	}

	// headerAt reports whether a valid header starts at position p. The caller
	// must ensure at least p+minlen bytes are available.
	headerAt := func(buf []byte, p int) bool {
		for offset, b := range constBytes {
			if buf[p+offset] != b {
				return false
			}
		}
		if checksumFn != nil {
			sum := checksumFn(buf[p+cs.Range[0] : p+cs.Range[1]])
			if !bytes.Equal(sum, buf[p+cs.Offset:p+cs.Offset+cs.Bytes]) {
				return false
			}
		}
		return true
	}

	if lf.Bytes > 0 {
		lfOffset := int(lf.Offset)
		lfBytes := int(lf.Bytes)

		// Length mode: the length field gives the message end.
		return func(data []byte, _ bool) (advance int, token []byte, err error) {
			dataLen := len(data)
			if dataLen == 0 || dataLen < minlen {
				return 0, nil, nil
			}

			// Validate the header at the start of the message; resync by one
			// byte on mismatch.
			if !headerAt(data, 0) {
				return 1, nil, nil
			}

			end := lengthConv(data[lfOffset : lfOffset+lfBytes])
			if end <= 0 {
				return 1, nil, nil
			}
			// A valid header before the claimed end means the length is bogus
			// (desync or truncation); discard up to that header.
			for p := 1; p < end && p+minlen <= dataLen; p++ {
				if headerAt(data, p) {
					return p, nil, nil
				}
			}
			if end > dataLen {
				return 0, nil, nil
			}
			if end > headerLen {
				return end, data[headerLen:end], nil
			}
			// The length field is too small to include any payload; discard it.
			return end, nil, nil
		}, nil
	}

	// Delimiter mode: the message ends at the next valid header.
	return func(data []byte, _ bool) (advance int, token []byte, err error) {
		dataLen := len(data)
		if dataLen == 0 || dataLen < minlen {
			return 0, nil, nil
		}

		// Validate the header at the start of the message; resync by one byte
		// on mismatch.
		if !headerAt(data, 0) {
			return 1, nil, nil
		}

		// A header can only start after the current message's header, so never
		// look before headerLen.
		for p := headerLen; p+minlen <= dataLen; p++ {
			if headerAt(data, p) {
				return p, data[headerLen:p], nil
			}
		}
		return 0, nil, nil
	}, nil
}

// makeChecksum returns a function computing the checksum of the given data
// using the requested strategy, producing a digest of width bytes. It returns
// nil when no checksum is configured.
func makeChecksum(strategy string, width int) (func([]byte) []byte, error) {
	switch strings.ToLower(strategy) {
	case "", "none":
		return nil, nil
	case "crc32":
		if width != 4 {
			return nil, fmt.Errorf("crc32 checksum requires 4 bytes, got %d", width)
		}
		return func(data []byte) []byte {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, crc32.ChecksumIEEE(data))
			return b
		}, nil
	case "md5":
		if width != md5.Size {
			return nil, fmt.Errorf("md5 checksum requires %d bytes, got %d", md5.Size, width)
		}
		return func(data []byte) []byte {
			sum := md5.Sum(data)
			return sum[:]
		}, nil
	case "sha256":
		if width != sha256.Size {
			return nil, fmt.Errorf("sha256 checksum requires %d bytes, got %d", sha256.Size, width)
		}
		return func(data []byte) []byte {
			sum := sha256.Sum256(data)
			return sum[:]
		}, nil
	case "xor":
		if width <= 0 {
			return nil, fmt.Errorf("xor checksum requires a positive byte width")
		}
		return func(data []byte) []byte {
			sum := make([]byte, width)
			for i, b := range data {
				sum[i%width] ^= b
			}
			return sum
		}, nil
	default:
		return nil, fmt.Errorf("unknown checksum strategy %q", strategy)
	}
}
