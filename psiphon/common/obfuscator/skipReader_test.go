package obfuscator

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestReadBuffer(t *testing.T) {
	t.Parallel()

	type test struct {
		name           string
		prefix         []byte
		terminator     []byte
		postfix        []byte
		readSize       int
		expectedErrStr string
	}

	tests := []test{
		{
			name:       "1 byte terminnator at start",
			prefix:     []byte{},
			terminator: []byte{'a'},
			postfix:    []byte("postfix"),
			readSize:   1024,
		},
		{
			name:       "no prefix",
			prefix:     []byte{},
			terminator: []byte("[terminator]"),
			postfix:    []byte("postfix"),
			readSize:   1,
		},
		{
			name:       "small prefix",
			prefix:     []byte("prefix"),
			terminator: []byte("[terminator]"),
			postfix:    []byte("postfix"),
			readSize:   1,
		},
		{
			name:       "large prefix",
			prefix:     []byte(strings.Repeat("prefix", 1000)),
			terminator: []byte("[terminator]"),
			postfix:    []byte("postfix"),
			readSize:   1,
		},
		{
			name:       "large read size",
			prefix:     []byte(strings.Repeat("prefix", 1000)),
			terminator: []byte("[terminator]"),
			postfix:    []byte("postfix"),
			readSize:   8192,
		},
		{
			name:           "max prefix size",
			prefix:         bytes.Repeat([]byte{'a'}, PREFIX_MAX_LENGTH),
			terminator:     []byte("[terminator]"),
			postfix:        []byte{},
			readSize:       8192,
			expectedErrStr: "",
		},
		{
			name:           "exceed max prefix length",
			prefix:         bytes.Repeat([]byte{'a'}, PREFIX_MAX_LENGTH+1),
			terminator:     []byte("[terminator]"),
			postfix:        []byte{},
			readSize:       8192,
			expectedErrStr: "exceeded max search size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			conn := newConn(append(tt.prefix, append(tt.terminator, tt.postfix...)...))
			reader, _ := WrapConnWithSkipReader(conn).(*SkipReader)
			defer reader.Close()

			err := reader.SkipUpToToken(
				tt.terminator, tt.readSize, PREFIX_MAX_LENGTH+len(tt.terminator))

			if tt.expectedErrStr != "" {
				if err == nil {
					t.Fatalf("SkipUpToToken returned nil error, expected %s", tt.expectedErrStr)
				} else if !strings.Contains(err.Error(), tt.expectedErrStr) {
					t.Fatalf("SkipUpToToken returned error %s, expected %s", err, tt.expectedErrStr)
				} else {
					return
				}
			}

			if err != nil {
				t.Fatalf("SkipUpToToken returned unexpected error: %s", err)
			}

			// read the rest one byte at a time
			var buff bytes.Buffer
			for {
				b := make([]byte, 1)
				_, err := reader.Read(b)
				if err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal(err)
				}
				buff.Write(b)
			}

			if !bytes.Equal(buff.Bytes(), tt.postfix) {
				t.Fatalf("Read returned %v, expected %v", buff.Bytes(), tt.postfix)
			}

		})
	}

}

func BenchmarkBase(b *testing.B) {

	data := make([]byte, 1024*1024)
	for i := 0; i < len(data); i++ {
		data[i] = byte(i % 256)
	}
	terminator := []byte("[terminator]postfix")
	copy(data[len(data)-len(terminator):], terminator)

	b.ResetTimer()

	idx := bytes.Index(data, []byte("[terminator]"))
	if idx == -1 {
		b.Fatal("terminator not found")
	}

	if idx != len(data)-len(terminator) {
		b.Fatalf("terminator not at expected position: %d", idx)
	}

}

func BenchmarkSkipReader(b *testing.B) {

	data := make([]byte, 1024*1024)
	for i := 0; i < len(data); i++ {
		data[i] = byte(i % 256)
	}
	tail := []byte("[terminator]postfix")
	copy(data[len(data)-len(tail):], tail)

	conn := newConn(data)
	reader, _ := WrapConnWithSkipReader(conn).(*SkipReader)
	defer reader.Close()

	b.ResetTimer()

	err := reader.SkipUpToToken([]byte("[terminator]"), 1024, 1024*1024*1024)
	if err != nil {
		b.Fatalf("SkipUpToToken failed: %s", err)
	}

	b.StopTimer()

	// read the rest
	rest, err := io.ReadAll(reader)
	if err != nil {
		b.Fatal(err)
	}
	if string(rest) != "postfix" {
		b.Fatalf("Read returned %s, expected 'postfix'", rest)
	}
}
