package signing

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
)

func NewRandReader(deterministic bool, seed string) io.Reader {
	if deterministic {
		return newDeterministicReader(seed)
	}
	return newUndeterministicReader()
}

func newUndeterministicReader() io.Reader {
	return rand.Reader
}

func newDeterministicReader(seed string) io.Reader {
	// Use a SHA256 hash of the seed as entropy
	hash := sha256.Sum256([]byte(seed))
	return &deterministicReader{data: hash[:], pos: 0}
}

type deterministicReader struct {
	data []byte
	pos  int
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	n := 0
	for i := range p {
		p[i] = r.data[r.pos%len(r.data)]
		r.pos++
		n++
	}
	return n, nil
}
