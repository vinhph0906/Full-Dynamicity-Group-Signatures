package nizk

import (
	"bytes"
	"encoding/binary"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// transcriptBuilder helps construct the Fiat-Shamir transcript in a structured way.
type transcriptBuilder struct {
	buf bytes.Buffer
	q   int64
}

func newTranscriptBuilder(q int64) *transcriptBuilder {
	return &transcriptBuilder{q: q}
}

func (tb *transcriptBuilder) appendBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	_, _ = tb.buf.Write(data)
}

func (tb *transcriptBuilder) appendVector(v *lattice.Vector) {
	if v == nil {
		return
	}
	var buf [8]byte
	for i := 0; i < v.Size; i++ {
		binary.BigEndian.PutUint64(buf[:], uint64(v.Data[i]))
		_, _ = tb.buf.Write(buf[:])
	}
}

func (tb *transcriptBuilder) bytes() []byte {
	return tb.buf.Bytes()
}
