// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"fmt"

	"github.com/pion/transport/v5/replaydetector"
)

// replayWindowDetector is the default replay detector used by
// SRTPReplayProtection and SRTCPReplayProtection.
//
// Its algorithm matches replaydetector.New from github.com/pion/transport
// (the detector used before replay-state checkpoints were introduced) but the
// state is kept in a form that can be exported and restored. Keeping the
// algorithm identical is important: a checkpoint taken from one process must
// make the restored process take exactly the same accept/reject decisions.
//
// The detector accepts monotonically increasing indexes up to maxSeq and keeps
// a sliding window of windowSize bits behind the highest accepted index.
type replayWindowDetector struct {
	latestSeq  uint64
	maxSeq     uint64
	windowSize uint
	// mask is a little-endian multi-word bitset. Bit i is set when
	// latestSeq-i has already been accepted.
	mask    []uint64
	n       uint
	msbMask uint64
}

var _ replaydetector.CheckAccepter = (*replayWindowDetector)(nil)

func newReplayWindowDetector(windowSize uint, maxSeq uint64) *replayWindowDetector {
	chunkSize := max((windowSize+63)/64, 1)

	return &replayWindowDetector{
		maxSeq:     maxSeq,
		windowSize: windowSize,
		mask:       make([]uint64, chunkSize),
		n:          windowSize,
		msbMask:    ^uint64(0) >> ((64 - windowSize%64) % 64),
	}
}

// Check returns true if seq has not been replayed.
func (d *replayWindowDetector) Check(seq uint64) (accept func() bool, ok bool) {
	if !d.checkSeq(seq) {
		return func() bool { return false }, false
	}

	return func() bool {
		return d.acceptSeq(seq)
	}, true
}

// CheckSeq reports whether seq has not been replayed.
func (d *replayWindowDetector) CheckSeq(seq uint64) replaydetector.Token {
	if !d.checkSeq(seq) {
		return replaydetector.Rejected(seq)
	}

	return replaydetector.Passed(seq)
}

// Accept records a passed Token's sequence number as received.
func (d *replayWindowDetector) Accept(tok replaydetector.Token) bool {
	if !tok.Passed() {
		return false
	}

	return d.acceptSeq(tok.Seq())
}

func (d *replayWindowDetector) checkSeq(seq uint64) bool {
	if seq > d.maxSeq {
		// Exceeded upper limit.
		return false
	}

	if seq <= d.latestSeq {
		if d.latestSeq-seq >= uint64(d.windowSize) {
			return false
		}
		if d.bit(uint(d.latestSeq-seq)) != 0 {
			// The sequence number is duplicated.
			return false
		}
	}

	return true
}

func (d *replayWindowDetector) acceptSeq(seq uint64) bool {
	latest := seq == 0 && d.latestSeq == 0 && d.bit(0) == 0
	if seq > d.latestSeq {
		// Update the head of the window.
		d.lsh(uint(min(seq-d.latestSeq, uint64(d.windowSize))))
		d.latestSeq = seq
		latest = true
	}
	diff := (d.latestSeq - seq) % d.maxSeq
	d.setBit(uint(diff))

	return latest
}

func (d *replayWindowDetector) bit(i uint) uint {
	if i >= d.n {
		return 0
	}
	if d.mask[i/64]&(1<<(i%64)) != 0 {
		return 1
	}

	return 0
}

func (d *replayWindowDetector) setBit(i uint) {
	if i >= d.n {
		return
	}
	d.mask[i/64] |= 1 << (i % 64)
}

// lsh shifts the window left by n bits, discarding bits that move past
// windowSize.
func (d *replayWindowDetector) lsh(shift uint) {
	if shift == 0 {
		return
	}
	nChunk := int(shift / 64) //nolint:gosec
	nN := shift % 64

	for i := len(d.mask) - 1; i >= 0; i-- {
		var carry uint64
		if i-nChunk >= 0 {
			carry = d.mask[i-nChunk] << nN
			if i-nChunk-1 >= 0 {
				carry |= d.mask[i-nChunk-1] >> (64 - nN)
			}
		}
		d.mask[i] = (d.mask[i] << shift) | carry
	}
	d.mask[len(d.mask)-1] &= d.msbMask
}

// exportState returns the detector state in a stable, serializable form.
// mask is encoded with bit i in byte i/8, least significant bit first. Only
// the windowSize least significant bits are meaningful.
func (d *replayWindowDetector) exportState() (latestSeq uint64, mask []byte) {
	mask = make([]byte, (d.n+7)/8)
	for i := uint(0); i < d.n; i++ {
		if d.bit(i) != 0 {
			mask[i/8] |= 1 << (i % 8)
		}
	}

	return d.latestSeq, mask
}

// importState restores a state previously produced by exportState.
func (d *replayWindowDetector) importState(latestSeq uint64, mask []byte) error {
	if latestSeq > d.maxSeq {
		return fmt.Errorf("%w: latest index %d exceeds maximum %d",
			ErrReplayStateCounterOverflow, latestSeq, d.maxSeq)
	}

	expectedLen := (d.n + 7) / 8
	if uint(len(mask)) != expectedLen {
		return fmt.Errorf("%w: window bitmap is %d bytes, expected %d",
			ErrReplayStateTruncated, len(mask), expectedLen)
	}

	// Reject non-canonical bitmaps: bits outside of the window must be zero.
	if d.n%8 != 0 && expectedLen > 0 {
		unusedMask := byte(0xff) << (d.n % 8) //nolint:gosec // shift below 8
		if mask[expectedLen-1]&unusedMask != 0 {
			return fmt.Errorf("%w: window bitmap has bits outside the window", ErrReplayStateCorrupted)
		}
	}

	d.latestSeq = latestSeq
	for i := range d.mask {
		d.mask[i] = 0
	}
	for i := uint(0); i < d.n; i++ {
		if mask[i/8]&(1<<(i%8)) != 0 {
			d.setBit(i)
		}
	}

	return nil
}
