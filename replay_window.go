// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"fmt"

	"github.com/pion/transport/v5/replaydetector"
)

// MaxReplayWindowSize is the largest replay protection window size accepted by
// Context.SetSRTPReplayWindow and Context.SetSRTCPReplayWindow. It bounds the
// per-SSRC memory a window configuration can allocate (MaxReplayWindowSize/8 bytes).
const MaxReplayWindowSize = 1 << 20

// validateReplayWindowSize reports whether windowSize is usable as a per-SSRC
// replay protection window.
func validateReplayWindowSize(windowSize uint) error {
	if windowSize == 0 || windowSize > MaxReplayWindowSize {
		return fmt.Errorf("%w: %d is not in the range [1, %d]", ErrInvalidReplayWindowSize, windowSize, MaxReplayWindowSize)
	}

	return nil
}

// SetSRTPReplayWindow sets the SRTP replay protection window size for a single SSRC,
// overriding the context-wide default configured with SRTPReplayProtection for that
// stream. SSRCs without a per-SSRC configuration keep using the context-wide default.
//
// The window can be adjusted at runtime: growing the window preserves every still
// traceable received sequence number, shrinking it keeps (at least) the history
// covered by the new window. Packets accepted before the reconfiguration that are
// still traceable are never accepted again afterwards. Note that sequence numbers
// which had already fallen out of the window before a grow are indistinguishable
// from never-seen ones and become acceptable again.
//
// The configuration applies to SSRC states created afterwards, and is applied
// in-place to an already existing state for the SSRC. If the existing state uses a
// custom replay detector (SRTPReplayDetectorFactory or SRTPNoReplayProtection) that
// cannot be resized, ErrReplayDetectorNotResizable is returned and the configuration
// is not stored. It only affects SRTP traffic; use SetSRTCPReplayWindow for SRTCP.
//
// Operation is not thread-safe, you need to provide synchronization with
// decrypting packets. Use SessionSRTP.SetRemoteReplayWindow to adjust the window
// concurrently with a running session.
func (c *Context) SetSRTPReplayWindow(ssrc uint32, windowSize uint) error {
	if err := validateReplayWindowSize(windowSize); err != nil {
		return err
	}

	if state, ok := c.srtpSSRCStates[ssrc]; ok {
		if err := state.setReplayWindowSize(windowSize); err != nil {
			return err
		}
	}
	c.srtpReplayWindows[ssrc] = windowSize

	return nil
}

// SetSRTCPReplayWindow sets the SRTCP replay protection window size for a single
// SSRC, overriding the context-wide default configured with SRTCPReplayProtection
// for that stream. It behaves like SetSRTPReplayWindow but applies to SRTCP traffic
// only; the SRTP policy for the same SSRC is left untouched.
//
// Operation is not thread-safe, you need to provide synchronization with
// decrypting packets. Use SessionSRTCP.SetRemoteReplayWindow to adjust the window
// concurrently with a running session.
func (c *Context) SetSRTCPReplayWindow(ssrc uint32, windowSize uint) error {
	if err := validateReplayWindowSize(windowSize); err != nil {
		return err
	}

	if state, ok := c.srtcpSSRCStates[ssrc]; ok {
		if err := state.setReplayWindowSize(windowSize); err != nil {
			return err
		}
	}
	c.srtcpReplayWindows[ssrc] = windowSize

	return nil
}

// SRTPReplayWindow returns the per-SSRC SRTP replay window configured with
// SetSRTPReplayWindow, and whether such a configuration exists.
func (c *Context) SRTPReplayWindow(ssrc uint32) (uint, bool) {
	windowSize, ok := c.srtpReplayWindows[ssrc]

	return windowSize, ok
}

// SRTCPReplayWindow returns the per-SSRC SRTCP replay window configured with
// SetSRTCPReplayWindow, and whether such a configuration exists.
func (c *Context) SRTCPReplayWindow(ssrc uint32) (uint, bool) {
	windowSize, ok := c.srtcpReplayWindows[ssrc]

	return windowSize, ok
}

func (s *srtpSSRCState) setReplayWindowSize(windowSize uint) error {
	detector, ok := s.replayDetector.(*resizableReplayDetector)
	if !ok {
		return fmt.Errorf("%w: ssrc=%d", ErrReplayDetectorNotResizable, s.ssrc)
	}
	detector.setWindowSize(windowSize)

	return nil
}

func (s *srtcpSSRCState) setReplayWindowSize(windowSize uint) error {
	detector, ok := s.replayDetector.(*resizableReplayDetector)
	if !ok {
		return fmt.Errorf("%w: ssrc=%d", ErrReplayDetectorNotResizable, s.ssrc)
	}
	detector.setWindowSize(windowSize)

	return nil
}

// newSRTPReplayDetectorFor returns the replay detector for a new SRTP SSRC state:
// a resizable detector when a per-SSRC window is configured, the context-wide
// factory otherwise.
func (c *Context) newSRTPReplayDetectorFor(ssrc uint32) replaydetector.ReplayDetector {
	if windowSize, ok := c.srtpReplayWindows[ssrc]; ok {
		return newResizableReplayDetector(windowSize, maxROC<<16|maxSequenceNumber)
	}

	return c.newSRTPReplayDetector()
}

// newSRTCPReplayDetectorFor returns the replay detector for a new SRTCP SSRC state:
// a resizable detector when a per-SSRC window is configured, the context-wide
// factory otherwise.
func (c *Context) newSRTCPReplayDetectorFor(ssrc uint32) replaydetector.ReplayDetector {
	if windowSize, ok := c.srtcpReplayWindows[ssrc]; ok {
		return newResizableReplayDetector(windowSize, maxSRTCPIndex)
	}

	return c.newSRTCPReplayDetector()
}

// resizableReplayDetector is a sliding window replay detector whose window size
// can be adjusted at runtime without losing the received sequence numbers that
// remain traceable. Its check/accept semantics match replaydetector.New: the
// sequence space does not wrap (for SRTP the rollover counter is folded into the
// sequence index by the Context before checking).
//
// Like every other replay detector used by Context it is not thread-safe; callers
// must synchronize Check/Accept with setWindowSize.
type resizableReplayDetector struct {
	latestSeq  uint64
	maxSeq     uint64
	windowSize uint
	mask       *replayWindowMask
}

func newResizableReplayDetector(windowSize uint, maxSeq uint64) *resizableReplayDetector {
	return &resizableReplayDetector{
		maxSeq:     maxSeq,
		windowSize: windowSize,
		mask:       newReplayWindowMask(windowSize),
	}
}

// setWindowSize resizes the window. Growing preserves all still traceable
// received sequence numbers; shrinking keeps the most recent windowSize bits of
// history, i.e. exactly the sequence numbers the new window still covers.
func (d *resizableReplayDetector) setWindowSize(windowSize uint) {
	if windowSize == d.windowSize {
		return
	}
	d.mask.resize(windowSize)
	d.windowSize = windowSize
}

func (d *resizableReplayDetector) Check(seq uint64) (func() bool, bool) {
	if !d.checkSeq(seq) {
		return func() bool { return false }, false
	}

	return func() bool {
		return d.acceptSeq(seq)
	}, true
}

func (d *resizableReplayDetector) CheckSeq(seq uint64) replaydetector.Token {
	if !d.checkSeq(seq) {
		return replaydetector.Rejected(seq)
	}

	return replaydetector.Passed(seq)
}

func (d *resizableReplayDetector) Accept(tok replaydetector.Token) bool {
	if !tok.Passed() {
		return false
	}

	return d.acceptSeq(tok.Seq())
}

func (d *resizableReplayDetector) checkSeq(seq uint64) bool {
	if seq > d.maxSeq {
		// Exceeded upper limit.
		return false
	}

	if seq <= d.latestSeq {
		if d.latestSeq-seq >= uint64(d.windowSize) {
			// Behind the window.
			return false
		}
		if d.mask.bit(uint(d.latestSeq-seq)) != 0 {
			// The sequence number is duplicated.
			return false
		}
	}

	return true
}

func (d *resizableReplayDetector) acceptSeq(seq uint64) bool {
	latest := seq == 0 && d.latestSeq == 0 && d.mask.bit(0) == 0
	if seq > d.latestSeq {
		// Update the head of the window.
		d.mask.lsh(uint(min(seq-d.latestSeq, uint64(d.windowSize))))
		d.latestSeq = seq
		latest = true
	}
	diff := (d.latestSeq - seq) % d.maxSeq
	d.mask.setBit(uint(diff))

	return latest
}

// replayWindowMask is a fixed-point bit mask of n bits tracking received sequence
// numbers relative to the latest observed one: bit i marks latestSeq-i.
type replayWindowMask struct {
	bits    []uint64
	n       uint
	msbMask uint64
}

func newReplayWindowMask(n uint) *replayWindowMask {
	chunkSize := max((n+63)/64, 1)

	return &replayWindowMask{
		bits:    make([]uint64, chunkSize),
		n:       n,
		msbMask: ^uint64(0) >> ((64 - n%64) % 64),
	}
}

// resize changes the number of tracked bits to n, preserving the low bits (the
// most recent history) up to the new size.
func (m *replayWindowMask) resize(n uint) {
	if n == m.n {
		return
	}
	chunkSize := max((n+63)/64, 1)
	newBits := make([]uint64, chunkSize)
	copy(newBits, m.bits)
	m.bits = newBits
	m.n = n
	m.msbMask = ^uint64(0) >> ((64 - n%64) % 64)
	m.bits[len(m.bits)-1] &= m.msbMask
}

// lsh shifts the mask towards higher bit positions by n, dropping the bits that
// fall off the window head. Bit i becomes bit i+n.
func (m *replayWindowMask) lsh(n uint) { //nolint:varnamelen
	if n == 0 {
		return
	}
	nChunk := int(n / 64) //nolint:gosec
	nN := n % 64

	for i := len(m.bits) - 1; i >= 0; i-- {
		var carry uint64
		if i-nChunk >= 0 {
			carry = m.bits[i-nChunk] << nN
			if i-nChunk-1 >= 0 {
				carry |= m.bits[i-nChunk-1] >> (64 - nN)
			}
		}
		m.bits[i] = (m.bits[i] << n) | carry
	}
	m.bits[len(m.bits)-1] &= m.msbMask
}

// bit returns the i-th bit of the mask, or 0 if i is outside the window.
func (m *replayWindowMask) bit(i uint) uint {
	if i >= m.n {
		return 0
	}
	chunk := i / 64
	pos := i % 64
	if m.bits[chunk]&(1<<pos) != 0 {
		return 1
	}

	return 0
}

// setBit sets the i-th bit of the mask. Bits outside the window are ignored.
func (m *replayWindowMask) setBit(i uint) {
	if i >= m.n {
		return
	}
	chunk := i / 64
	pos := i % 64
	m.bits[chunk] |= 1 << pos
}
