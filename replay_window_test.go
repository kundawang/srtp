// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/transport/v5/replaydetector"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	replayWindowVideoSSRC = 0x711DE0
	replayWindowAudioSSRC = 0xA0D10
)

// reversedBlockOrder returns a permutation of [0, n) reversing every block of
// depth consecutive elements, simulating a jittery link with reorder depth.
func reversedBlockOrder(n, depth int) []int {
	order := make([]int, 0, n)
	for start := 0; start < n; start += depth {
		end := min(start+depth, n)
		for i := end - 1; i >= start; i-- {
			order = append(order, i)
		}
	}

	return order
}

func encryptRTPForWindowTest(t *testing.T, ctx *Context, ssrc uint32, seq uint16) []byte {
	t.Helper()

	encrypted, err := encryptSRTP(ctx, &rtp.Packet{
		Header:  rtp.Header{SSRC: ssrc, SequenceNumber: seq},
		Payload: []byte{0x00, 0x01, 0x02, 0x03},
	})
	require.NoError(t, err)

	return encrypted
}

func decryptRTPForWindowTest(ctx *Context, encrypted []byte) error {
	_, err := ctx.DecryptRTP(nil, encrypted, nil)

	return err
}

func encryptRTCPForWindowTest(t *testing.T, ctx *Context, ssrc uint32) []byte {
	t.Helper()

	// Minimal RTCP Receiver Report: V=2, RC=0, PT=201, length=1, SSRC.
	raw := make([]byte, 8)
	raw[0] = 0x80
	raw[1] = 201
	binary.BigEndian.PutUint16(raw[2:], 1)
	binary.BigEndian.PutUint32(raw[4:], ssrc)

	encrypted, err := ctx.EncryptRTCP(nil, raw, nil)
	require.NoError(t, err)

	return encrypted
}

// TestResizableReplayDetectorGrowShrink verifies the detector semantics directly:
// growing keeps every still traceable sequence number, shrinking keeps the history
// covered by the new window, and accepted packets are never re-accepted.
func TestResizableReplayDetectorGrowShrink(t *testing.T) {
	assertT := assert.New(t)

	detector := newResizableReplayDetector(64, maxROC<<16|maxSequenceNumber)

	// Accept 0..99 except the held-back 10.
	for seq := range uint64(100) {
		if seq == 10 {
			continue
		}
		token := detector.CheckSeq(seq)
		require.True(t, token.Passed(), "seq %d must pass the check", seq)
		detector.Accept(token)
	}

	// The held-back packet is behind the window now.
	assertT.False(detector.CheckSeq(10).Passed(), "seq 10 is too old for window 64")
	// Duplicates are rejected.
	assertT.False(detector.CheckSeq(50).Passed(), "seq 50 is a duplicate")

	// Grow: all still traceable history is preserved, and previously too old
	// (but never accepted) packets become acceptable again.
	detector.setWindowSize(256)
	assertT.False(detector.CheckSeq(50).Passed(), "seq 50 must stay a duplicate after growing")
	token := detector.CheckSeq(10)
	require.True(t, token.Passed(), "seq 10 must be acceptable after growing to 256")
	detector.Accept(token)
	assertT.False(detector.CheckSeq(10).Passed(), "seq 10 is a duplicate once accepted")

	// Shrink to 4: the history covered by the new window is kept, everything
	// older is rejected and must not become acceptable again.
	detector.setWindowSize(4)
	assertT.False(detector.CheckSeq(98).Passed(), "seq 98 must stay a duplicate after shrinking")
	assertT.False(detector.CheckSeq(96).Passed(), "seq 96 must stay a duplicate after shrinking")
	assertT.False(detector.CheckSeq(95).Passed(), "seq 95 fell out of the shrunk window")
	assertT.False(detector.CheckSeq(10).Passed(), "seq 10 fell out of the shrunk window")

	// The window still slides forward after shrinking.
	token = detector.CheckSeq(100)
	require.True(t, token.Passed())
	detector.Accept(token)
	assertT.False(detector.CheckSeq(96).Passed(), "seq 96 is too old after the window slid")

	// The legacy Check API agrees with CheckSeq/Accept.
	accept, ok := detector.Check(101)
	require.True(t, ok)
	accept()
	assertT.False(detector.CheckSeq(101).Passed(), "seq 101 is a duplicate once accepted")
}

// TestPerSSRCReplayWindowTwoStreams is the motivating scenario: a video stream
// crossing a long jittery link needs a deep replay window, while the audio
// stream keeps the small default window.
func TestPerSSRCReplayWindowTwoStreams(t *testing.T) {
	assertT := assert.New(t)

	const (
		videoPackets = 1200
		audioPackets = 400
		videoDepth   = 300 // reordered by up to 299 positions
		audioDepth   = 32  // reordered by up to 31 positions
	)

	encryptContext, err := buildTestContext(profileCTR)
	require.NoError(t, err)
	decryptContext, err := buildTestContext(profileCTR, SRTPReplayProtection(64))
	require.NoError(t, err)

	// Only the video SSRC gets a per-SSRC window; audio keeps the default 64.
	require.NoError(t, decryptContext.SetSRTPReplayWindow(replayWindowVideoSSRC, 512))

	videoEncrypted := make([][]byte, videoPackets)
	for i := range videoEncrypted {
		videoEncrypted[i] = encryptRTPForWindowTest(t, encryptContext, replayWindowVideoSSRC, uint16(i)) //nolint:gosec
	}
	audioEncrypted := make([][]byte, audioPackets)
	for i := range audioEncrypted {
		audioEncrypted[i] = encryptRTPForWindowTest(t, encryptContext, replayWindowAudioSSRC, uint16(i)) //nolint:gosec
	}

	// Interleave both streams, each with its own reorder depth.
	for _, i := range reversedBlockOrder(videoPackets, videoDepth) {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, videoEncrypted[i]),
			"video packet %d must pass the 512 window", i)
	}
	for _, i := range reversedBlockOrder(audioPackets, audioDepth) {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, audioEncrypted[i]),
			"audio packet %d must pass the default window", i)
	}

	// Replays of already accepted packets are rejected on both streams.
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, videoEncrypted[0]), errDuplicated)
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, videoEncrypted[videoPackets-1]), errDuplicated)
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, audioEncrypted[0]), errDuplicated)
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, audioEncrypted[audioPackets-1]), errDuplicated)

	// An unconfigured SSRC still uses the context-wide default window of 64:
	// in-window reorder passes, packets lagging by more than 64 are dropped.
	const otherSSRC = 0xDEAD
	otherEncrypted := make([][]byte, 200)
	for i := range otherEncrypted {
		otherEncrypted[i] = encryptRTPForWindowTest(t, encryptContext, otherSSRC, uint16(i)) //nolint:gosec
	}
	for _, i := range reversedBlockOrder(100, 32) {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, otherEncrypted[i]))
	}
	for i := 100; i < 200; i++ {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, otherEncrypted[i]))
	}
	err = decryptRTPForWindowTest(decryptContext, otherEncrypted[50])
	assertT.ErrorIs(err, errDuplicated, "packet lagging by more than the default window must be rejected")
}

// TestPerSSRCReplayWindowAcrossROC verifies replay decisions for sequences
// wrapping 65535 (spanning a ROC increment) with a per-SSRC window.
func TestPerSSRCReplayWindowAcrossROC(t *testing.T) {
	assertT := assert.New(t)

	const (
		ssrc  = 0xB0A7
		first = 65500
		count = 200 // 65500..65535, then 0..163 on ROC 1
		depth = 32
	)

	encryptContext, err := buildTestContext(profileCTR)
	require.NoError(t, err)
	decryptContext, err := buildTestContext(profileCTR, SRTPReplayProtection(64))
	require.NoError(t, err)
	require.NoError(t, decryptContext.SetSRTPReplayWindow(ssrc, 128))

	encrypted := make([][]byte, count)
	for i := range encrypted {
		encrypted[i] = encryptRTPForWindowTest(t, encryptContext, ssrc, uint16(first+i)) //nolint:gosec
	}

	// Reorder across the wrap and confirm every packet is accepted exactly once.
	for _, i := range reversedBlockOrder(count, depth) {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, encrypted[i]),
			"packet %d (seq %d) must be accepted across the ROC boundary", i, uint16(first+i)) //nolint:gosec
	}

	// Replays from before and after the wrap are both rejected.
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[10]), errDuplicated)
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[100]), errDuplicated)

	roc, ok := decryptContext.ROC(ssrc)
	require.True(t, ok)
	assertT.Equal(uint32(1), roc, "ROC must have advanced after the wrap")
}

// TestPerSSRCReplayWindowRuntimeResize verifies grow/shrink continuity on a live
// SRTP stream: history is preserved across reconfigurations and previously
// accepted packets are never re-accepted.
func TestPerSSRCReplayWindowRuntimeResize(t *testing.T) {
	assertT := assert.New(t)

	const ssrc = 0xFEED

	encryptContext, err := buildTestContext(profileCTR)
	require.NoError(t, err)
	decryptContext, err := buildTestContext(profileCTR, SRTPReplayProtection(64))
	require.NoError(t, err)

	encrypted := make([][]byte, 300)
	for i := range encrypted {
		encrypted[i] = encryptRTPForWindowTest(t, encryptContext, ssrc, uint16(i)) //nolint:gosec
	}

	// Deliver 0..99 in order, holding back seq 30.
	for i := range 100 {
		if i == 30 {
			continue
		}
		assertT.NoError(decryptRTPForWindowTest(decryptContext, encrypted[i]))
	}

	// Seq 30 lags by 69 > 64: too old for the current window.
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[30]), errDuplicated)

	// Grow to 256 at runtime: the held-back packet becomes acceptable, and all
	// previously accepted packets stay rejected.
	require.NoError(t, decryptContext.SetSRTPReplayWindow(ssrc, 256))
	assertT.NoError(decryptRTPForWindowTest(decryptContext, encrypted[30]),
		"held-back packet must be accepted after growing the window")
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[30]), errDuplicated)
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[40]), errDuplicated,
		"packet accepted before the reconfiguration must not be re-accepted")

	// Continue the stream, then shrink to 16.
	for i := 100; i < 200; i++ {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, encrypted[i]))
	}
	require.NoError(t, decryptContext.SetSRTPReplayWindow(ssrc, 16))

	// The shrunk window still covers the most recent history...
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[195]), errDuplicated,
		"history covered by the shrunk window must be kept")
	// ...and older accepted packets are rejected as too old, not re-accepted.
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[150]), errDuplicated)
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[30]), errDuplicated)

	// The stream keeps making progress with the new window size.
	for i := 200; i < 210; i++ {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, encrypted[i]))
	}
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[209]), errDuplicated)

	window, ok := decryptContext.SRTPReplayWindow(ssrc)
	require.True(t, ok)
	assertT.Equal(uint(16), window)
}

// TestSetReplayWindowInvalidSizes verifies deterministic errors for invalid and
// oversized windows on both SRTP and SRTCP policies.
func TestSetReplayWindowInvalidSizes(t *testing.T) {
	assertT := assert.New(t)

	decryptContext, err := buildTestContext(profileCTR, SRTPReplayProtection(64), SRTCPReplayProtection(64))
	require.NoError(t, err)

	for _, windowSize := range []uint{0, MaxReplayWindowSize + 1, 1 << 40} {
		assertT.ErrorIs(decryptContext.SetSRTPReplayWindow(1, windowSize), ErrInvalidReplayWindowSize)
		assertT.ErrorIs(decryptContext.SetSRTCPReplayWindow(1, windowSize), ErrInvalidReplayWindowSize)
	}

	// Boundary values are accepted.
	assertT.NoError(decryptContext.SetSRTPReplayWindow(1, 1))
	assertT.NoError(decryptContext.SetSRTCPReplayWindow(1, MaxReplayWindowSize))

	// Failed configurations are not stored.
	_, ok := decryptContext.SRTPReplayWindow(2)
	assertT.False(ok)
}

// TestSetReplayWindowCustomDetector verifies the deterministic outcome when a
// per-SSRC window collides with a custom replay detector factory.
func TestSetReplayWindowCustomDetector(t *testing.T) {
	assertT := assert.New(t)

	const (
		liveSSRC   = 0x1111
		futureSSRC = 0x2222
	)

	decryptContext, err := buildTestContext(profileCTR, SRTPReplayDetectorFactory(func() replaydetector.ReplayDetector {
		return replaydetector.New(64, maxROC<<16|maxSequenceNumber)
	}))
	require.NoError(t, err)
	encryptContext, err := buildTestContext(profileCTR)
	require.NoError(t, err)

	// Create a live state using the custom factory detector.
	assertT.NoError(decryptRTPForWindowTest(decryptContext, encryptRTPForWindowTest(t, encryptContext, liveSSRC, 0)))

	// Resizing the custom detector fails deterministically and stores nothing.
	assertT.ErrorIs(decryptContext.SetSRTPReplayWindow(liveSSRC, 128), ErrReplayDetectorNotResizable)
	_, ok := decryptContext.SRTPReplayWindow(liveSSRC)
	assertT.False(ok, "failed resize must not store a per-SSRC configuration")

	// Configuring an SSRC before its state exists succeeds: the per-SSRC window
	// takes precedence over the custom factory for that SSRC.
	require.NoError(t, decryptContext.SetSRTPReplayWindow(futureSSRC, 128))
	encrypted := make([][]byte, 200)
	for i := range encrypted {
		encrypted[i] = encryptRTPForWindowTest(t, encryptContext, futureSSRC, uint16(i)) //nolint:gosec
	}
	for _, i := range reversedBlockOrder(200, 100) {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, encrypted[i]),
			"packet %d must pass the per-SSRC window of 128", i)
	}
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[0]), errDuplicated)

	// A context with replay protection disabled also rejects resizing live states.
	nopContext, err := buildTestContext(profileCTR, SRTPNoReplayProtection())
	require.NoError(t, err)
	assertT.NoError(decryptRTPForWindowTest(nopContext, encryptRTPForWindowTest(t, encryptContext, liveSSRC, 1000)))
	assertT.ErrorIs(nopContext.SetSRTPReplayWindow(liveSSRC, 64), ErrReplayDetectorNotResizable)
}

// TestReplayWindowPolicyBoundaries verifies that the SRTP and SRTCP per-SSRC
// policies are independent from each other.
func TestReplayWindowPolicyBoundaries(t *testing.T) {
	assertT := assert.New(t)

	const ssrc = 0xCAFE

	encryptContext, err := buildTestContext(profileCTR)
	require.NoError(t, err)
	decryptContext, err := buildTestContext(profileCTR, SRTPReplayProtection(64), SRTCPReplayProtection(16))
	require.NoError(t, err)

	// Configuring the SRTP window leaves the SRTCP policy untouched.
	require.NoError(t, decryptContext.SetSRTPReplayWindow(ssrc, 512))
	_, ok := decryptContext.SRTCPReplayWindow(ssrc)
	assertT.False(ok, "SRTP window configuration must not leak into the SRTCP policy")

	rtcpEncrypted := make([][]byte, 100)
	for i := range rtcpEncrypted {
		rtcpEncrypted[i] = encryptRTCPForWindowTest(t, encryptContext, ssrc)
	}
	for _, pkt := range rtcpEncrypted {
		_, err = decryptContext.DecryptRTCP(nil, pkt, nil)
		assertT.NoError(err)
	}
	// Index 1 lags by 99: too old for the default SRTCP window of 16.
	_, err = decryptContext.DecryptRTCP(nil, rtcpEncrypted[0], nil)
	assertT.ErrorIs(err, errDuplicated)

	// Growing the SRTCP window at runtime keeps the still traceable accepted
	// history: index 95 is inside both the old and the new window and stays
	// rejected as a duplicate.
	require.NoError(t, decryptContext.SetSRTCPReplayWindow(ssrc, 128))
	_, err = decryptContext.DecryptRTCP(nil, rtcpEncrypted[94], nil)
	assertT.ErrorIs(err, errDuplicated, "traceable index accepted before growing must stay rejected")

	// Index 1 had already fallen out of the 16-bit window before the grow, so
	// it was no longer traceable; after growing it is indistinguishable from an
	// unseen packet and is accepted. This pins the documented grow semantics.
	_, err = decryptContext.DecryptRTCP(nil, rtcpEncrypted[0], nil)
	assertT.NoError(err, "untraceable index becomes acceptable after growing")

	// And the SRTP policy is unchanged by the SRTCP configuration.
	window, ok := decryptContext.SRTPReplayWindow(ssrc)
	require.True(t, ok)
	assertT.Equal(uint(512), window)
}

// TestPerSSRCReplayWindowSSRCReuse verifies that the per-SSRC configuration
// survives SSRC state resets (SetROC) and key updates (contextWithKey).
func TestPerSSRCReplayWindowSSRCReuse(t *testing.T) {
	assertT := assert.New(t)

	const ssrc = 0xBEEF

	encryptContext, err := buildTestContext(profileCTR)
	require.NoError(t, err)
	decryptContext, err := buildTestContext(profileCTR, SRTPReplayProtection(64))
	require.NoError(t, err)

	// The SSRC appears, then the sender is restarted with a fresh ROC (SSRC reuse).
	assertT.NoError(decryptRTPForWindowTest(decryptContext, encryptRTPForWindowTest(t, encryptContext, ssrc, 0)))
	decryptContext.SetROC(ssrc, 1)
	encryptContext.SetROC(ssrc, 1)

	// Configuring the window after the state exists resizes it in place.
	require.NoError(t, decryptContext.SetSRTPReplayWindow(ssrc, 200))

	// Deep reorder (depth 100 > default 64) passes with the configured window.
	encrypted := make([][]byte, 300)
	for i := range encrypted {
		encrypted[i] = encryptRTPForWindowTest(t, encryptContext, ssrc, uint16(i)) //nolint:gosec
	}
	for _, i := range reversedBlockOrder(300, 100) {
		assertT.NoError(decryptRTPForWindowTest(decryptContext, encrypted[i]),
			"packet %d must pass the resized window after SSRC reuse", i)
	}
	assertT.ErrorIs(decryptRTPForWindowTest(decryptContext, encrypted[0]), errDuplicated)

	// Key updates carry the per-SSRC policy over to the new context.
	keyLen, err := profileCTR.KeyLen()
	require.NoError(t, err)
	saltLen, err := profileCTR.SaltLen()
	require.NoError(t, err)
	next, err := decryptContext.contextWithKey(make([]byte, keyLen), make([]byte, saltLen), profileCTR)
	require.NoError(t, err)
	window, ok := next.SRTPReplayWindow(ssrc)
	require.True(t, ok)
	assertT.Equal(uint(200), window, "per-SSRC window must survive re-keying")
}

// TestPerSSRCReplayWindowConcurrentSession adjusts the window of a running
// session concurrently with decryption: every adjustment has a deterministic
// result and the in-order stream is delivered completely.
func TestPerSSRCReplayWindowConcurrentSession(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC      = 5000
		rtpHeaderSize = 12
		packetCount   = 500
	)
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}

	aSession, bSession := buildSessionSRTPPair(t)
	bReadStream, err := bSession.OpenReadStream(testSSRC)
	assert.NoError(t, err)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for i := range uint16(packetCount) {
			_, werr := aWriteStream.WriteRTP(
				&rtp.Header{SSRC: testSSRC, SequenceNumber: i}, append([]byte{}, testPayload...))
			if werr != nil {
				return
			}
		}
	}()

	var readerWG sync.WaitGroup
	received := 0
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			if _, perr := assertPayloadSRTP(t, bReadStream, rtpHeaderSize, testPayload); perr == nil {
				received++
			} else if errors.Is(perr, io.EOF) {
				return
			}
		}
	}()

	// Adjust the window while packets are being decrypted.
	for i := range 50 {
		assert.NoError(t, bSession.SetRemoteReplayWindow(testSSRC, uint(32+i))) //nolint:gosec
		assert.ErrorIs(t, bSession.SetRemoteReplayWindow(testSSRC, 0), ErrInvalidReplayWindowSize)
	}

	writerWG.Wait()
	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
	assert.NoError(t, bReadStream.Close())
	readerWG.Wait()

	assert.Equal(t, packetCount, received, "in-order stream must be fully delivered under concurrent resizing")
}
