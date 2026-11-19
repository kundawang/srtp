// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"encoding/binary"
	"slices"
	"sync"
	"testing"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/transport/v5/replaydetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const replayStateTestSSRC = 0xC0FFEE01

// rtpPacketAt builds an RTP packet with the given SSRC and sequence number.
func rtpPacketAt(tb testing.TB, ssrc uint32, seq uint16) []byte {
	tb.Helper()

	pkt := &rtp.Packet{
		Header:  rtp.Header{Version: 2, SSRC: ssrc, SequenceNumber: seq, Timestamp: uint32(seq)},
		Payload: rtpTestCaseDecrypted(),
	}
	raw, err := pkt.Marshal()
	require.NoError(tb, err)

	return raw
}

// rtcpPacketAt builds an RTCP packet whose sender SSRC is replayStateTestSSRC.
func rtcpPacketAt(tb testing.TB) []byte {
	tb.Helper()

	ssrc := uint32(replayStateTestSSRC)
	tb.Helper()

	// The SRTCP SSRC is read from the first SSRC field of the packet, which for
	// a PLI is the sender SSRC. Set both so the context state is keyed by ssrc.
	raw, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{SenderSSRC: ssrc, MediaSSRC: ssrc}})
	require.NoError(tb, err)

	return raw
}

// replayStateTestContext builds a context for the given profile with the given
// replay window. profileCTR/protection profile share buildTestContext keys.
func replayStateTestContext(tb testing.TB, profile ProtectionProfile, window uint) *Context {
	tb.Helper()

	ctx, err := buildTestContext(profile, SRTPReplayProtection(window), SRTCPReplayProtection(window))
	require.NoError(tb, err)

	return ctx
}

// decryptReplayStateFixture replays packets into ctx and reports, for each, whether
// decryption succeeded and the resulting plaintext.
func decryptReplayStateFixture(tb testing.TB, ctx *Context, packets [][]byte) ([]bool, [][]byte) {
	tb.Helper()

	ok := make([]bool, len(packets))
	plain := make([][]byte, len(packets))
	for i, p := range packets {
		out, err := ctx.DecryptRTP(nil, bytes.Clone(p), nil)
		ok[i] = err == nil
		plain[i] = out
	}

	return ok, plain
}

func TestReplayWindowDetectorMatchesTransportDetector(t *testing.T) {
	// The checkpointable default detector must make exactly the same decisions as
	// the detector it replaced, including the out-of-order and wrap quirks.
	maxSeq := uint64(maxROC)<<16 | uint64(maxSequenceNumber)

	sequences := []uint64{
		0, 1, 2, 63, 64, 65, 127, 128, 5000, 5001, 5002,
		maxSeq - 2, maxSeq - 1, maxSeq, maxSeq + 1,
	}

	for _, window := range []uint{1, 7, 32, 64, 65, 128, 1000} {
		for _, limit := range []uint64{maxSRTCPIndex, maxSeq} {
			ref := replaydetector.New(window, limit)
			got := newReplayWindowDetector(window, limit)
			require.Equal(t, window, got.windowSize)

			assertSame := func(seq uint64) {
				t.Helper()
				refAccept, refOK := ref.Check(seq)
				gotAccept, gotOK := got.Check(seq)
				assert.Equal(t, refOK, gotOK, "Check(%d) window=%d max=%d", seq, window, limit)
				if refOK && gotOK {
					assert.Equal(t, refAccept(), gotAccept(), "accept(%d) window=%d max=%d", seq, window, limit)
				}
			}

			// Accept in a pseudo-random but deterministic order, including
			// duplicates and out-of-window entries.
			for i := range sequences {
				seq := sequences[(i*7)%len(sequences)]
				assertSame(seq)
				assertSame(seq)
			}
			slices.Reverse(sequences)
			for _, seq := range sequences {
				assertSame(seq)
			}
			slices.Reverse(sequences)
		}
	}
}

func TestReplayWindowDetectorCheckSeqMatchesCheck(t *testing.T) {
	maxSeq := uint64(maxSRTCPIndex)
	ref := replaydetector.New(64, maxSeq)
	got := newReplayWindowDetector(64, maxSeq)

	for _, seq := range []uint64{0, 5, 70, 6, 200, 5, 0, maxSeq, maxSeq + 1} {
		refAccept, refOK := ref.Check(seq)
		gotTok := got.CheckSeq(seq)
		require.Equal(t, refOK, gotTok.Passed(), "CheckSeq(%d)", seq)
		if refOK {
			assert.Equal(t, refAccept(), got.Accept(gotTok), "Accept(%d)", seq)
		} else {
			assert.False(t, got.Accept(gotTok))
		}
	}
}

func TestReplayWindowDetectorRoundTrip(t *testing.T) {
	for _, window := range []uint{1, 8, 33, 64, 200} {
		src := newReplayWindowDetector(window, uint64(maxROC)<<16|uint64(maxSequenceNumber))
		for _, seq := range []uint64{0, 3, 4, 100, 99, 101, 102, 5, 3} {
			accept, ok := src.Check(seq)
			if ok {
				accept()
			}
		}

		latest, mask := src.exportState()
		dst := newReplayWindowDetector(window, src.maxSeq)
		require.NoError(t, dst.importState(latest, mask))

		assert.Equal(t, src.latestSeq, dst.latestSeq)
		assert.Equal(t, src.mask, dst.mask)

		// Restored detector must make the same decisions from here on.
		for _, seq := range []uint64{0, 3, 90, 100, 101, 103, 50, 200} {
			srcAccept, srcOK := src.Check(seq)
			dstAccept, dstOK := dst.Check(seq)
			require.Equal(t, srcOK, dstOK, "window=%d seq=%d", window, seq)
			if srcOK {
				assert.Equal(t, srcAccept(), dstAccept(), "window=%d seq=%d", window, seq)
			}
		}
	}
}

func TestReplayStateRoundTripSRTP(t *testing.T) {
	encryptCtx := replayStateTestContext(t, profileCTR, 64)
	recvCtx := replayStateTestContext(t, profileCTR, 64)

	// Encrypt before the switch: seq 65530, 65531, and 0 (a ROC rollover).
	var packets [][]byte
	for _, seq := range []uint16{65530, 65531, 0} {
		enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, seq), nil)
		require.NoError(t, err)
		packets = append(packets, enc)
	}

	ok, _ := decryptReplayStateFixture(t, recvCtx, packets[:2])
	require.Equal(t, []bool{true, true}, ok)
	// 0 was encrypted but not yet received at checkpoint time.
	// Checkpoint happens with ROC=1 established (via seq 0 not yet accepted: ROC still 1? no,
	// not accepted yet). Accept 65531 first: index 65531, ROC 0.
	roc, _ := recvCtx.ROC(replayStateTestSSRC)
	require.Equal(t, uint32(0), roc)

	checkpoint, err := recvCtx.ExportReplayState()
	require.NoError(t, err)

	// New process: same keys and config, replay window empty.
	switchedCtx := replayStateTestContext(t, profileCTR, 64)
	require.NoError(t, switchedCtx.RestoreReplayState(checkpoint))

	// Already accepted packets are still rejected.
	for _, p := range packets[:2] {
		_, decErr := switchedCtx.DecryptRTP(nil, bytes.Clone(p), nil)
		assert.ErrorIs(t, decErr, errDuplicated)
	}

	// The next packet continues to decrypt, including across the ROC rollover.
	next := func(seq uint16) []byte {
		enc, encErr := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, seq), nil)
		require.NoError(t, encErr)

		return enc
	}
	dec, err := switchedCtx.DecryptRTP(nil, next(65532), nil)
	require.NoError(t, err)
	assert.Equal(t, rtpPacketAt(t, replayStateTestSSRC, 65532), dec)

	// A late, out-of-order packet that was never accepted is still accepted.
	dec, err = switchedCtx.DecryptRTP(nil, packets[2], nil)
	require.NoError(t, err)
	assert.Equal(t, rtpPacketAt(t, replayStateTestSSRC, 0), dec)

	roc, _ = switchedCtx.ROC(replayStateTestSSRC)
	assert.Equal(t, uint32(1), roc)

	dec, err = switchedCtx.DecryptRTP(nil, next(1), nil)
	require.NoError(t, err)
	assert.Equal(t, rtpPacketAt(t, replayStateTestSSRC, 1), dec)
}

func TestReplayStateRoundTripSRTCP(t *testing.T) {
	encryptCtx := replayStateTestContext(t, profileCTR, 64)
	recvCtx := replayStateTestContext(t, profileCTR, 64)

	plain := rtcpPacketAt(t)
	var packets [][]byte
	for range 4 {
		enc, err := encryptCtx.EncryptRTCP(nil, plain, nil)
		require.NoError(t, err)
		packets = append(packets, enc)
	}

	okPackets := packets[:2]
	for _, p := range okPackets {
		_, err := recvCtx.DecryptRTCP(nil, bytes.Clone(p), nil)
		require.NoError(t, err)
	}
	// Index reports the last index used for encryption; the receive side has
	// seen (and accepted) indexes 1 and 2.
	idx, _ := recvCtx.Index(replayStateTestSSRC)
	require.Equal(t, uint32(0), idx, "receive side does not advance the SRTCP index counter")

	checkpoint, err := recvCtx.ExportReplayState()
	require.NoError(t, err)

	switchedCtx := replayStateTestContext(t, profileCTR, 64)
	require.NoError(t, switchedCtx.RestoreReplayState(checkpoint))

	for _, p := range okPackets {
		_, decErr := switchedCtx.DecryptRTCP(nil, bytes.Clone(p), nil)
		assert.ErrorIs(t, decErr, errDuplicated)
	}

	// The next index decrypts.
	_, err = switchedCtx.DecryptRTCP(nil, packets[2], nil)
	require.NoError(t, err)
	// The replayed packet at the previously unseen index 3 is now rejected.
	_, err = switchedCtx.DecryptRTCP(nil, packets[3], nil)
	require.NoError(t, err)
	_, err = switchedCtx.DecryptRTCP(nil, packets[3], nil)
	assert.ErrorIs(t, err, errDuplicated)

	// Replaying that packet is rejected again.
	_, err = switchedCtx.DecryptRTCP(nil, packets[2], nil)
	assert.ErrorIs(t, err, errDuplicated)
}

func TestReplayStateSRTPSRTCPIsolation(t *testing.T) {
	// SRTP and SRTCP use the same SSRC space but separate states; both must be
	// preserved and intercept independently.
	ctx := replayStateTestContext(t, profileGCM, 64)

	encryptCtx := replayStateTestContext(t, profileGCM, 64)
	rtpEnc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, 1), nil)
	require.NoError(t, err)
	rtcpEnc, err := encryptCtx.EncryptRTCP(nil, rtcpPacketAt(t), nil)
	require.NoError(t, err)

	_, err = ctx.DecryptRTP(nil, bytes.Clone(rtpEnc), nil)
	require.NoError(t, err)
	_, err = ctx.DecryptRTCP(nil, bytes.Clone(rtcpEnc), nil)
	require.NoError(t, err)

	checkpoint, err := ctx.ExportReplayState()
	require.NoError(t, err)

	restored := replayStateTestContext(t, profileGCM, 64)
	require.NoError(t, restored.RestoreReplayState(checkpoint))

	_, err = restored.DecryptRTP(nil, bytes.Clone(rtpEnc), nil)
	assert.ErrorIs(t, err, errDuplicated)
	_, err = restored.DecryptRTCP(nil, bytes.Clone(rtcpEnc), nil)
	assert.ErrorIs(t, err, errDuplicated)
}

func TestReplayStateClearSSRC(t *testing.T) {
	encryptCtx := replayStateTestContext(t, profileCTR, 64)
	ctx := replayStateTestContext(t, profileCTR, 64)

	const otherSSRC = 0xC0FFEE02

	pkt := func(ssrc uint32, seq uint16) []byte {
		enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, ssrc, seq), nil)
		require.NoError(t, err)

		return enc
	}

	cleared := pkt(replayStateTestSSRC, 100)
	untouched := pkt(otherSSRC, 200)
	for _, p := range [][]byte{cleared, untouched} {
		_, err := ctx.DecryptRTP(nil, bytes.Clone(p), nil)
		require.NoError(t, err)
	}

	checkpoint, err := ctx.ExportReplayState()
	require.NoError(t, err)
	restored := replayStateTestContext(t, profileCTR, 64)
	require.NoError(t, restored.RestoreReplayState(checkpoint))

	restored.ClearReplayState(replayStateTestSSRC)

	// The export after clearing drops that SSRC's entry: the checkpoint
	// shrinks by one SRTP entry.
	afterClear, err := restored.ExportReplayState()
	require.NoError(t, err)
	assert.Equal(t, len(checkpoint), len(afterClear)+4+8+1+8+8)

	// Cleared SSRC can be replayed; the untouched SSRC cannot.
	_, err = restored.DecryptRTP(nil, bytes.Clone(cleared), nil)
	assert.NoError(t, err)
	_, err = restored.DecryptRTP(nil, bytes.Clone(untouched), nil)
	assert.ErrorIs(t, err, errDuplicated)

	// Clearing a stream and then receiving from it again records fresh state.
	afterReplay, err := restored.ExportReplayState()
	require.NoError(t, err)
	assert.Equal(t, len(checkpoint), len(afterReplay))
}

func TestReplayStateNoKeyMaterial(t *testing.T) {
	keyLen, err := profileCTR.KeyLen()
	require.NoError(t, err)
	saltLen, err := profileCTR.SaltLen()
	require.NoError(t, err)

	// Use distinctive key material; neither the master key nor the salt may
	// appear verbatim in the checkpoint.
	masterKey := bytes.Repeat([]byte{0xAA}, keyLen)
	masterSalt := bytes.Repeat([]byte{0x55}, saltLen)

	encryptCtx, err := CreateContext(masterKey, masterSalt, profileCTR,
		SRTPReplayProtection(64), SRTCPReplayProtection(64))
	require.NoError(t, err)
	recvCtx, err := CreateContext(masterKey, masterSalt, profileCTR,
		SRTPReplayProtection(64), SRTCPReplayProtection(64))
	require.NoError(t, err)

	enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, 7), nil)
	require.NoError(t, err)
	_, err = recvCtx.DecryptRTP(nil, enc, nil)
	require.NoError(t, err)

	checkpoint, err := recvCtx.ExportReplayState()
	require.NoError(t, err)

	assert.NotContains(t, string(checkpoint), string(masterKey))
	assert.NotContains(t, string(checkpoint), string(masterSalt))

	// Session keys derived from the master key must not appear either.
	sessionKey, err := aesCmKeyDerivation(labelSRTPEncryption, masterKey, masterSalt, 0, keyLen)
	require.NoError(t, err)
	sessionSalt, err := aesCmKeyDerivation(labelSRTPSalt, masterKey, masterSalt, 0, saltLen)
	require.NoError(t, err)
	assert.NotContains(t, string(checkpoint), string(sessionKey))
	assert.NotContains(t, string(checkpoint), string(sessionSalt))

	// Header records the profile and version.
	assert.Equal(t, replayStateMagic, string(checkpoint[:len(replayStateMagic)]))
	assert.Equal(t, byte(ReplayStateVersion), checkpoint[len(replayStateMagic)])
	profileOffset := len(replayStateMagic) + 1
	assert.Equal(t, uint16(profileCTR), binary.BigEndian.Uint16(checkpoint[profileOffset:]))
}

func TestReplayStateEmptyContext(t *testing.T) {
	ctx := replayStateTestContext(t, profileCTR, 64)
	checkpoint, err := ctx.ExportReplayState()
	require.NoError(t, err)
	assert.Len(t, checkpoint, replayStateHeaderLen)

	restored := replayStateTestContext(t, profileCTR, 64)
	require.NoError(t, restored.RestoreReplayState(checkpoint))

	encryptCtx := replayStateTestContext(t, profileCTR, 64)
	enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, 1), nil)
	require.NoError(t, err)
	_, err = restored.DecryptRTP(nil, enc, nil)
	require.NoError(t, err)
}

func TestReplayStateErrors(t *testing.T) {
	encryptCtx := replayStateTestContext(t, profileCTR, 64)
	recvCtx := replayStateTestContext(t, profileCTR, 64)

	enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, 1), nil)
	require.NoError(t, err)
	_, err = recvCtx.DecryptRTP(nil, enc, nil)
	require.NoError(t, err)

	good, err := recvCtx.ExportReplayState()
	require.NoError(t, err)

	t.Run("BadVersion", func(t *testing.T) {
		bad := bytes.Clone(good)
		bad[len(replayStateMagic)] = ReplayStateVersion + 1
		err := replayStateTestContext(t, profileCTR, 64).RestoreReplayState(bad)
		assert.ErrorIs(t, err, ErrReplayStateVersion)
	})

	t.Run("BadMagic", func(t *testing.T) {
		bad := bytes.Clone(good)
		bad[0] ^= 0xff
		err := replayStateTestContext(t, profileCTR, 64).RestoreReplayState(bad)
		assert.ErrorIs(t, err, ErrReplayStateCorrupted)
	})

	t.Run("Truncated", func(t *testing.T) {
		for _, n := range []int{
			0, 1, len(replayStateMagic), len(replayStateMagic) + 1,
			replayStateHeaderLen - 1, len(good) - 1,
		} {
			err := replayStateTestContext(t, profileCTR, 64).RestoreReplayState(good[:n])
			assert.ErrorIs(t, err, ErrReplayStateTruncated, "truncated to %d bytes", n)
		}
	})

	t.Run("TrailingBytes", func(t *testing.T) {
		bad := append(bytes.Clone(good), 0x00)
		err := replayStateTestContext(t, profileCTR, 64).RestoreReplayState(bad)
		assert.ErrorIs(t, err, ErrReplayStateCorrupted)
	})

	t.Run("WrongKey", func(t *testing.T) {
		keyLen, err := profileCTR.KeyLen()
		require.NoError(t, err)
		saltLen, err := profileCTR.SaltLen()
		require.NoError(t, err)

		otherKey := bytes.Repeat([]byte{0x11}, keyLen)
		otherSalt := bytes.Repeat([]byte{0x22}, saltLen)
		other, err := CreateContext(otherKey, otherSalt, profileCTR,
			SRTPReplayProtection(64), SRTCPReplayProtection(64))
		require.NoError(t, err)

		assert.ErrorIs(t, other.RestoreReplayState(good), ErrReplayStateMismatch)
	})

	t.Run("WrongProfile", func(t *testing.T) {
		other, err := buildTestContext(profileGCM, SRTPReplayProtection(64), SRTCPReplayProtection(64))
		require.NoError(t, err)
		assert.ErrorIs(t, other.RestoreReplayState(good), ErrReplayStateMismatch)
	})

	t.Run("WrongReplayWindow", func(t *testing.T) {
		other := replayStateTestContext(t, profileCTR, 32)
		assert.ErrorIs(t, other.RestoreReplayState(good), ErrReplayStateMismatch)
	})

	t.Run("WrongEncryptionConfig", func(t *testing.T) {
		other, err := buildTestContext(profileCTR,
			SRTPReplayProtection(64), SRTCPReplayProtection(64), SRTPNoEncryption())
		require.NoError(t, err)
		assert.ErrorIs(t, other.RestoreReplayState(good), ErrReplayStateMismatch)
	})

	t.Run("SignatureKeyMaterialDiffers", func(t *testing.T) {
		// A checkpoint from a context with different auth tag or cryptex settings
		// must be rejected even with the same key and profile.
		other, err := buildTestContext(profileCTR,
			SRTPReplayProtection(64), SRTCPReplayProtection(64), SRTPAuthenticationTagLength(4))
		require.NoError(t, err)
		assert.ErrorIs(t, other.RestoreReplayState(good), ErrReplayStateMismatch)
	})

	t.Run("CounterOverflow", func(t *testing.T) {
		// Patch the SRTP index in the checkpoint beyond 2^48-1.
		idx := replayStateHeaderLen + 4 // skip SSRC
		bad := bytes.Clone(good)
		binary.BigEndian.PutUint64(bad[idx:], srtpMaxIndex+1)
		err := replayStateTestContext(t, profileCTR, 64).RestoreReplayState(bad)
		assert.ErrorIs(t, err, ErrReplayStateCounterOverflow)

		// A replay window head beyond the maximum is rejected too.
		bad = bytes.Clone(good)
		latestOff := replayStateHeaderLen + 4 + 8 + 1
		binary.BigEndian.PutUint64(bad[latestOff:], srtpMaxIndex+1)
		err = replayStateTestContext(t, profileCTR, 64).RestoreReplayState(bad)
		assert.ErrorIs(t, err, ErrReplayStateCounterOverflow)
	})

	t.Run("CorruptedBitmap", func(t *testing.T) {
		// With a window that is not a multiple of 8, the unused high bits of
		// the last bitmap byte must be zero.
		ctx := replayStateTestContext(t, profileCTR, 60)
		enc := func() []byte {
			encryptCtx := replayStateTestContext(t, profileCTR, 60)
			out, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, 1), nil)
			require.NoError(t, err)
			_, err = ctx.DecryptRTP(nil, out, nil)
			require.NoError(t, err)

			return out
		}
		_ = enc()

		snap, err := ctx.ExportReplayState()
		require.NoError(t, err)
		lastMaskByte := len(snap) - 1
		snap[lastMaskByte] |= 0x80
		err = replayStateTestContext(t, profileCTR, 60).RestoreReplayState(snap)
		assert.ErrorIs(t, err, ErrReplayStateCorrupted)
	})

	t.Run("DuplicateSSRC", func(t *testing.T) {
		src := replayStateTestContext(t, profileCTR, 64)
		encryptCtx := replayStateTestContext(t, profileCTR, 64)
		for _, ssrc := range []uint32{replayStateTestSSRC, replayStateTestSSRC + 1} {
			en, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, ssrc, 1), nil)
			require.NoError(t, err)
			_, err = src.DecryptRTP(nil, en, nil)
			require.NoError(t, err)
		}
		two, err := src.ExportReplayState()
		require.NoError(t, err)

		// Entry layout for a 64-bit window: ssrc(4) index(8) rollover(1)
		// latest(8) mask(8). Copy the first entry's SSRC into the second.
		entryLen := 4 + 8 + 1 + 8 + 8
		second := replayStateHeaderLen + entryLen
		require.LessOrEqual(t, second+4, len(two))
		copy(two[second:second+4], two[replayStateHeaderLen:replayStateHeaderLen+4])
		err = replayStateTestContext(t, profileCTR, 64).RestoreReplayState(two)
		assert.ErrorIs(t, err, ErrReplayStateCorrupted)
	})

	t.Run("AlreadyRestored", func(t *testing.T) {
		ctx := replayStateTestContext(t, profileCTR, 64)
		require.NoError(t, ctx.RestoreReplayState(good))
		assert.ErrorIs(t, ctx.RestoreReplayState(good), ErrReplayStateAlreadyRestored)
	})

	t.Run("ContextAlreadyUsed", func(t *testing.T) {
		used := replayStateTestContext(t, profileCTR, 64)
		_, err := used.DecryptRTP(nil, bytes.Clone(enc), nil)
		require.NoError(t, err)
		assert.ErrorIs(t, used.RestoreReplayState(good), ErrReplayStateAlreadyRestored)
	})

	t.Run("ErrorLeavesContextUntouched", func(t *testing.T) {
		ctx := replayStateTestContext(t, profileCTR, 64)
		bad := bytes.Clone(good)
		binary.BigEndian.PutUint64(bad[replayStateHeaderLen+4:], srtpMaxIndex+1)
		require.ErrorIs(t, ctx.RestoreReplayState(bad), ErrReplayStateCounterOverflow)

		// A valid restore still works afterwards, and the original packet is
		// rejected as a duplicate.
		require.NoError(t, ctx.RestoreReplayState(good))
		_, err := ctx.DecryptRTP(nil, bytes.Clone(enc), nil)
		assert.ErrorIs(t, err, errDuplicated)
	})
}

func TestReplayStateCustomDetector(t *testing.T) {
	keyLen, err := profileCTR.KeyLen()
	require.NoError(t, err)
	saltLen, err := profileCTR.SaltLen()
	require.NoError(t, err)

	encryptCtx, err := CreateContext(bytes.Repeat([]byte{0xAA}, keyLen), bytes.Repeat([]byte{0x55}, saltLen),
		profileCTR, SRTPReplayProtection(64), SRTCPReplayProtection(64))
	require.NoError(t, err)
	enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, 1), nil)
	require.NoError(t, err)

	t.Run("CustomDetectorWithState", func(t *testing.T) {
		ctx, err := CreateContext(bytes.Repeat([]byte{0xAA}, keyLen), bytes.Repeat([]byte{0x55}, saltLen),
			profileCTR,
			SRTPReplayDetectorFactory(func() replaydetector.ReplayDetector {
				return replaydetector.New(64, srtpMaxIndex)
			}),
			SRTCPReplayProtection(64),
		)
		require.NoError(t, err)
		_, err = ctx.DecryptRTP(nil, enc, nil)
		require.NoError(t, err)

		_, err = ctx.ExportReplayState()
		assert.ErrorIs(t, err, ErrReplayStateUnsupported)
	})

	t.Run("CustomDetectorWithoutState", func(t *testing.T) {
		// A custom factory is never checkpointable, even when it produces a
		// detector that happens to hold no state.
		ctx, err := CreateContext(bytes.Repeat([]byte{0xAA}, keyLen), bytes.Repeat([]byte{0x55}, saltLen),
			profileCTR,
			SRTPReplayDetectorFactory(func() replaydetector.ReplayDetector { return &nopReplayDetector{} }),
			SRTCPReplayProtection(64),
		)
		require.NoError(t, err)

		_, err = ctx.ExportReplayState()
		assert.ErrorIs(t, err, ErrReplayStateUnsupported)
	})

	t.Run("NoReplayProtection", func(t *testing.T) {
		// With no per-SSRC state yet there is nothing that cannot be exported.
		ctx, err := CreateContext(bytes.Repeat([]byte{0xAA}, keyLen), bytes.Repeat([]byte{0x55}, saltLen),
			profileCTR, SRTPNoReplayProtection(), SRTCPNoReplayProtection())
		require.NoError(t, err)

		checkpoint, err := ctx.ExportReplayState()
		require.NoError(t, err)
		assert.Len(t, checkpoint, replayStateHeaderLen)

		// With state present the ROC/index cannot be exported, so exporting
		// must fail loudly instead of producing a useless checkpoint.
		_, err = ctx.DecryptRTP(nil, bytes.Clone(enc), nil)
		require.NoError(t, err)
		_, err = ctx.ExportReplayState()
		assert.ErrorIs(t, err, ErrReplayStateUnsupported)
	})
}

func TestReplayStateLaterOptionOverridesWindow(t *testing.T) {
	// A later option may disable replay protection after a window was set, so
	// the Context keeps a stale window. The checkpoint must not advertise it,
	// or it could not be restored into an identically built Context.
	keyLen, err := profileCTR.KeyLen()
	require.NoError(t, err)
	saltLen, err := profileCTR.SaltLen()
	require.NoError(t, err)

	build := func() *Context {
		ctx, ctxErr := CreateContext(bytes.Repeat([]byte{0xAA}, keyLen), bytes.Repeat([]byte{0x55}, saltLen),
			profileCTR,
			SRTPReplayProtection(64), SRTCPReplayProtection(64),
			SRTPNoReplayProtection(), SRTCPNoReplayProtection(),
		)
		require.NoError(t, ctxErr)

		return ctx
	}

	checkpoint, err := build().ExportReplayState()
	require.NoError(t, err)
	assert.Len(t, checkpoint, replayStateHeaderLen)

	// The advertised windows are zero even though the context once had them.
	const srtpWindowOffset = len(replayStateMagic) + 1 + 2 + 1 + replayStateKeyIDLen
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(checkpoint[srtpWindowOffset:]))
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(checkpoint[srtpWindowOffset+4:]))

	restored := build()
	require.NoError(t, restored.RestoreReplayState(checkpoint))
}

func TestReplayStateSRTCPIndexContinues(t *testing.T) {
	// The SRTCP index is only meaningful on the sending side. A context that
	// both sends and receives (as the test contexts do) must keep the index so
	// that encryption continues at the same value.
	sendCtx := replayStateTestContext(t, profileCTR, 64)
	recvCtx := replayStateTestContext(t, profileCTR, 64)

	plain := rtcpPacketAt(t)
	var sent [][]byte
	for range 3 {
		enc, err := sendCtx.EncryptRTCP(nil, plain, nil)
		require.NoError(t, err)
		sent = append(sent, enc)
	}

	// Receive only the first packet; the send-side index is what is exported.
	_, err := recvCtx.DecryptRTCP(nil, bytes.Clone(sent[0]), nil)
	require.NoError(t, err)

	// Give the receive context a matching send-side index.
	recvCtx.SetIndex(replayStateTestSSRC, 3)
	checkpoint, err := recvCtx.ExportReplayState()
	require.NoError(t, err)

	restored := replayStateTestContext(t, profileCTR, 64)
	require.NoError(t, restored.RestoreReplayState(checkpoint))

	idx, ok := restored.Index(replayStateTestSSRC)
	require.True(t, ok)
	assert.Equal(t, uint32(3), idx)

	// The next encryption continues at index 4. The SRTCP index sits before the
	// auth tag, so read it with the package helper.
	enc, err := restored.EncryptRTCP(nil, plain, nil)
	require.NoError(t, err)
	authTagLen, err := profileCTR.AuthTagRTCPLen()
	require.NoError(t, err)
	assert.Equal(t, uint32(4), getRTCPIndex(enc, authTagLen))
}

func TestReplayStateConcurrentSnapshot(t *testing.T) {
	// Decryption and snapshotting must race safely (run with -race). Every
	// checkpoint taken mid-stream must be internally consistent, i.e. it must
	// be restorable and must not contain torn SSRC entries.
	encryptCtx := replayStateTestContext(t, profileCTR, 64)
	recvCtx := replayStateTestContext(t, profileCTR, 64)

	const (
		numSSRC    = 4
		numPackets = 400
	)
	packets := make([][][]byte, numSSRC)
	for s := range numSSRC {
		seq := uint16(1)
		for range numPackets {
			enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, uint32(s+1), seq), nil)
			require.NoError(t, err)
			packets[s] = append(packets[s], enc)
			seq++
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for s := range numSSRC {
			for _, p := range packets[s] {
				_, _ = recvCtx.DecryptRTP(nil, p, nil)
			}
		}
	}()

	var snapshots [][]byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			snap, err := recvCtx.ExportReplayState()
			require.NoError(t, err)
			snapshots = append(snapshots, snap)
		}
	}()
	wg.Wait()

	require.NotEmpty(t, snapshots)
	for i, snap := range snapshots {
		restored := replayStateTestContext(t, profileCTR, 64)
		require.NoError(t, restored.RestoreReplayState(snap), "snapshot %d must be consistent", i)
	}
}

func TestReplayStateSessionWrappers(t *testing.T) {
	// Session wrappers must expose the remote (decrypting) context's state.
	ctx := replayStateTestContext(t, profileCTR, 64)
	encryptCtx := replayStateTestContext(t, profileCTR, 64)
	enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(t, replayStateTestSSRC, 1), nil)
	require.NoError(t, err)
	_, err = ctx.DecryptRTP(nil, enc, nil)
	require.NoError(t, err)

	sess := &SessionSRTP{session: session{remoteContext: ctx}}
	checkpoint, err := sess.ExportReplayState()
	require.NoError(t, err)
	assert.NotEmpty(t, checkpoint)

	target := &SessionSRTP{session: session{remoteContext: replayStateTestContext(t, profileCTR, 64)}}
	require.NoError(t, target.RestoreReplayState(checkpoint))
	_, err = target.remoteContext.DecryptRTP(nil, bytes.Clone(enc), nil)
	assert.ErrorIs(t, err, errDuplicated)

	target.ClearReplayState(replayStateTestSSRC)
	_, err = target.remoteContext.DecryptRTP(nil, bytes.Clone(enc), nil)
	assert.NoError(t, err)
}
