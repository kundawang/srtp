// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixtures below are generated through the normal encryption path and then
// replayed as raw bytes. They straddle the 16-bit sequence number wrap
// (65535 -> 0) and contain out-of-order and duplicate arrivals, so the same
// input can be fed to a context that received traffic in one process and to a
// fresh context that restored a checkpoint.

type srtpFixturePacket struct {
	name string
	seq  uint16
	dup  bool
}

func srtpFixturePackets() []srtpFixturePacket {
	// Head: pre-wrap packets with one late arrival, then the wrap itself.
	// Tail: post-wrap packets with out-of-order and duplicate arrivals. All
	// tail sequence numbers are close enough to the window head that the ROC
	// guess is unambiguous, which is what makes the switch a fair comparison.
	return []srtpFixturePacket{
		{name: "pre-wrap-65532", seq: 65532},
		{name: "pre-wrap-65534", seq: 65534},
		{name: "pre-wrap-65535", seq: 65535},
		{name: "late-65533", seq: 65533},
		{name: "wrap-0", seq: 0},
		{name: "wrap-1", seq: 1},
		// --- process switch happens here ---
		{name: "post-wrap-2", seq: 2},
		{name: "post-wrap-4", seq: 4},
		{name: "late-3", seq: 3},
		{name: "dup-2", seq: 2, dup: true},
		{name: "post-wrap-5", seq: 5},
		{name: "dup-0", seq: 0, dup: true},
		{name: "post-wrap-6", seq: 6},
	}
}

// srtpFixtureChunks returns the packet counts received before and after the
// process switch.
func srtpFixtureChunks() (headLen, tailLen int) {
	all := srtpFixturePackets()

	return 6, len(all) - 6
}

// buildSRTPFixture encrypts the fixture packets once and returns the raw bytes
// keyed by fixture index.
func buildSRTPFixture(tb testing.TB, profile ProtectionProfile) [][]byte {
	tb.Helper()

	encryptCtx := replayStateTestContext(tb, profile, 64)
	raw := make([][]byte, 0, len(srtpFixturePackets()))
	for _, p := range srtpFixturePackets() {
		enc, err := encryptCtx.EncryptRTP(nil, rtpPacketAt(tb, replayStateTestSSRC, p.seq), nil)
		require.NoError(tb, err)
		raw = append(raw, enc)
	}

	return raw
}

// receiveSRTPFixture replays raw packets and reports accept/reject plus the
// plaintext of accepted packets.
func receiveSRTPFixture(tb testing.TB, ctx *Context, raw [][]byte) ([]bool, [][]byte) {
	tb.Helper()

	accepted := make([]bool, len(raw))
	plain := make([][]byte, len(raw))
	for i, p := range raw {
		out, err := ctx.DecryptRTP(nil, bytes.Clone(p), nil)
		accepted[i] = err == nil
		plain[i] = out
	}

	return accepted, plain
}

// TestReplayStateFixtureAcrossSwitch is the end-to-end requirement-4 test:
// the tail of an SRTP fixture spanning a 16-bit wrap, with out-of-order and
// duplicate packets, is received identically whether the receiver processed
// the head itself or restored a checkpoint taken after the head.
func TestReplayStateFixtureAcrossSwitch(t *testing.T) {
	for _, profile := range []ProtectionProfile{profileCTR, profileGCM} {
		t.Run(profile.String(), func(t *testing.T) {
			raw := buildSRTPFixture(t, profile)
			headLen, tailLen := srtpFixtureChunks()
			require.Equal(t, len(raw), headLen+tailLen)
			fixture := srtpFixturePackets()

			// (a) Continuous receive in a single context.
			continuous := replayStateTestContext(t, profile, 64)
			continuousAccepted, continuousPlain := receiveSRTPFixture(t, continuous, raw)

			// (b) Receive the head, checkpoint, restore into a fresh process,
			// then receive the tail.
			first := replayStateTestContext(t, profile, 64)
			headAccepted, headPlain := receiveSRTPFixture(t, first, raw[:headLen])
			for i := range headLen {
				require.True(t, headAccepted[i], "head packet %s must be accepted", fixture[i].name)
			}
			checkpoint, err := first.ExportReplayState()
			require.NoError(t, err)

			second := replayStateTestContext(t, profile, 64)
			require.NoError(t, second.RestoreReplayState(checkpoint))

			// Already accepted packets are still rejected after the switch.
			replayedAccepted, _ := receiveSRTPFixture(t, second, raw[:headLen])
			for i := range headLen {
				assert.False(t, replayedAccepted[i], "pre-checkpoint packet %s must stay rejected", fixture[i].name)
			}

			// And a genuine replay window with the checkpoint restored matches
			// a continuous receiver packet for packet.
			_, _ = headAccepted, headPlain

			tailRaw := raw[headLen:]
			tailAccepted, tailPlain := receiveSRTPFixture(t, second, tailRaw)
			assert.Equal(t, continuousAccepted[headLen:], tailAccepted,
				"accept/reject decisions must match across the switch")
			for i := range tailLen {
				assert.Equal(t, continuousPlain[headLen+i], tailPlain[i],
					"tail packet %s plaintext", fixture[headLen+i].name)
			}

			// The wrap really was exercised and late packets were accepted.
			assert.True(t, continuousAccepted[3], "late pre-wrap packet must be accepted")
			assert.True(t, continuousAccepted[8], "late post-wrap packet must be accepted")
			assert.False(t, continuousAccepted[9], "duplicate post-wrap packet must be rejected")
			assert.False(t, continuousAccepted[11], "duplicate seq 0 must be rejected")

			// ROC kept climbing across the wrap and was restored.
			roc, ok := first.ROC(replayStateTestSSRC)
			require.True(t, ok)
			require.Equal(t, uint32(1), roc)

			// The restored context continues past the checkpoint without a
			// second ROC rollover.
			roc, ok = second.ROC(replayStateTestSSRC)
			require.True(t, ok)
			assert.Equal(t, uint32(1), roc)
		})
	}
}

// TestReplayStateFixtureFreshTail verifies that after the switch the tail is
// accepted exactly as a continuous receiver accepts it, and that every packet
// accepted before the checkpoint stays rejected.
func TestReplayStateFixtureFreshTail(t *testing.T) {
	for _, profile := range []ProtectionProfile{profileCTR, profileGCM} {
		t.Run(profile.String(), func(t *testing.T) {
			raw := buildSRTPFixture(t, profile)
			headLen, tailLen := srtpFixtureChunks()
			fixture := srtpFixturePackets()

			continuous := replayStateTestContext(t, profile, 64)
			continuousAccepted, continuousPlain := receiveSRTPFixture(t, continuous, raw)

			first := replayStateTestContext(t, profile, 64)
			headAccepted, _ := receiveSRTPFixture(t, first, raw[:headLen])
			for i := range headLen {
				require.True(t, headAccepted[i])
			}
			checkpoint, err := first.ExportReplayState()
			require.NoError(t, err)

			second := replayStateTestContext(t, profile, 64)
			require.NoError(t, second.RestoreReplayState(checkpoint))

			tailAccepted, tailPlain := receiveSRTPFixture(t, second, raw[headLen:])
			assert.Equal(t, continuousAccepted[headLen:], tailAccepted)
			for i := range tailLen {
				assert.Equal(t, continuousPlain[headLen+i], tailPlain[i], "tail packet %s", fixture[headLen+i].name)
			}

			// Everything accepted before the checkpoint is still rejected.
			replayAccepted, _ := receiveSRTPFixture(t, second, raw[:headLen])
			for i := range headLen {
				assert.False(t, replayAccepted[i], "pre-checkpoint packet %s must stay rejected", fixture[i].name)
			}
		})
	}
}

// buildSRTCPFixture encrypts a run of SRTCP packets with consecutive indexes
// starting at base, using the normal encryption path.
func buildSRTCPFixture(tb testing.TB, base uint32, n int) [][]byte {
	tb.Helper()

	encryptCtx := replayStateTestContext(tb, profileCTR, 64)
	plain := rtcpPacketAt(tb)
	raw := make([][]byte, 0, n)
	for i := range n {
		encryptCtx.SetIndex(replayStateTestSSRC, base+uint32(i)-1) //nolint:gosec // test fixture
		enc, err := encryptCtx.EncryptRTCP(nil, plain, nil)
		require.NoError(tb, err)
		raw = append(raw, enc)
	}

	return raw
}

func TestReplayStateFixtureSRTCPOutOfOrder(t *testing.T) {
	// Start near the top of the usable SRTCP index space.
	raw := buildSRTCPFixture(t, maxSRTCPIndex-8, 8)
	require.Len(t, raw, 8)

	// Arrival order: 1,2,3,8, late 4, duplicate 1, 5,6,7.
	order := []int{0, 1, 2, 7, 3, 0, 4, 5, 6}
	arrange := func() [][]byte {
		out := make([][]byte, len(order))
		for i, idx := range order {
			out[i] = raw[idx]
		}

		return out
	}
	receive := func(ctx *Context, packets [][]byte) []bool {
		accepted := make([]bool, len(packets))
		for i, p := range packets {
			_, err := ctx.DecryptRTCP(nil, bytes.Clone(p), nil)
			accepted[i] = err == nil
		}

		return accepted
	}

	continuous := replayStateTestContext(t, profileCTR, 64)
	continuousAccepted := receive(continuous, arrange())
	assert.Equal(t, []bool{true, true, true, true, true, false, true, true, true}, continuousAccepted)

	// Switch in the middle of the arrival order: head = first 4 arrivals.
	const headLen = 4
	first := replayStateTestContext(t, profileCTR, 64)
	headAccepted := receive(first, arrange()[:headLen])
	require.Equal(t, continuousAccepted[:headLen], headAccepted)

	checkpoint, err := first.ExportReplayState()
	require.NoError(t, err)

	second := replayStateTestContext(t, profileCTR, 64)
	require.NoError(t, second.RestoreReplayState(checkpoint))

	// Tail replay from the restored context must match the continuous one.
	tailAccepted := receive(second, arrange()[headLen:])
	assert.Equal(t, continuousAccepted[headLen:], tailAccepted)

	// The duplicate index 1 that arrived after the switch is still rejected,
	// and it is rejected as a duplicate, not as an authentication failure.
	_, err = second.DecryptRTCP(nil, bytes.Clone(arrange()[headLen:][1]), nil)
	assert.ErrorIs(t, err, errDuplicated, "duplicate SRTCP index must be rejected after restore")
}

// TestReplayStateFixtureOnWireTamper proves the checkpoint does not carry
// enough information to forge packets and that the restored context rejects
// tampered ciphertext exactly like the original one.
func TestReplayStateFixtureOnWireTamper(t *testing.T) {
	raw := buildSRTPFixture(t, profileCTR)
	headLen, _ := srtpFixtureChunks()

	first := replayStateTestContext(t, profileCTR, 64)
	_, _ = receiveSRTPFixture(t, first, raw[:headLen])
	checkpoint, err := first.ExportReplayState()
	require.NoError(t, err)

	second := replayStateTestContext(t, profileCTR, 64)
	require.NoError(t, second.RestoreReplayState(checkpoint))

	// Flip a payload bit in a not-yet-seen packet; it must fail authentication
	// and must not advance the replay window.
	tampered := bytes.Clone(raw[headLen])
	tampered[12] ^= 0xff
	_, err = second.DecryptRTP(nil, tampered, nil)
	assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)

	// The genuine packet is still accepted afterwards.
	_, err = second.DecryptRTP(nil, bytes.Clone(raw[headLen]), nil)
	assert.NoError(t, err)
}
