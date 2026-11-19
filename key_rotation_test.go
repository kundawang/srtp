// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"math"
	"sync"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var rotationTestKeys = []RotationKey{ //nolint:gochecknoglobals
	{
		MKI:       []byte{0x11, 0x11, 0x11, 0x11},
		MasterKey: bytes.Repeat([]byte{0xA1}, 16),
		// Salt is zeroed on the last 4 bytes to keep keys distinct but valid.
		MasterSalt: bytes.Repeat([]byte{0xB1}, 14),
	},
	{
		MKI:        []byte{0x22, 0x22, 0x22, 0x22},
		MasterKey:  bytes.Repeat([]byte{0xA2}, 16),
		MasterSalt: bytes.Repeat([]byte{0xB2}, 14),
	},
	{
		MKI:        []byte{0x33, 0x33, 0x33, 0x33},
		MasterKey:  bytes.Repeat([]byte{0xA3}, 16),
		MasterSalt: bytes.Repeat([]byte{0xB3}, 14),
	},
}

func newRotationContext(t *testing.T, packetsPerKey, grace uint64, extraOpts ...ContextOption) *Context {
	t.Helper()

	opts := append([]ContextOption{
		MasterKeyIndicator(rotationTestKeys[0].MKI),
		SRTPReplayProtection(64),
		SRTPKeyRotation(rotationTestKeys[1:], packetsPerKey, grace),
	}, extraOpts...)
	ctx, err := CreateContext(rotationTestKeys[0].MasterKey, rotationTestKeys[0].MasterSalt, profileCTR, opts...)
	require.NoError(t, err)

	return ctx
}

func rotationTestPacket(t *testing.T, ssrc uint32, sequenceNumber uint16) []byte {
	t.Helper()

	raw, err := (&rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    96,
			SequenceNumber: sequenceNumber,
			Timestamp:      0x11223344,
			SSRC:           ssrc,
		},
		Payload: []byte{byte(sequenceNumber >> 8), byte(sequenceNumber), 0x42, 0x42},
	}).Marshal()
	require.NoError(t, err)

	return raw
}

func encryptSeq(t *testing.T, ctx *Context, ssrc uint32, sequenceNumber uint16) []byte {
	t.Helper()

	encrypted, err := ctx.EncryptRTP(nil, rotationTestPacket(t, ssrc, sequenceNumber), nil)
	require.NoError(t, err)

	return encrypted
}

// packetMKI extracts the MKI of an encrypted packet. profileCTR uses a 10-byte
// auth tag and the test MKIs are 4 bytes long.
func packetMKI(t *testing.T, encrypted []byte) []byte {
	t.Helper()

	authTagLen := 10
	mkiLen := len(rotationTestKeys[0].MKI)
	require.Greater(t, len(encrypted), authTagLen+mkiLen)

	return encrypted[len(encrypted)-authTagLen-mkiLen : len(encrypted)-authTagLen]
}

func decryptSeq(t *testing.T, ctx *Context, encrypted []byte) error {
	t.Helper()

	_, err := ctx.DecryptRTP(nil, encrypted, nil)

	return err
}

// TestKeyRotationSendBoundaries verifies that the sender rotates keys
// automatically after packetsPerKey packets, that each SSRC is counted
// independently, that the last key keeps being used once the sequence is
// exhausted, and that the state is observable per SSRC.
func TestKeyRotationSendBoundaries(t *testing.T) {
	const packetsPerKey = 4

	enc := newRotationContext(t, packetsPerKey, 2)
	const ssrcA, ssrcB = 0x0A0A0A0A, 0x0B0B0B0B

	// Three keys total: seq 0-3 -> key0, 4-7 -> key1, 8+ -> key2 (last key).
	for seq := uint16(0); seq < 14; seq++ {
		encrypted := encryptSeq(t, enc, ssrcA, seq)

		expectedKey := rotationTestKeys[min(int(seq)/packetsPerKey, len(rotationTestKeys)-1)]
		assert.Equal(t, expectedKey.MKI, packetMKI(t, encrypted), "seq=%d", seq)
	}

	state, ok := enc.SendRotationState(ssrcA)
	require.True(t, ok)
	assert.Equal(t, 2, state.KeyIndex)
	assert.Equal(t, rotationTestKeys[2].MKI, state.MKI)
	assert.Equal(t, uint64(6), state.PacketsWithCurrentKey) // seq 8..13
	assert.Equal(t, len(rotationTestKeys), state.KeyCount)
	assert.True(t, state.LastKey)

	// SSRC B has its own independent counter: 3 packets must still be on key0.
	for seq := uint16(0); seq < 3; seq++ {
		encrypted := encryptSeq(t, enc, ssrcB, seq)
		assert.Equal(t, rotationTestKeys[0].MKI, packetMKI(t, encrypted), "ssrcB seq=%d", seq)
	}

	state, ok = enc.SendRotationState(ssrcB)
	require.True(t, ok)
	assert.Equal(t, 0, state.KeyIndex)
	assert.Equal(t, uint64(3), state.PacketsWithCurrentKey)
	assert.False(t, state.LastKey)

	// An SSRC without any packet has no observable state.
	_, ok = enc.SendRotationState(0x0C0C0C0C)
	assert.False(t, ok)
}

// TestKeyRotationReceiveGraceAndLatePackets verifies that the receiver accepts
// legitimate late packets with an old MKI during the grace period, keeps replay
// protection per key, and removes old keys once the grace period elapses.
func TestKeyRotationReceiveGraceAndLatePackets(t *testing.T) {
	const (
		packetsPerKey = 4
		grace         = 2
		ssrc          = 0x0A0A0A0A
	)

	enc := newRotationContext(t, packetsPerKey, grace)
	dec := newRotationContext(t, packetsPerKey, grace)

	// key0: seq 0-3, key1: seq 4-7, key2: seq 8-11.
	packets := map[uint16][]byte{}
	for seq := uint16(0); seq < 12; seq++ {
		packets[seq] = encryptSeq(t, enc, ssrc, seq)
	}

	expectOK := func(seq uint16) {
		t.Helper()
		decrypted, err := dec.DecryptRTP(nil, packets[seq], nil)
		require.NoError(t, err, "seq=%d", seq)
		assert.Equal(t, rotationTestPacket(t, ssrc, seq), decrypted, "seq=%d", seq)
	}
	expectErr := func(seq uint16, target error) {
		t.Helper()
		assert.ErrorIs(t, decryptSeq(t, dec, packets[seq]), target, "seq=%d", seq)
	}

	expectOK(0)
	expectOK(1)
	expectOK(4) // rotation to key1 detected
	expectOK(5)
	expectOK(2)                 // late key0 packet within the grace period
	expectErr(2, errDuplicated) // replayed key0 packet rejected by key0's own detector
	expectOK(6)
	expectOK(3) // grace period still running: 2 packets received since rotation
	expectOK(7) // grace period elapsed (3 > 2): key0 is removed
	expectErr(3, ErrMKINotFound)
	expectOK(8)                 // rotation to key2
	expectErr(8, errDuplicated) // replayed key2 packet rejected
	expectOK(9)
	expectOK(10)
	expectOK(11)

	state, ok := dec.ReceiveRotationState(ssrc)
	require.True(t, ok)
	assert.Equal(t, 2, state.KeyIndex)
	assert.Equal(t, rotationTestKeys[2].MKI, state.MKI)
	assert.Equal(t, uint64(3), state.PacketsWithCurrentKey) // seq 9, 10, 11
	assert.True(t, state.LastKey)
}

// TestKeyRotationDualSSRCRoundTrip verifies an interleaved encrypt/decrypt
// round trip across all three keys for two SSRCs.
func TestKeyRotationDualSSRCRoundTrip(t *testing.T) {
	const packetsPerKey = 3

	enc := newRotationContext(t, packetsPerKey, 1)
	dec := newRotationContext(t, packetsPerKey, 1)
	const ssrcA, ssrcB = 0x0A0A0A0A, 0x0B0B0B0B

	for seq := uint16(0); seq < 9; seq++ {
		for _, ssrc := range []uint32{ssrcA, ssrcB} {
			encrypted := encryptSeq(t, enc, ssrc, seq)
			decrypted, err := dec.DecryptRTP(nil, encrypted, nil)
			require.NoError(t, err, "ssrc=%d seq=%d", ssrc, seq)
			assert.Equal(t, rotationTestPacket(t, ssrc, seq), decrypted)
		}
	}

	for _, ssrc := range []uint32{ssrcA, ssrcB} {
		recvState, ok := dec.ReceiveRotationState(ssrc)
		require.True(t, ok, "ssrc=%d", ssrc)
		assert.Equal(t, 2, recvState.KeyIndex, "ssrc=%d", ssrc)
		assert.True(t, recvState.LastKey, "ssrc=%d", ssrc)

		sendState, ok := enc.SendRotationState(ssrc)
		require.True(t, ok, "ssrc=%d", ssrc)
		assert.Equal(t, 2, sendState.KeyIndex, "ssrc=%d", ssrc)
	}
}

// TestKeyRotationConfigErrors verifies invalid rotation configurations are
// rejected with clear errors.
func TestKeyRotationConfigErrors(t *testing.T) {
	key := rotationTestKeys[0]
	newCtx := func(opts ...ContextOption) error {
		_, err := CreateContext(key.MasterKey, key.MasterSalt, profileCTR, opts...)

		return err
	}

	assert.ErrorIs(t, newCtx(
		MasterKeyIndicator(key.MKI),
		SRTPKeyRotation(nil, 4, 2),
	), errRotationNoKeys, "empty key sequence")

	assert.ErrorIs(t, newCtx(
		SRTPKeyRotation(rotationTestKeys[1:], 4, 2),
	), errMKIIsNotEnabled, "rotation without MKI on the initial key")

	assert.ErrorIs(t, newCtx(
		MasterKeyIndicator(key.MKI),
		SRTPKeyRotation(rotationTestKeys[1:], 0, 2),
	), errZeroPacketsPerKey, "zero packets per key")

	dup := rotationTestKeys[1]
	assert.ErrorIs(t, newCtx(
		MasterKeyIndicator(key.MKI),
		SRTPKeyRotation([]RotationKey{dup, dup}, 4, 2),
	), errMKIAlreadyInUse, "duplicate MKI in the sequence")

	assert.ErrorIs(t, newCtx(
		MasterKeyIndicator(key.MKI),
		SRTPKeyRotation([]RotationKey{key}, 4, 2),
	), errMKIAlreadyInUse, "MKI equal to the initial key's MKI")

	badLen := rotationTestKeys[1]
	badLen.MKI = []byte{0x01, 0x02, 0x03}
	assert.ErrorIs(t, newCtx(
		MasterKeyIndicator(key.MKI),
		SRTPKeyRotation([]RotationKey{badLen}, 4, 2),
	), errInvalidMKILength, "MKI length mismatch")

	emptyMKI := rotationTestKeys[1]
	emptyMKI.MKI = nil
	assert.ErrorIs(t, newCtx(
		MasterKeyIndicator(key.MKI),
		SRTPKeyRotation([]RotationKey{emptyMKI}, 4, 2),
	), errInvalidMKILength, "empty MKI")

	shortKey := rotationTestKeys[1]
	shortKey.MasterKey = []byte{0x01}
	assert.ErrorIs(t, newCtx(
		MasterKeyIndicator(key.MKI),
		SRTPKeyRotation([]RotationKey{shortKey}, 4, 2),
	), errShortSrtpMasterKey, "short master key")

	ctx, err := CreateContext(key.MasterKey, key.MasterSalt, profileCTR, MasterKeyIndicator(key.MKI))
	require.NoError(t, err)
	assert.ErrorIs(t, ctx.UpdateOptions(SRTPKeyRotation(rotationTestKeys[1:], 4, 2)),
		ErrContextOptionNotUpdatable, "rotation option must not be updatable after construction")
}

// TestKeyRotationDecryptFailure verifies that packets failing authentication
// neither advance the rotation state nor consume the replay window.
func TestKeyRotationDecryptFailure(t *testing.T) {
	const (
		packetsPerKey = 2
		grace         = 1
		ssrc          = 0x0A0A0A0A
	)

	enc := newRotationContext(t, packetsPerKey, grace)
	dec := newRotationContext(t, packetsPerKey, grace)

	require.NoError(t, decryptSeq(t, dec, encryptSeq(t, enc, ssrc, 0)))

	// Corrupt the payload of the first key1 packet.
	corrupted := encryptSeq(t, enc, ssrc, 2)
	corrupted[14] ^= 0xFF
	assert.Error(t, decryptSeq(t, dec, corrupted))

	// The failed packet must not have advanced the rotation state.
	state, ok := dec.ReceiveRotationState(ssrc)
	require.True(t, ok)
	assert.Equal(t, 0, state.KeyIndex)

	// The authentic retransmission of the same packet is still accepted: the
	// failed attempt did not consume the replay window. With packetsPerKey=2
	// the sender rotated to key1 for seq 3 and 4.
	require.NoError(t, decryptSeq(t, dec, encryptSeq(t, enc, ssrc, 3)))
	require.NoError(t, decryptSeq(t, dec, encryptSeq(t, enc, ssrc, 4)))

	state, ok = dec.ReceiveRotationState(ssrc)
	require.True(t, ok)
	assert.Equal(t, 1, state.KeyIndex)
}

// TestKeyRotationUnknownMKI verifies that packets with an MKI outside the
// rotation sequence are rejected.
func TestKeyRotationUnknownMKI(t *testing.T) {
	enc := newRotationContext(t, 4, 2)
	dec := newRotationContext(t, 4, 2)

	encrypted := encryptSeq(t, enc, 0x0A0A0A0A, 0)
	mki := packetMKI(t, encrypted)
	for i := range mki {
		mki[i] ^= 0xFF
	}

	assert.ErrorIs(t, decryptSeq(t, dec, encrypted), ErrMKINotFound)
}

// TestKeyRotationCounterSaturation verifies that the packet counters saturate
// at math.MaxUint64 instead of wrapping around.
func TestKeyRotationCounterSaturation(t *testing.T) {
	enc := newRotationContext(t, 4, 2)
	dec := newRotationContext(t, 4, 2)

	// Send side: a saturated counter on the last key must not wrap to zero.
	sendState := &rotationSendState{keyIndex: len(rotationTestKeys) - 1, count: math.MaxUint64}
	enc.rotator.sendStates[7] = sendState
	enc.rotator.sendCipher(7)
	assert.Equal(t, uint64(math.MaxUint64), sendState.count)

	// Receive side: a saturated grace counter must not wrap to zero either.
	recvKey := &rotationRecvKey{
		cipher:         dec.rotator.ciphers[1],
		replayDetector: dec.rotator.newReplayDetector(),
	}
	recvState := &rotationRecvState{
		current:       1,
		sinceRotation: math.MaxUint64,
		keys:          map[int]*rotationRecvKey{1: recvKey},
	}
	dec.rotator.recvStates[7] = recvState

	_, token, err := dec.rotator.recvCheck(7, 10, dec.rotator.mkis[1], 10)
	require.NoError(t, err)
	dec.rotator.recvAccept(token)
	assert.Equal(t, uint64(math.MaxUint64), recvState.sinceRotation)
}

// TestKeyRotationConcurrent exercises concurrent writes to the rotation state
// from multiple goroutines. Run with -race.
func TestKeyRotationConcurrent(t *testing.T) {
	const (
		goroutines    = 8
		packetsPerKey = 100
		iterations    = 500
	)

	enc := newRotationContext(t, packetsPerKey, 10)
	dec := newRotationContext(t, packetsPerKey, 10)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(ssrc uint32) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				enc.rotator.sendCipher(ssrc)

				keyIndex := min(i/packetsPerKey, len(rotationTestKeys)-1)
				_, token, err := dec.rotator.recvCheck(ssrc, uint16(i), dec.rotator.mkis[keyIndex], uint64(i)) //nolint:gosec
				if err == nil {
					dec.rotator.recvAccept(token)
				}
			}
		}(uint32(g)) //nolint:gosec
	}
	wg.Wait()

	for g := 0; g < goroutines; g++ {
		sendState, ok := enc.rotator.sendState(uint32(g)) //nolint:gosec
		require.True(t, ok)
		assert.Equal(t, len(rotationTestKeys)-1, sendState.KeyIndex)
		assert.Equal(t, uint64(iterations-2*packetsPerKey), sendState.PacketsWithCurrentKey)

		recvState, ok := dec.rotator.recvState(uint32(g)) //nolint:gosec
		require.True(t, ok)
		assert.Equal(t, len(rotationTestKeys)-1, recvState.KeyIndex)
	}
}

// TestKeyRotationDisabled verifies the rotation observability methods on a
// context without key rotation.
func TestKeyRotationDisabled(t *testing.T) {
	ctx, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR)
	require.NoError(t, err)

	_, ok := ctx.SendRotationState(1)
	assert.False(t, ok)
	_, ok = ctx.ReceiveRotationState(1)
	assert.False(t, ok)
}
