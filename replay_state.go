// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
)

// ReplayStateVersion is the version of the replay-state checkpoint format
// produced by Context.ExportReplayState.
//
// A checkpoint contains the SRTP rollover counter and replay window of every
// SSRC, as well as the SRTCP index and replay window of every SSRC. It never
// contains master keys, session keys, salts or any other key material; the
// only key-dependent value it carries is a truncated, one-way fingerprint used
// to reject a checkpoint restored under a different key or configuration.
const ReplayStateVersion = 1

const (
	replayStateMagic = "SRTPCKPT"
	// magic (8) + version (1) + profile (2) + flags (1) + key ID (16) +
	// SRTP window (4) + SRTCP window (4) + SRTP entries (4) + SRTCP entries (4).
	replayStateHeaderLen = 44

	replayStateFlagSRTP   = 1 << 0
	replayStateFlagSRTCP  = 1 << 1
	replayStateKnownFlags = replayStateFlagSRTP | replayStateFlagSRTCP

	// replayStateMaxWindow bounds the window size accepted from a checkpoint so
	// that a corrupt header cannot trigger a huge allocation.
	replayStateMaxWindow = 1 << 20

	replayStateKeyIDLen = 16

	// srtpMaxIndex / srtcpMaxIndex are the largest values the respective replay
	// detectors accept.
	srtcpMaxIndexConst = uint64(maxSRTCPIndex)
)

// replayKind classifies the replay detector configured for one protocol.
type replayKind uint8

const (
	// replayKindDisabled is SRTPNoReplayProtection / SRTCPNoReplayProtection.
	replayKindDisabled replayKind = iota
	// replayKindDefault is the built-in detector configured by
	// SRTPReplayProtection / SRTCPReplayProtection; it can be checkpointed.
	replayKindDefault
	// replayKindCustom is any detector installed by
	// SRTPReplayDetectorFactory / SRTCPReplayDetectorFactory.
	replayKindCustom
)

// srtpMaxIndex is the largest SRTP packet index (ROC||SEQ) accepted by the
// default replay detector.
const srtpMaxIndex = uint64(maxROC)<<16 | uint64(maxSequenceNumber)

// ExportReplayState returns a self-contained checkpoint of the receive-side
// replay state of the Context: for every SSRC it records the SRTP rollover
// counter, packet index and replay window, and the SRTCP index and replay
// window. The checkpoint carries the format version, the protection profile
// and a one-way key fingerprint, but no key material.
//
// Export is supported for the built-in replay detectors configured with
// SRTPReplayProtection / SRTCPReplayProtection. A custom detector installed
// with SRTPReplayDetectorFactory can never be checkpointed and yields
// ErrReplayStateUnsupported. A protocol with replay protection disabled is
// omitted while it has no per-SSRC state; once it has state, which carries the
// ROC/index needed for decryption, ExportReplayState fails rather than
// returning an incomplete checkpoint.
//
// The Context is synchronized internally for the duration of the export, so
// the checkpoint never observes a half-applied packet. It is safe to call
// concurrently with DecryptRTP/DecryptRTCP on the same Context, and with the
// session-level wrappers used by the session receive loops.
func (c *Context) ExportReplayState() ([]byte, error) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	return c.exportReplayStateLocked()
}

//nolint:cyclop
func (c *Context) exportReplayStateLocked() ([]byte, error) {
	if c.srtpReplayKind == replayKindDefault && c.srtpReplayWindow > replayStateMaxWindow {
		return nil, fmt.Errorf("%w: SRTP replay window %d is too large to checkpoint",
			ErrReplayStateUnsupported, c.srtpReplayWindow)
	}
	if c.srtcpReplayKind == replayKindDefault && c.srtcpReplayWindow > replayStateMaxWindow {
		return nil, fmt.Errorf("%w: SRTCP replay window %d is too large to checkpoint",
			ErrReplayStateUnsupported, c.srtcpReplayWindow)
	}
	// Custom detectors have opaque state that cannot be serialized.
	if c.srtpReplayKind == replayKindCustom {
		return nil, fmt.Errorf("%w: SRTP uses a custom replay detector", ErrReplayStateUnsupported)
	}
	if c.srtcpReplayKind == replayKindCustom {
		return nil, fmt.Errorf("%w: SRTCP uses a custom replay detector", ErrReplayStateUnsupported)
	}
	// Without replay protection the per-SSRC state still carries the ROC/index
	// needed to decrypt. That state is not part of a checkpoint, so refuse
	// rather than silently producing a checkpoint that cannot be honored.
	if c.srtpReplayKind == replayKindDisabled && len(c.srtpSSRCStates) > 0 {
		return nil, fmt.Errorf("%w: SRTP has replay protection disabled", ErrReplayStateUnsupported)
	}
	if c.srtcpReplayKind == replayKindDisabled && len(c.srtcpSSRCStates) > 0 {
		return nil, fmt.Errorf("%w: SRTCP has replay protection disabled", ErrReplayStateUnsupported)
	}

	var flags uint8
	if c.srtpReplayKind == replayKindDefault {
		flags |= replayStateFlagSRTP
	}
	if c.srtcpReplayKind == replayKindDefault {
		flags |= replayStateFlagSRTCP
	}

	srtpSSRCs := make([]uint32, 0, len(c.srtpSSRCStates))
	for ssrc := range c.srtpSSRCStates {
		srtpSSRCs = append(srtpSSRCs, ssrc)
	}
	slices.Sort(srtpSSRCs)

	srtcpSSRCs := make([]uint32, 0, len(c.srtcpSSRCStates))
	for ssrc := range c.srtcpSSRCStates {
		srtcpSSRCs = append(srtcpSSRCs, ssrc)
	}
	slices.Sort(srtcpSSRCs)

	// The advertised window must match the checkpoint's entry layout, so it is
	// zero for protocols without the default detector. A context that switched
	// SRTPReplayProtection off still carries a stale srtpReplayWindow, which
	// must not leak into the header.
	var srtpWindow, srtcpWindow uint
	if c.srtpReplayKind == replayKindDefault {
		srtpWindow = c.srtpReplayWindow
	}
	if c.srtcpReplayKind == replayKindDefault {
		srtcpWindow = c.srtcpReplayWindow
	}

	srtpMaskLen := (srtpWindow + 7) / 8
	srtcpMaskLen := (srtcpWindow + 7) / 8
	size := replayStateHeaderLen +
		len(srtpSSRCs)*(4+8+1+8+int(srtpMaskLen)) +
		len(srtcpSSRCs)*(4+4+8+int(srtcpMaskLen))

	out := make([]byte, 0, size)
	out = append(out, replayStateMagic...)
	out = append(out, byte(ReplayStateVersion))
	out = binary.BigEndian.AppendUint16(out, uint16(c.profile))
	out = append(out, flags)
	out = append(out, c.replayStateKeyID[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(srtpWindow))      //nolint:gosec // bounded above
	out = binary.BigEndian.AppendUint32(out, uint32(srtcpWindow))     //nolint:gosec // bounded above
	out = binary.BigEndian.AppendUint32(out, uint32(len(srtpSSRCs)))  //nolint:gosec // bounded by map size
	out = binary.BigEndian.AppendUint32(out, uint32(len(srtcpSSRCs))) //nolint:gosec // bounded by map size

	for _, ssrc := range srtpSSRCs {
		state := c.srtpSSRCStates[ssrc]
		detector, ok := state.replayDetector.(*replayWindowDetector)
		if !ok || detector.windowSize != c.srtpReplayWindow {
			return nil, fmt.Errorf("%w: SRTP %d uses a custom replay detector",
				ErrReplayStateUnsupported, ssrc)
		}
		latest, mask := detector.exportState()
		if len(mask) != int(srtpMaskLen) {
			return nil, fmt.Errorf("%w: inconsistent SRTP replay window for %d", ErrReplayStateCorrupted, ssrc)
		}
		if state.index > srtpMaxIndex {
			return nil, fmt.Errorf("%w: SRTP index %d exceeds the maximum", ErrReplayStateCounterOverflow, state.index)
		}

		out = binary.BigEndian.AppendUint32(out, ssrc)
		out = binary.BigEndian.AppendUint64(out, state.index)
		if state.rolloverHasProcessed {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
		out = binary.BigEndian.AppendUint64(out, latest)
		out = append(out, mask...)
	}

	for _, ssrc := range srtcpSSRCs {
		state := c.srtcpSSRCStates[ssrc]
		detector, ok := state.replayDetector.(*replayWindowDetector)
		if !ok || detector.windowSize != c.srtcpReplayWindow {
			return nil, fmt.Errorf("%w: SRTCP %d uses a custom replay detector",
				ErrReplayStateUnsupported, ssrc)
		}
		latest, mask := detector.exportState()
		if len(mask) != int(srtcpMaskLen) {
			return nil, fmt.Errorf("%w: inconsistent SRTCP replay window for %d", ErrReplayStateCorrupted, ssrc)
		}
		if state.srtcpIndex > maxSRTCPIndex {
			return nil, fmt.Errorf("%w: SRTCP index %d exceeds the maximum",
				ErrReplayStateCounterOverflow, state.srtcpIndex)
		}

		out = binary.BigEndian.AppendUint32(out, ssrc)
		out = binary.BigEndian.AppendUint32(out, state.srtcpIndex)
		out = binary.BigEndian.AppendUint64(out, latest)
		out = append(out, mask...)
	}

	return out, nil
}

// RestoreReplayState replaces the receive-side replay state of the Context
// with a checkpoint previously produced by ExportReplayState.
//
// The checkpoint must have been produced by a Context with the same master
// key and salt, protection profile and replay configuration. Restoring is
// atomic: on error the Context is left untouched. A Context accepts a restore
// only once; a second call, or a call on a Context that has already processed
// packets, returns ErrReplayStateAlreadyRestored.
//
// After a successful restore, packets that were already accepted before the
// checkpoint are still rejected as duplicates, while new packets continue to
// decrypt.
func (c *Context) RestoreReplayState(checkpoint []byte) error {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	return c.restoreReplayStateLocked(checkpoint)
}

//nolint:cyclop
func (c *Context) restoreReplayStateLocked(checkpoint []byte) error {
	// Reject restores into a context that already has state before looking at
	// the checkpoint: the error is about the context, not the input.
	if c.replayStateRestored || len(c.srtpSSRCStates) > 0 || len(c.srtcpSSRCStates) > 0 {
		return ErrReplayStateAlreadyRestored
	}

	reader := &replayStateReader{buf: checkpoint}

	magic, err := reader.bytesOf(len(replayStateMagic))
	if err != nil {
		return err
	}
	if string(magic) != replayStateMagic {
		return fmt.Errorf("%w: bad magic", ErrReplayStateCorrupted)
	}

	version, err := reader.uint8()
	if err != nil {
		return err
	}
	if version != ReplayStateVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrReplayStateVersion, version, ReplayStateVersion)
	}

	profile, err := reader.uint16()
	if err != nil {
		return err
	}

	flags, err := reader.uint8()
	if err != nil {
		return err
	}
	if flags&^uint8(replayStateKnownFlags) != 0 {
		return fmt.Errorf("%w: unknown flags %#x", ErrReplayStateCorrupted, flags)
	}

	keyID, err := reader.bytesOf(replayStateKeyIDLen)
	if err != nil {
		return err
	}

	srtpWindow, err := reader.uint32()
	if err != nil {
		return err
	}
	srtcpWindow, err := reader.uint32()
	if err != nil {
		return err
	}
	srtpCount, err := reader.uint32()
	if err != nil {
		return err
	}
	srtcpCount, err := reader.uint32()
	if err != nil {
		return err
	}

	if ProtectionProfile(profile) != c.profile {
		return fmt.Errorf("%w: profile %s, context uses %s",
			ErrReplayStateMismatch, ProtectionProfile(profile), c.profile)
	}
	if string(keyID) != string(c.replayStateKeyID[:]) {
		return fmt.Errorf("%w: checkpoint was created for a different key or configuration",
			ErrReplayStateMismatch)
	}

	includedSRTP := flags&replayStateFlagSRTP != 0
	includedSRTCP := flags&replayStateFlagSRTCP != 0
	if c.srtpReplayKind == replayKindCustom || c.srtcpReplayKind == replayKindCustom {
		return fmt.Errorf("%w: the context uses a custom replay detector", ErrReplayStateUnsupported)
	}
	if includedSRTP != (c.srtpReplayKind == replayKindDefault) ||
		includedSRTCP != (c.srtcpReplayKind == replayKindDefault) {
		return fmt.Errorf("%w: checkpoint replay configuration does not match the context",
			ErrReplayStateMismatch)
	}

	if includedSRTP {
		if srtpWindow != uint32(c.srtpReplayWindow) || srtpWindow > replayStateMaxWindow { //nolint:gosec // bounded above
			return fmt.Errorf("%w: SRTP replay window %d does not match the context",
				ErrReplayStateMismatch, srtpWindow)
		}
	} else if srtpWindow != 0 {
		return fmt.Errorf("%w: unexpected SRTP replay window", ErrReplayStateCorrupted)
	}

	if includedSRTCP {
		if srtcpWindow != uint32(c.srtcpReplayWindow) || srtcpWindow > replayStateMaxWindow { //nolint:gosec // bounded above
			return fmt.Errorf("%w: SRTCP replay window %d does not match the context",
				ErrReplayStateMismatch, srtcpWindow)
		}
	} else if srtcpWindow != 0 {
		return fmt.Errorf("%w: unexpected SRTCP replay window", ErrReplayStateCorrupted)
	}

	srtpMaskLen := (srtpWindow + 7) / 8
	srtcpMaskLen := (srtcpWindow + 7) / 8
	if minEntry := uint64(4 + 8 + 1 + 8); uint64(srtpCount)*minEntry > uint64(reader.remaining()) { //nolint:gosec // reader.remaining() >= 0
		return fmt.Errorf("%w: SRTP entry count %d exceeds the checkpoint size", ErrReplayStateTruncated, srtpCount)
	}
	if minEntry := uint64(4 + 4 + 8); uint64(srtcpCount)*minEntry > uint64(reader.remaining()) { //nolint:gosec // reader.remaining() >= 0
		return fmt.Errorf("%w: SRTCP entry count %d exceeds the checkpoint size", ErrReplayStateTruncated, srtcpCount)
	}

	newSRTPStates := make(map[uint32]*srtpSSRCState, srtpCount)
	for range srtpCount {
		ssrc, err := reader.uint32()
		if err != nil {
			return err
		}
		index, err := reader.uint64()
		if err != nil {
			return err
		}
		rollover, err := reader.uint8()
		if err != nil {
			return err
		}
		latest, err := reader.uint64()
		if err != nil {
			return err
		}
		mask, err := reader.bytesOf(int(srtpMaskLen))
		if err != nil {
			return err
		}

		if rollover > 1 {
			return fmt.Errorf("%w: invalid rollover marker for SRTP %d", ErrReplayStateCorrupted, ssrc)
		}
		if index > srtpMaxIndex {
			return fmt.Errorf("%w: SRTP index %d exceeds the maximum", ErrReplayStateCounterOverflow, index)
		}
		if _, exists := newSRTPStates[ssrc]; exists {
			return fmt.Errorf("%w: duplicate SRTP SSRC %d", ErrReplayStateCorrupted, ssrc)
		}
		detector := newReplayWindowDetector(uint(srtpWindow), srtpMaxIndex)
		if err := detector.importState(latest, mask); err != nil {
			return err
		}
		newSRTPStates[ssrc] = &srtpSSRCState{
			ssrc:                 ssrc,
			rolloverHasProcessed: rollover == 1,
			index:                index,
			replayDetector:       detector,
			checkAccepter:        detector,
		}
	}

	newSRTCPStates := make(map[uint32]*srtcpSSRCState, srtcpCount)
	for range srtcpCount {
		ssrc, err := reader.uint32()
		if err != nil {
			return err
		}
		srtcpIndex, err := reader.uint32()
		if err != nil {
			return err
		}
		latest, err := reader.uint64()
		if err != nil {
			return err
		}
		mask, err := reader.bytesOf(int(srtcpMaskLen))
		if err != nil {
			return err
		}

		if srtcpIndex > maxSRTCPIndex {
			return fmt.Errorf("%w: SRTCP index %d exceeds the maximum",
				ErrReplayStateCounterOverflow, srtcpIndex)
		}
		if _, exists := newSRTCPStates[ssrc]; exists {
			return fmt.Errorf("%w: duplicate SRTCP SSRC %d", ErrReplayStateCorrupted, ssrc)
		}
		detector := newReplayWindowDetector(uint(srtcpWindow), srtcpMaxIndexConst)
		if err := detector.importState(latest, mask); err != nil {
			return err
		}
		newSRTCPStates[ssrc] = &srtcpSSRCState{
			srtcpIndex:     srtcpIndex,
			ssrc:           ssrc,
			replayDetector: detector,
			checkAccepter:  detector,
		}
	}

	if reader.remaining() != 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrReplayStateCorrupted, reader.remaining())
	}

	c.srtpSSRCStates = newSRTPStates
	c.srtcpSSRCStates = newSRTCPStates
	c.replayStateRestored = true

	return nil
}

// ClearReplayState drops the SRTP and SRTCP replay state of a single SSRC. It
// is safe to call concurrently with decryption. Subsequent packets for the
// SSRC are treated as the first packets seen from it.
func (c *Context) ClearReplayState(ssrc uint32) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	delete(c.srtpSSRCStates, ssrc)
	delete(c.srtcpSSRCStates, ssrc)
}

// replayStateReader is a bounds-checked big-endian reader.
type replayStateReader struct {
	buf []byte
	off int
}

func (r *replayStateReader) remaining() int {
	return len(r.buf) - r.off
}

func (r *replayStateReader) bytesOf(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, fmt.Errorf("%w: need %d bytes, have %d", ErrReplayStateTruncated, n, r.remaining())
	}
	out := r.buf[r.off : r.off+n]
	r.off += n

	return out, nil
}

func (r *replayStateReader) uint8() (uint8, error) {
	b, err := r.bytesOf(1)
	if err != nil {
		return 0, err
	}

	return b[0], nil
}

func (r *replayStateReader) uint16() (uint16, error) {
	b, err := r.bytesOf(2)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint16(b), nil
}

func (r *replayStateReader) uint32() (uint32, error) {
	b, err := r.bytesOf(4)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}

func (r *replayStateReader) uint64() (uint64, error) {
	b, err := r.bytesOf(8)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(b), nil
}

// replayStateKeyID derives the non-secret fingerprint stored in a checkpoint.
// It commits to the key material without exporting it: inverting a truncated
// SHA-256 over a full-entropy master key is infeasible.
func replayStateKeyID(
	profile ProtectionProfile,
	masterKey, masterSalt []byte,
	encryptSRTP, encryptSRTCP bool,
	rccMode RCCMode, rocTransmitRate uint16,
	authTagRTPLen *int, cryptexMode CryptexMode,
	sendMKI []byte,
) [replayStateKeyIDLen]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("github.com/pion/srtp/v3 replay state key id v1"))
	var num [8]byte
	writeU16 := func(v uint16) {
		binary.BigEndian.PutUint16(num[:2], v)
		_, _ = hash.Write(num[:2])
	}
	writeU32 := func(v uint32) {
		binary.BigEndian.PutUint32(num[:4], v)
		_, _ = hash.Write(num[:4])
	}
	writeBytes := func(b []byte) {
		writeU32(uint32(len(b))) //nolint:gosec // bounded by key/salt/MKI sizes
		_, _ = hash.Write(b)
	}

	writeU16(uint16(profile))
	writeBytes(masterKey)
	writeBytes(masterSalt)
	flags := uint16(0)
	if encryptSRTP {
		flags |= 1
	}
	if encryptSRTCP {
		flags |= 2
	}
	writeU16(flags)
	writeU16(uint16(rccMode)) //nolint:gosec // small enum
	writeU16(rocTransmitRate)
	if authTagRTPLen != nil {
		writeU16(1)
		writeU16(uint16(*authTagRTPLen)) //nolint:gosec // auth tag length
	} else {
		writeU16(0)
		writeU16(0)
	}
	writeU16(uint16(cryptexMode)) //nolint:gosec // small enum
	writeBytes(sendMKI)

	var out [replayStateKeyIDLen]byte
	copy(out[:], hash.Sum(nil))

	return out
}
