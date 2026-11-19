// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"math"
	"sync"

	"github.com/pion/transport/v5/replaydetector"
)

// RotationKey is a single master key in a packet-count-driven key rotation
// sequence. See SRTPKeyRotation for details.
type RotationKey struct {
	// MKI is the Master Key Identifier sent in packets encrypted with this key.
	// It must be non-empty, have the same length as the MKI of the Context's
	// initial key (see MasterKeyIndicator), and be unique within the sequence.
	MKI []byte
	// MasterKey and MasterSalt are the SRTP master key and salt used with this MKI.
	MasterKey  []byte
	MasterSalt []byte
}

// RotationState describes the key rotation state of a single SSRC.
type RotationState struct {
	// KeyIndex is the index of the key currently in use within the rotation
	// sequence. Index 0 is the Context's initial master key.
	KeyIndex int
	// MKI is the Master Key Identifier of the key currently in use.
	MKI []byte
	// PacketsWithCurrentKey is the number of packets processed with the current key.
	// On the send side it is the number of packets encrypted with the current key.
	// On the receive side it is the number of packets authenticated with the
	// current key since it became the newest key.
	PacketsWithCurrentKey uint64
	// KeyCount is the total number of keys in the rotation sequence,
	// including the Context's initial key.
	KeyCount int
	// LastKey reports whether the current key is the last key of the sequence.
	// Once the last key is reached no further rotation happens: the sender
	// keeps using it and the receiver keeps accepting it.
	LastKey bool
}

// rotationConfig holds the not-yet-validated SRTPKeyRotation option values.
type rotationConfig struct {
	keys                []RotationKey
	packetsPerKey       uint64
	receiveGracePackets uint64
}

// keyRotator implements packet-count-driven SRTP key rotation.
//
// The key sequence is the Context's initial key (index 0) followed by the
// configured RotationKey-s. Packet counting is per SSRC: each SSRC rotates
// independently after packetsPerKey packets.
//
// On the receive side every key gets its own replay detector, so replay
// protection is maintained per key. After the newest seen key advances, keys
// older than the current one are removed once receiveGracePackets further
// packets have been authenticated; packets for removed keys are rejected with
// ErrMKINotFound.
//
// Unlike Context itself, keyRotator is safe for concurrent use: all rotation
// state is guarded by its own mutex. The ciphers it returns are shared with
// the Context and remain subject to the Context's synchronization contract.
type keyRotator struct {
	mu sync.Mutex

	ciphers    []srtpCipher
	mkis       [][]byte
	mkiToIndex map[string]int

	packetsPerKey       uint64
	receiveGracePackets uint64

	newReplayDetector func() replaydetector.ReplayDetector

	sendStates map[uint32]*rotationSendState
	recvStates map[uint32]*rotationRecvState
}

type rotationSendState struct {
	keyIndex int
	count    uint64
}

type rotationRecvKey struct {
	cipher         srtpCipher
	replayDetector replaydetector.ReplayDetector
	checkAccepter  replaydetector.CheckAccepter
}

type rotationRecvState struct {
	// keys holds the still-accepted keys. Keys older than current are removed
	// once the receive grace period has elapsed.
	keys map[int]*rotationRecvKey
	// current is the newest key index seen on this SSRC.
	current int
	// sinceRotation counts packets authenticated with the current key since it
	// became the newest key.
	sinceRotation uint64
}

// rotationRecvToken carries the state needed to commit a received packet after
// it has been successfully authenticated. A token must be consumed by exactly
// one recvAccept call; if decryption fails the token is discarded and neither
// the replay detector nor the rotation state is updated.
type rotationRecvToken struct {
	ssrc        uint32
	state       *rotationRecvState
	keyIndex    int
	key         *rotationRecvKey
	markAsValid func() bool
	tok         replaydetector.Token
}

// newKeyRotator validates the rotation configuration and builds the key
// sequence: index 0 is the Context's initial key, followed by cfg.keys.
func (c *Context) newKeyRotator(cfg *rotationConfig) (*keyRotator, error) {
	if len(cfg.keys) == 0 {
		return nil, errRotationNoKeys
	}
	if len(c.sendMKI) == 0 {
		return nil, errMKIIsNotEnabled
	}
	if cfg.packetsPerKey == 0 {
		return nil, errZeroPacketsPerKey
	}

	r := &keyRotator{
		ciphers:             []srtpCipher{c.cipher},
		mkis:                [][]byte{bytes.Clone(c.sendMKI)},
		mkiToIndex:          map[string]int{string(c.sendMKI): 0},
		packetsPerKey:       cfg.packetsPerKey,
		receiveGracePackets: cfg.receiveGracePackets,
		newReplayDetector:   c.newSRTPReplayDetector,
		sendStates:          map[uint32]*rotationSendState{},
		recvStates:          map[uint32]*rotationRecvState{},
	}

	for i := range cfg.keys {
		key := cfg.keys[i]
		if len(key.MKI) == 0 || len(key.MKI) != len(c.sendMKI) {
			return nil, errInvalidMKILength
		}
		if _, ok := r.mkiToIndex[string(key.MKI)]; ok {
			return nil, errMKIAlreadyInUse
		}

		cipher, err := c.createCipher(key.MKI, key.MasterKey, key.MasterSalt, c.encryptSRTP, c.encryptSRTCP)
		if err != nil {
			return nil, err
		}

		r.mkiToIndex[string(key.MKI)] = len(r.ciphers)
		r.ciphers = append(r.ciphers, cipher)
		r.mkis = append(r.mkis, bytes.Clone(key.MKI))
	}

	return r, nil
}

// sendCipher returns the cipher to encrypt the next packet of the given SSRC
// with, advancing the per-SSRC rotation state. When the configured keys are
// exhausted the last key keeps being used. The packet counter saturates at
// math.MaxUint64 instead of wrapping.
func (r *keyRotator) sendCipher(ssrc uint32) srtpCipher {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.sendStates[ssrc]
	if !ok {
		state = &rotationSendState{}
		r.sendStates[ssrc] = state
	}

	if state.count >= r.packetsPerKey && state.keyIndex+1 < len(r.ciphers) {
		state.keyIndex++
		state.count = 0
	}
	if state.count < math.MaxUint64 {
		state.count++
	}

	return r.ciphers[state.keyIndex]
}

// recvCheck looks up the cipher for the MKI of a received packet and performs
// the replay check against the per-key replay detector. The packet is only
// committed (replay detector marked, rotation state advanced) by recvAccept
// after successful authentication; if authentication fails the token must be
// discarded.
//
// Packets with an unknown MKI, or with an MKI whose key was removed after the
// receive grace period, are rejected with ErrMKINotFound. Replayed packets are
// rejected with a duplicatedError.
func (r *keyRotator) recvCheck(
	ssrc uint32, sequenceNumber uint16, mki []byte, index uint64,
) (srtpCipher, *rotationRecvToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	keyIndex, ok := r.mkiToIndex[string(mki)]
	if !ok {
		return nil, nil, ErrMKINotFound
	}

	// The SSRC in the RTP header is unauthenticated at this point. A state for
	// a previously unseen SSRC is kept local and only committed to the map by
	// recvAccept, after the packet has been authenticated.
	state, ok := r.recvStates[ssrc]
	if !ok {
		state = &rotationRecvState{current: -1, keys: map[int]*rotationRecvKey{}}
	}

	key, ok := state.keys[keyIndex]
	if !ok {
		if keyIndex <= state.current {
			// The key is known but was already removed after the receive
			// grace period elapsed.
			return nil, nil, ErrMKINotFound
		}
		key = &rotationRecvKey{
			cipher:         r.ciphers[keyIndex],
			replayDetector: r.newReplayDetector(),
		}
		key.checkAccepter, _ = key.replayDetector.(replaydetector.CheckAccepter)
		state.keys[keyIndex] = key
	}

	token := &rotationRecvToken{ssrc: ssrc, state: state, keyIndex: keyIndex, key: key}
	if key.checkAccepter != nil {
		token.tok = key.checkAccepter.CheckSeq(index)
		if !token.tok.Passed() {
			return nil, nil, &duplicatedError{Proto: "srtp", SSRC: ssrc, Index: uint32(sequenceNumber)}
		}
	} else {
		var passed bool
		token.markAsValid, passed = key.replayDetector.Check(index)
		if !passed {
			return nil, nil, &duplicatedError{Proto: "srtp", SSRC: ssrc, Index: uint32(sequenceNumber)}
		}
	}

	return key.cipher, token, nil
}

// recvAccept commits a successfully authenticated packet: it marks the packet
// in the per-key replay detector, advances the rotation state, and removes
// keys whose receive grace period has elapsed.
func (r *keyRotator) recvAccept(token *rotationRecvToken) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.recvStates[token.ssrc]; !ok {
		r.recvStates[token.ssrc] = token.state
	}
	state := token.state

	if token.key.checkAccepter != nil {
		token.key.checkAccepter.Accept(token.tok)
	} else {
		token.markAsValid()
	}

	switch {
	case token.keyIndex > state.current:
		state.current = token.keyIndex
		state.sinceRotation = 0
	case token.keyIndex == state.current:
		if state.sinceRotation < math.MaxUint64 {
			state.sinceRotation++
		}
		if state.sinceRotation > r.receiveGracePackets {
			// The grace period has elapsed: remove every key older than the
			// current one together with its replay detector. Late packets for
			// removed keys are rejected with ErrMKINotFound from now on.
			for keyIndex := range state.keys {
				if keyIndex < state.current {
					delete(state.keys, keyIndex)
				}
			}
		}
	default:
		// Late packet on an older key still within its grace period.
	}
}

// sendState returns the rotation state used for encrypting the given SSRC.
func (r *keyRotator) sendState(ssrc uint32) (RotationState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.sendStates[ssrc]
	if !ok {
		return RotationState{}, false
	}

	return RotationState{
		KeyIndex:              state.keyIndex,
		MKI:                   bytes.Clone(r.mkis[state.keyIndex]),
		PacketsWithCurrentKey: state.count,
		KeyCount:              len(r.ciphers),
		LastKey:               state.keyIndex == len(r.ciphers)-1,
	}, true
}

// recvState returns the rotation state of received packets for the given SSRC.
func (r *keyRotator) recvState(ssrc uint32) (RotationState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, ok := r.recvStates[ssrc]
	if !ok {
		return RotationState{}, false
	}

	return RotationState{
		KeyIndex:              state.current,
		MKI:                   bytes.Clone(r.mkis[state.current]),
		PacketsWithCurrentKey: state.sinceRotation,
		KeyCount:              len(r.ciphers),
		LastKey:               state.current == len(r.ciphers)-1,
	}, true
}

func (r *keyRotator) setCryptex(useCryptex bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, cipher := range r.ciphers {
		cipher.setCryptex(useCryptex)
	}
}

// SendRotationState returns the key rotation state used for encrypting packets
// of the given SSRC. It returns false if key rotation is not enabled or no
// packet has been encrypted for the SSRC yet.
func (c *Context) SendRotationState(ssrc uint32) (RotationState, bool) {
	if c.rotator == nil {
		return RotationState{}, false
	}

	return c.rotator.sendState(ssrc)
}

// ReceiveRotationState returns the key rotation state of received packets for
// the given SSRC. It returns false if key rotation is not enabled or no packet
// has been authenticated for the SSRC yet.
func (c *Context) ReceiveRotationState(ssrc uint32) (RotationState, bool) {
	if c.rotator == nil {
		return RotationState{}, false
	}

	return c.rotator.recvState(ssrc)
}
