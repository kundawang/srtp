// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"fmt"
)

var (
	// ErrFailedToVerifyAuthTag is returned when decryption fails due to invalid authentication tag.
	ErrFailedToVerifyAuthTag = errors.New("failed to verify auth tag")
	// ErrMKINotFound is returned when decryption fails due to unknown MKI value in packet.
	ErrMKINotFound = errors.New("MKI not found")
	// ErrContextOptionNotUpdatable indicates an option cannot be updated after construction.
	ErrContextOptionNotUpdatable = errors.New("option can only be set during context construction")

	// ErrReplayStateVersion indicates a checkpoint was produced by an unsupported format version.
	ErrReplayStateVersion = errors.New("unsupported replay state version")
	// ErrReplayStateCorrupted indicates a checkpoint is malformed or has been modified.
	ErrReplayStateCorrupted = errors.New("replay state is corrupted")
	// ErrReplayStateTruncated indicates a checkpoint ended before all declared data was read.
	ErrReplayStateTruncated = errors.New("replay state is truncated")
	// ErrReplayStateMismatch indicates a checkpoint does not belong to this Context's key,
	// protection profile or replay configuration.
	ErrReplayStateMismatch = errors.New("replay state does not match the context")
	// ErrReplayStateCounterOverflow indicates a checkpoint holds a counter beyond its maximum.
	ErrReplayStateCounterOverflow = errors.New("replay state counter overflow")
	// ErrReplayStateUnsupported indicates the Context cannot export a checkpoint, e.g. because
	// it uses a custom replay detector.
	ErrReplayStateUnsupported = errors.New("replay state is not supported")
	// ErrReplayStateAlreadyRestored indicates RestoreReplayState was called on a Context that
	// already had replay state restored or had already processed packets.
	ErrReplayStateAlreadyRestored = errors.New("replay state was already restored")

	errDuplicated                    = errors.New("duplicated packet")
	errShortSrtpMasterKey            = errors.New("SRTP master key is not long enough")
	errShortSrtpMasterSalt           = errors.New("SRTP master salt is not long enough")
	errNoSuchSRTPProfile             = errors.New("no such SRTP Profile")
	errNonZeroKDRNotSupported        = errors.New("indexOverKdr > 0 is not supported yet")
	errExporterWrongLabel            = errors.New("exporter called with wrong label")
	errNoConfig                      = errors.New("no config provided")
	errNoConn                        = errors.New("no conn provided")
	errTooShortRTP                   = errors.New("packet is too short to be RTP packet")
	errTooShortRTCP                  = errors.New("packet is too short to be RTCP packet")
	errPayloadDiffers                = errors.New("payload differs")
	errStartedChannelUsedIncorrectly = errors.New("started channel used incorrectly, should only be closed")
	errBadIVLength                   = errors.New("bad iv length in xorBytesCTR")
	errExceededMaxPackets            = errors.New("exceeded the maximum number of packets")
	errMKIAlreadyInUse               = errors.New("MKI already in use")
	errMKIIsNotEnabled               = errors.New("MKI is not enabled")
	errInvalidMKILength              = errors.New("invalid MKI length")
	errTooLongSRTPAuthTag            = errors.New("SRTP auth tag is too long")
	errTooShortSRTPAuthTag           = errors.New("SRTP auth tag is too short")

	errStreamNotInited     = errors.New("stream has not been inited, unable to close")
	errStreamAlreadyClosed = errors.New("stream is already closed")
	errStreamAlreadyInited = errors.New("stream is already inited")
	errFailedTypeAssertion = errors.New("failed to cast child")

	errZeroRocTransmitRate = errors.New("ROC transmit rate is zero")
	errUnsupportedRccMode  = errors.New("unsupported RCC mode")

	errUnsupportedHeaderExtension   = errors.New("unsupported header extension")
	errHeaderLengthMismatch         = errors.New("header length mismatch")
	errUnencryptedHeaderExtAndCSRCs = errors.New("unencrypted header extensions and CSRCs are not allowed")
	errCryptexDisabled              = errors.New("cryptex is disabled")
)

type duplicatedError struct {
	Proto string // srtp or srtcp
	SSRC  uint32
	Index uint32 // sequence number or index
}

func (e *duplicatedError) Error() string {
	return fmt.Sprintf("%s ssrc=%d index=%d: %v", e.Proto, e.SSRC, e.Index, errDuplicated)
}

func (e *duplicatedError) Unwrap() error {
	return errDuplicated
}
