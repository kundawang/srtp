// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/pion/rtp"
	"github.com/pion/transport/v5/utils/xor"
)

/*
RFC 6904: Encryption of Header Extensions in the Secure Real-time Transport Protocol

Only the payload of the selected RFC 8285 header extension elements is encrypted. The one- or
two-byte element header and any padding octets are never encrypted, so a receiver (or an
intermediate node that was told which IDs are protected) can still parse the extension block.

A keystream is generated with AES-CM using the header encryption key k_he and header salt k_hs
derived from the master key with labels 0x06 and 0x07. The counter is the same one that is used
for the RTP payload. The keystream starts at the first element ID/length byte, i.e. right after
the "defined by profile" and "length" fields of the extension block. Byte N of the extension
element area (counting from that point) is XORed with byte N of the keystream, but only when it
belongs to a protected element. This is equivalent to ANDing the keystream with the RFC 6904
encryption mask before XORing it with the header extension.

Encryption is symmetric, so the same function encrypts and decrypts. It must be applied before
the authentication tag is computed and after the tag has been verified, which is how it is wired
into the AES-CM cipher below.
*/

const (
	labelSRTPHeaderEncryption = 0x06
	labelSRTPHeaderSalt       = 0x07

	// csrcLength is the size of a CSRC identifier in bytes (RFC 3550).
	csrcLength = 4
)

// isEncryptedHeaderExtensionID reports whether the payload of the given extension element ID
// must be encrypted.
func (s *srtpCipherAesCmHmacSha1) isEncryptedHeaderExtensionID(id uint8) bool {
	for _, encryptionID := range s.encryptedHeaderExtensionIDs {
		if encryptionID == id {
			return true
		}
	}

	return false
}

// cryptHeaderExtensions encrypts (or, symmetrically, decrypts in place) the payload of the
// header extension elements listed in the cipher configuration. It reports whether at least one
// element payload was transformed.
//
// headerLen must be the length of the complete RTP header, including CSRCs and the extension
// block. buf is expected to hold the (un)protected header at its start.
func (s *srtpCipherAesCmHmacSha1) cryptHeaderExtensions(
	buf []byte,
	header *rtp.Header,
	headerLen int,
	roc uint32,
) (bool, error) {
	if len(s.encryptedHeaderExtensionIDs) == 0 || !header.Extension {
		return false, nil
	}

	// The extension block starts after the fixed header and the CSRCs, with the "defined by
	// profile" and "length" fields. RFC 6904 starts the keystream and the mask after them, at
	// the first RFC 8285 element ID/length byte.
	extensionBlockStart := minSrtpHeaderSize + len(header.CSRC)*csrcLength
	extensionElementsStart := extensionBlockStart + extensionHeaderSize
	if headerLen < extensionElementsStart || headerLen > len(buf) {
		return false, errHeaderLengthMismatch
	}

	extensionLength := int(binary.BigEndian.Uint16(buf[extensionBlockStart+2:extensionElementsStart])) * 4
	extensionEnd := extensionElementsStart + extensionLength
	if extensionEnd > headerLen {
		return false, errTruncatedHeaderExtension
	} else if extensionEnd != headerLen {
		return false, errHeaderLengthMismatch
	} else if extensionLength == 0 {
		return false, nil
	}

	counter := generateCounter(header.SequenceNumber, roc, header.SSRC, s.headerSessionSalt)

	switch header.ExtensionProfile {
	case rtp.ExtensionProfileOneByte:
		return s.cryptOneByteHeaderExtensions(buf, extensionElementsStart, extensionEnd, counter)
	case rtp.ExtensionProfileTwoByte:
		return s.cryptTwoByteHeaderExtensions(buf, extensionElementsStart, extensionEnd, counter)
	default:
		return false, fmt.Errorf("%w: %#x", errUnsupportedHeaderExtension, header.ExtensionProfile)
	}
}

// cryptOneByteHeaderExtensions walks RFC 8285 one-byte elements: a 4-bit ID, a 4-bit length
// minus one, and the element payload. A zero byte is padding and is skipped. An ID of 0 or 15
// terminates parsing, as required by RFC 5285.
func (s *srtpCipherAesCmHmacSha1) cryptOneByteHeaderExtensions(
	buf []byte,
	extensionStart, extensionEnd int,
	counter [aes.BlockSize]byte,
) (bool, error) {
	modified := false
	for pos := extensionStart; pos < extensionEnd; {
		elementHeader := buf[pos]
		if elementHeader == 0 { // Padding octet.
			pos++

			continue
		}

		id := elementHeader >> 4
		if id == 0 || id == 0x0F { // RFC 5285: ID 0 is padding, ID 15 is reserved.
			break
		}

		length := int(elementHeader&0x0F) + 1
		pos++
		if pos+length > extensionEnd {
			return modified, errTruncatedHeaderExtension
		}

		if s.isEncryptedHeaderExtensionID(id) {
			// The one-byte form cannot express a zero-length element, so length is always > 0.
			xorHeaderExtensionKeystream(s.headerEncryptionBlock, counter, buf[pos:pos+length], pos-extensionStart)
			modified = true
		}

		pos += length
	}

	return modified, nil
}

// cryptTwoByteHeaderExtensions walks RFC 8285 two-byte elements: an 8-bit ID, an 8-bit length,
// and the element payload. A zero byte is padding and is skipped, so an element with ID 0 cannot
// be expressed in this form. Zero-length elements are valid and are left untouched, as RFC 6904
// does not protect them.
func (s *srtpCipherAesCmHmacSha1) cryptTwoByteHeaderExtensions(
	buf []byte,
	extensionStart, extensionEnd int,
	counter [aes.BlockSize]byte,
) (bool, error) {
	modified := false
	for pos := extensionStart; pos < extensionEnd; {
		if buf[pos] == 0 { // Padding octet.
			pos++

			continue
		}

		if pos+2 > extensionEnd {
			return modified, errTruncatedHeaderExtension
		}

		id := buf[pos]
		length := int(buf[pos+1])
		pos += 2
		if pos+length > extensionEnd {
			return modified, errTruncatedHeaderExtension
		}

		if length > 0 && s.isEncryptedHeaderExtensionID(id) {
			xorHeaderExtensionKeystream(s.headerEncryptionBlock, counter, buf[pos:pos+length], pos-extensionStart)
			modified = true
		}

		pos += length
	}

	return modified, nil
}

// xorHeaderExtensionKeystream XORs payload with the AES-CM keystream generated for the packet,
// starting at the given offset inside the header extension element area. offset is relative to
// the first element ID/length byte, exactly as required by RFC 6904.
func xorHeaderExtensionKeystream(block cipher.Block, counter [aes.BlockSize]byte, payload []byte, offset int) {
	if len(payload) == 0 {
		return
	}

	var sedCounter [aes.BlockSize]byte
	copy(sedCounter[:], counter[:])
	for range offset / aes.BlockSize {
		incrementCTR(sedCounter[:])
	}

	var keystream [aes.BlockSize]byte
	skip := offset % aes.BlockSize
	for pos := 0; pos < len(payload); {
		block.Encrypt(keystream[:], sedCounter[:])
		incrementCTR(sedCounter[:])

		n := xor.XorBytes(payload[pos:], payload[pos:], keystream[skip:])
		pos += n
		skip = 0
	}
}
