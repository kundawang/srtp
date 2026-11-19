// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 6904, Appendix A.1: header encryption and salting keys derived from the master key/salt.
const (
	rfc6904MasterKey  = `E1F97A0D3E018BE0D64FA32C06DE4139`
	rfc6904MasterSalt = `0EC675AD498AFEEBB6960B3AABE6`
	rfc6904HeaderKey  = `549752054D6FB708622C4A2E596A1B93`
	rfc6904HeaderSalt = `AB01818174C40D39A3781F7C2D27`
)

// RFC 6904, Appendix A.2: extension element payload byte ranges within the header extension.
//
//nolint:gochecknoglobals // Shared test fixture.
var rfc6904ElementPayloads = map[uint8][2]int{
	1: {1, 9},   // Payload of ID 1: 8 bytes.
	2: {10, 13}, // Payload of ID 2: 3 bytes.
	3: {14, 15}, // Payload of ID 3: 1 byte.
	4: {16, 23}, // Payload of ID 4: 7 bytes.
}

// rfc6904PlainExtension is the plaintext header extension from RFC 6904, Appendix A.2, prefixed
// with the 0xBEDE / 0x0006 "defined by profile" and "length" fields.
//
//nolint:gochecknoglobals // Shared test fixture.
var rfc6904PlainExtension = mustHex(`bede0006
	17 414273A475262748 22 0000C8 30 8E 46 55996386B395FB 00`)

// rfc6904PlainPacket is the complete RTP packet used by the RFC 6904 test vectors. The extension
// block is followed by an 8-byte payload so that payload encryption is exercised as well.
//
//nolint:gochecknoglobals // Shared test fixture.
var rfc6904PlainPacket = append(
	append(mustHex(`90601234 DECAFBAD CAFEBABE`), rfc6904PlainExtension...),
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
)

func rfc6904Cipher(t *testing.T, ids ...uint8) *Context {
	t.Helper()

	keys := derivedSessionKeys{
		srtpSessionKey:      fromHex(t, `c61e7a93744f39ee10734afe3ff7a087`),
		srtpSessionSalt:     fromHex(t, `30cbbc08863d8c85d49db34a9ae1`),
		srtpSessionAuthTag:  fromHex(t, `cebe321f6ff7716b6fd4ab49af256a156d38baa4`),
		srtcpSessionKey:     fromHex(t, `c61e7a93744f39ee10734afe3ff7a087`),
		srtcpSessionSalt:    fromHex(t, `30cbbc08863d8c85d49db34a9ae1`),
		srtcpSessionAuthTag: fromHex(t, `cebe321f6ff7716b6fd4ab49af256a156d38baa4`),
	}

	cipher, err := newSrtpCipherAesCmHmacSha1WithDerivedKeysAndHeaderKeys(
		ProtectionProfileAes128CmHmacSha1_80, keys, true, true,
		fromHex(t, rfc6904HeaderKey), fromHex(t, rfc6904HeaderSalt), ids...)
	require.NoError(t, err)

	ctx, err := createContextWithCipher(ProtectionProfileAes128CmHmacSha1_80, cipher)
	require.NoError(t, err)

	return ctx
}

// mustHex decodes a hex string, panicking on malformed input. It is used for package-level test
// fixtures that cannot take a *testing.T.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "", "\r", "").Replace(s))
	if err != nil {
		panic(err)
	}

	return b
}

// assertRFC6904Extension checks that only the payloads of the RFC 6904 element IDs were transformed.
// It takes the complete extension block, including the "defined by profile" and "length" fields.
func assertRFC6904Extension(t *testing.T, actual, expected []byte) {
	t.Helper()

	require.Len(t, actual, len(expected), "the header extension encryption must not change the packet size")

	// Bytes outside the element payloads are never touched. The element area starts after the
	// 4-byte "defined by profile" / "length" preamble, which is also never modified.
	for pos := range expected {
		protected := false
		if pos >= extensionHeaderSize {
			for _, span := range rfc6904ElementPayloads {
				if pos >= extensionHeaderSize+span[0] && pos < extensionHeaderSize+span[1] {
					protected = true

					break
				}
			}
		}
		if !protected {
			assert.Equal(t, expected[pos], actual[pos], "byte %d outside an element payload must not change", pos)
		}
	}
}

func TestKeyDerivationHeaderExtensionRFC6904(t *testing.T) {
	masterKey := fromHex(t, rfc6904MasterKey)
	masterSalt := fromHex(t, rfc6904MasterSalt)

	headerKey, err := aesCmKeyDerivation(labelSRTPHeaderEncryption, masterKey, masterSalt, 0, 16)
	require.NoError(t, err)
	assert.Equal(t, fromHex(t, rfc6904HeaderKey), headerKey)

	headerSalt, err := aesCmKeyDerivation(labelSRTPHeaderSalt, masterKey, masterSalt, 0, 14)
	require.NoError(t, err)
	assert.Equal(t, fromHex(t, rfc6904HeaderSalt), headerSalt)
}

func TestHeaderExtensionEncryptionRFC6904(t *testing.T) {
	// Header extension IDs 1, 3 and 4 are negotiated as encrypted in RFC 6904, Appendix A.2.
	encryptedExtension := fromHex(t, `bede0006
		17 588A9270F4E15E1C 22 0000C8 30 95 46 A994F0BC547897 00`)
	extensionEnd := minSrtpHeaderSize + len(rfc6904PlainExtension)

	t.Run("Encrypt", func(t *testing.T) {
		ctx := rfc6904Cipher(t, 1, 3, 4)

		actual, err := ctx.EncryptRTP(nil, rfc6904PlainPacket, nil)
		require.NoError(t, err)
		require.Len(t, actual, len(rfc6904PlainPacket)+10)

		assertRFC6904Extension(t, actual[minSrtpHeaderSize:extensionEnd], encryptedExtension)
	})

	t.Run("Decrypt", func(t *testing.T) {
		encrypted, err := rfc6904Cipher(t, 1, 3, 4).EncryptRTP(nil, rfc6904PlainPacket, nil)
		require.NoError(t, err)

		decrypted, err := rfc6904Cipher(t, 1, 3, 4).DecryptRTP(nil, encrypted, nil)
		require.NoError(t, err)
		assert.Equal(t, rfc6904PlainPacket, decrypted)
	})

	t.Run("Only selected IDs are encrypted", func(t *testing.T) {
		actual, err := rfc6904Cipher(t, 4).EncryptRTP(nil, rfc6904PlainPacket, nil)
		require.NoError(t, err)

		extension := actual[minSrtpHeaderSize:extensionEnd]
		expected := fromHex(t, `bede0006
			17 414273A475262748 22 0000C8 30 8E 46 A994F0BC547897 00`)
		assert.Equal(t, expected, extension)

		// The elements that are not selected stay in the clear.
		assert.Equal(t, rfc6904PlainExtension[5:13], extension[5:13])
		assert.Equal(t, rfc6904PlainExtension[18:19], extension[18:19])
	})

	t.Run("No IDs configured is a no-op", func(t *testing.T) {
		actual, err := rfc6904Cipher(t).EncryptRTP(nil, rfc6904PlainPacket, nil)
		require.NoError(t, err)
		assert.Equal(t, rfc6904PlainExtension, actual[minSrtpHeaderSize:extensionEnd])
	})
}

func TestHeaderExtensionEncryptionRoundTrip(t *testing.T) {
	send, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)

	recv, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)

	// RTP header, payload and padding must survive a round trip unharmed.
	for _, paddingSize := range []byte{0, 4} {
		packet := rtp.Packet{
			Header: rtp.Header{
				Version:          2,
				SequenceNumber:   0x1234,
				Timestamp:        0xDECAFBAD,
				SSRC:             0xCAFEBABE,
				Extension:        true,
				ExtensionProfile: rtp.ExtensionProfileOneByte,
				Padding:          paddingSize > 0,
				PaddingSize:      paddingSize,
			},
			Payload: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		}
		require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `414273A475262748`)))
		require.NoError(t, packet.Header.SetExtension(2, fromHex(t, `0000C8`)))
		require.NoError(t, packet.Header.SetExtension(3, fromHex(t, `8E`)))
		require.NoError(t, packet.Header.SetExtension(4, fromHex(t, `55996386B395FB`)))

		raw, err := packet.Marshal()
		require.NoError(t, err)

		encrypted, err := send.EncryptRTP(nil, raw, nil)
		require.NoError(t, err)

		decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
		require.NoError(t, err)
		assert.Equal(t, raw, decrypted)

		// Authenticated and decrypted headers must still expose the clear-text elements.
		var decoded rtp.Packet
		require.NoError(t, decoded.Unmarshal(decrypted))
		assert.Equal(t, fromHex(t, `0000C8`), decoded.Header.GetExtension(2),
			"unencrypted extension ID 2 must stay readable")
		assert.Equal(t, fromHex(t, `414273A475262748`), decoded.Header.GetExtension(1))
		assert.Equal(t, paddingSize, decoded.Header.PaddingSize)
	}
}

func TestHeaderExtensionEncryptionTwoByteProfile(t *testing.T) {
	key := make([]byte, 16)
	salt := make([]byte, 14)

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SequenceNumber:   7,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileTwoByte,
		},
		Payload: []byte{0xAA, 0xBB},
	}
	// Zero-length element for the protected ID: RFC 6904 defines no protection for it.
	require.NoError(t, packet.Header.SetExtensionWithProfile(1, nil, rtp.ExtensionProfileTwoByte))
	require.NoError(t, packet.Header.SetExtension(2, fromHex(t, `00`)))
	require.NoError(t, packet.Header.SetExtension(3, fromHex(t, `0102030405060708090A0B0C0D0E0F10`)))

	raw, err := packet.Marshal()
	require.NoError(t, err)

	send, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3))
	require.NoError(t, err)
	recv, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3))
	require.NoError(t, err)

	encrypted, err := send.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)
	require.Len(t, encrypted, len(raw)+10)

	// Element headers, the zero-length element and the clear-text element are byte-identical on
	// the wire; only the 16-byte payload of ID 3 changes.
	extensionElementsStart := minSrtpHeaderSize + extensionHeaderSize
	assert.Equal(t, raw[extensionElementsStart:extensionElementsStart+5],
		encrypted[extensionElementsStart:extensionElementsStart+5])
	assert.NotEqual(t, raw[extensionElementsStart+7:extensionElementsStart+23],
		encrypted[extensionElementsStart+7:extensionElementsStart+23])

	decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, decrypted)
}

func TestHeaderExtensionEncryptionAuthFailureLeavesHeadersEncrypted(t *testing.T) {
	send, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)

	// A different master key means the packet must fail authentication and must not be decrypted.
	recv, err := CreateContext(make([]byte, 16), make([]byte, 14),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)

	encrypted, err := send.EncryptRTP(nil, rfc6904PlainPacket, nil)
	require.NoError(t, err)
	before := bytes.Clone(encrypted)

	_, err = recv.DecryptRTP(nil, encrypted, nil)
	assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)
	assert.Equal(t, before, encrypted, "a packet that fails authentication must not be modified")

	// Tampering with a protected header extension byte is detected by the authentication tag.
	tampered := bytes.Clone(encrypted)
	tampered[minSrtpHeaderSize+1] ^= 0xFF
	_, err = send.DecryptRTP(nil, tampered, nil)
	assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)
}

func TestHeaderExtensionEncryptionConfig(t *testing.T) {
	key := make([]byte, 16)
	salt := make([]byte, 14)

	t.Run("Unsupported profiles", func(t *testing.T) {
		for _, profile := range []ProtectionProfile{
			ProtectionProfileAeadAes128Gcm,
			ProtectionProfileAeadAes256Gcm,
			ProtectionProfileNullHmacSha1_80,
			ProtectionProfileNullHmacSha1_32,
		} {
			keyLen, err := profile.KeyLen()
			require.NoError(t, err)
			saltLen, err := profile.SaltLen()
			require.NoError(t, err)

			_, err = CreateContext(make([]byte, keyLen), make([]byte, saltLen), profile,
				SRTPHeaderExtensionEncryption(1))
			assert.ErrorIs(t, err, errUnsupportedHeaderExtensionProfile, profile.String())
		}
	})

	t.Run("Invalid IDs", func(t *testing.T) {
		_, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
			SRTPHeaderExtensionEncryption(0))
		assert.ErrorIs(t, err, errInvalidEncryptedHeaderExtensionID)
	})

	t.Run("Duplicate IDs", func(t *testing.T) {
		_, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
			SRTPHeaderExtensionEncryption(1, 2, 1))
		assert.ErrorIs(t, err, errDuplicateEncryptedHeaderExtension)
	})

	t.Run("Conflicts with Cryptex", func(t *testing.T) {
		for _, mode := range []CryptexMode{CryptexModeEnabled, CryptexModeRequired} {
			_, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
				SRTPHeaderExtensionEncryption(1), Cryptex(mode))
			assert.ErrorIs(t, err, errHeaderExtensionEncryptionAndCryptex)
		}
	})

	t.Run("Cannot enable Cryptex at runtime", func(t *testing.T) {
		ctx, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
			SRTPHeaderExtensionEncryption(1))
		require.NoError(t, err)

		err = ctx.UpdateOptions(Cryptex(CryptexModeEnabled))
		assert.ErrorIs(t, err, errHeaderExtensionEncryptionAndCryptex)
		assert.Equal(t, CryptexModeDisabled, ctx.cryptexMode, "a rejected option must not be applied")

		// Disabling Cryptex is still allowed.
		assert.NoError(t, ctx.UpdateOptions(Cryptex(CryptexModeDisabled)))
	})

	t.Run("Not updatable after construction", func(t *testing.T) {
		ctx, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80)
		require.NoError(t, err)

		err = ctx.UpdateOptions(SRTPHeaderExtensionEncryption(1))
		assert.ErrorIs(t, err, ErrContextOptionNotUpdatable)
	})

	t.Run("IDs are copied", func(t *testing.T) {
		ids := []uint8{1}
		ctx, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(ids...))
		require.NoError(t, err)

		ids[0] = 2
		assert.Equal(t, []uint8{1}, ctx.encryptedHeaderExtensionIDs)
	})

	t.Run("Preserved across key update", func(t *testing.T) {
		ctx, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
			SRTPHeaderExtensionEncryption(1, 2))
		require.NoError(t, err)

		next, err := ctx.contextWithKey(make([]byte, 16), make([]byte, 14), ProtectionProfileAes128CmHmacSha1_80)
		require.NoError(t, err)
		assert.Equal(t, []uint8{1, 2}, next.encryptedHeaderExtensionIDs)
	})
}

func TestHeaderExtensionEncryptionTruncatedPacket(t *testing.T) {
	cipher, ok := rfc6904Cipher(t, 1).cipher.(*srtpCipherAesCmHmacSha1)
	require.True(t, ok)
	header := &rtp.Header{
		Version:          2,
		SequenceNumber:   1,
		Extension:        true,
		ExtensionProfile: rtp.ExtensionProfileOneByte,
	}

	// A one-byte element that claims 16 payload bytes inside a 4-byte extension block. The RTP
	// parser rejects this earlier, so the cipher is called directly.
	truncated := fromHex(t, `9000 0001 00000000 00000000 BEDE 0001 1F 0102 03`)
	_, err := cipher.cryptHeaderExtensions(truncated, header, len(truncated), 0)
	assert.ErrorIs(t, err, errTruncatedHeaderExtension)

	// The extension "length" field claims more words than the header actually contains.
	overlong := fromHex(t, `9000 0001 00000000 00000000 BEDE 00FF 1001 0102`)
	_, err = cipher.cryptHeaderExtensions(overlong, header, len(overlong), 0)
	assert.ErrorIs(t, err, errTruncatedHeaderExtension)
}

func TestHeaderExtensionEncryptionUnknownIDIgnored(t *testing.T) {
	ctx, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(9))
	require.NoError(t, err)

	// No element with ID 9 is present: the packet must be left with a plain header extension.
	encrypted, err := ctx.EncryptRTP(nil, rfc6904PlainPacket, nil)
	require.NoError(t, err)
	assert.Equal(t, rfc6904PlainExtension,
		encrypted[minSrtpHeaderSize:minSrtpHeaderSize+len(rfc6904PlainExtension)])
}

func TestHeaderExtensionEncryptionKeyLength(t *testing.T) {
	// AES-256 uses 32-byte keys and salts derived with the same labels.
	key := bytes.Repeat([]byte{0x11}, 32)
	salt := bytes.Repeat([]byte{0x22}, 14)

	send, err := CreateContext(key, salt, ProtectionProfileAes256CmHmacSha1_80, SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)
	recv, err := CreateContext(key, salt, ProtectionProfileAes256CmHmacSha1_80, SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SequenceNumber:   1,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		},
		Payload: []byte{0xAA},
	}
	require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `01020304`)))
	raw, err := packet.Marshal()
	require.NoError(t, err)

	encrypted, err := send.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)
	assert.NotEqual(t, raw, encrypted)

	decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, decrypted)
}

func TestHeaderExtensionEncryptionMKI(t *testing.T) {
	// Key switches through MKI must derive the header keys from the key that protects the packet.
	masterKey1 := fromHex(t, rfc6904MasterKey)
	masterSalt1 := fromHex(t, rfc6904MasterSalt)
	masterKey2 := bytes.Repeat([]byte{0x5A}, 16)
	masterSalt2 := bytes.Repeat([]byte{0x6B}, 14)
	mki1 := []byte{0x01, 0x02}
	mki2 := []byte{0x03, 0x04}

	send, err := CreateContext(masterKey1, masterSalt1, ProtectionProfileAes128CmHmacSha1_80,
		MasterKeyIndicator(mki1), SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)
	require.NoError(t, send.AddCipherForMKI(mki2, masterKey2, masterSalt2))

	recv, err := CreateContext(masterKey1, masterSalt1, ProtectionProfileAes128CmHmacSha1_80,
		MasterKeyIndicator(mki1), SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)
	require.NoError(t, recv.AddCipherForMKI(mki2, masterKey2, masterSalt2))

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SequenceNumber:   1,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		},
		Payload: []byte{0xAA},
	}
	require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `01020304`)))
	raw, err := packet.Marshal()
	require.NoError(t, err)

	encrypted1, err := send.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)
	require.NoError(t, send.SetSendMKI(mki2))
	encrypted2, err := send.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)
	assert.NotEqual(t, encrypted1, encrypted2)

	decrypted1, err := recv.DecryptRTP(nil, encrypted1, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, decrypted1)

	decrypted2, err := recv.DecryptRTP(nil, encrypted2, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, decrypted2)
}

func TestHeaderExtensionEncryptionPaddingElement(t *testing.T) {
	// Padding bytes inside the extension block are not element headers and stay untouched.
	key := make([]byte, 16)
	salt := make([]byte, 14)

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SequenceNumber:   1,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		},
		Payload: []byte{0xAA},
	}
	require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `0102`)))
	raw, err := packet.Marshal()
	require.NoError(t, err)

	// Move the extension length field so that the block holds the element plus a padding octet.
	raw[minSrtpHeaderSize+3] = 0x01

	ctx, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)

	encrypted, err := ctx.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)

	decrypted, err := ctx.DecryptRTP(nil, encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, decrypted)
}

func TestHeaderExtensionEncryptionNoExtension(t *testing.T) {
	// Packets without an extension block must be byte-identical to the unconfigured implementation.
	key := make([]byte, 16)
	salt := make([]byte, 14)

	plain, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80)
	require.NoError(t, err)

	withHeaderEncryption, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
		SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)

	packet := rtp.Packet{
		Header:  rtp.Header{Version: 2, SequenceNumber: 10, SSRC: 0x1234},
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	raw, err := packet.Marshal()
	require.NoError(t, err)

	expected, err := plain.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)
	actual, err := withHeaderEncryption.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestHeaderExtensionEncryptionUnsupportedProfileBytes(t *testing.T) {
	// RFC 3550 extensions use a profile other than the RFC 8285 one-byte/two-byte forms.
	ctx, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)

	// Fixed RTP header with the X bit set, followed by a non-RFC 8285 extension profile and one
	// word of extension data.
	raw := fromHex(t, `9000 0001 00000000 00000000 1234 0001 DEADBEEF`)

	_, err = ctx.EncryptRTP(nil, raw, nil)
	assert.ErrorIs(t, err, errUnsupportedHeaderExtension)
}

func TestHeaderExtensionEncryptionRFC6904VectorByteForByte(t *testing.T) {
	// The RFC 6904, Appendix A.2 vector extended to a complete SRTP packet with an 8-byte payload.
	packet := bytes.Clone(rfc6904PlainPacket)

	send, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)
	recv, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)

	encrypted, err := send.EncryptRTP(nil, packet, nil)
	require.NoError(t, err)
	assert.Equal(t, fromHex(t, `BEDE0006 17 588A9270F4E15E1C 22 0000C8 30 95 46 A994F0BC547897 00`),
		encrypted[minSrtpHeaderSize:minSrtpHeaderSize+len(rfc6904PlainExtension)])

	decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, rfc6904PlainPacket, decrypted)

	// The authentication tag covers the encrypted header extension: encrypting the header changes
	// the tag relative to a context without header extension encryption.
	plainCtx, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80)
	require.NoError(t, err)
	plainEncrypted, err := plainCtx.EncryptRTP(nil, packet, nil)
	require.NoError(t, err)
	assert.NotEqual(t, plainEncrypted[len(plainEncrypted)-10:], encrypted[len(encrypted)-10:])
}

func TestHeaderExtensionEncryptionSequenceNumberChangesKeystream(t *testing.T) {
	key := make([]byte, 16)
	salt := make([]byte, 14)

	ctx, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)

	// A one-byte element with ID 1 and one payload byte, padded to a 32-bit boundary.
	headerExtension := fromHex(t, `BEDE0001 10 AA 0000`)

	encrypt := func(sequenceNumber uint16) []byte {
		header := rtp.Header{
			Version:          2,
			SequenceNumber:   sequenceNumber,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		}
		buf := make([]byte, 0, 64)
		buf = append(buf, 0x90, 0x00)
		buf = binary.BigEndian.AppendUint16(buf, sequenceNumber)
		buf = binary.BigEndian.AppendUint32(buf, 0)
		buf = binary.BigEndian.AppendUint32(buf, 0xCAFEBABE)
		buf = append(buf, headerExtension...)

		headerLen := len(buf)
		encrypted, err := ctx.cipher.encryptRTP(nil, &header, headerLen, buf, 0, false)
		require.NoError(t, err)

		return encrypted[minSrtpHeaderSize+extensionHeaderSize : headerLen]
	}

	assert.NotEqual(t, encrypt(1), encrypt(2), "the per-packet keystream must depend on the sequence number")
}

func TestHeaderExtensionEncryptionRepeatedID(t *testing.T) {
	// RFC 5285 allows an ID to appear more than once; every occurrence of a protected ID must be
	// encrypted with the keystream position it occupies in this packet.
	key := make([]byte, 16)
	salt := make([]byte, 14)

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SequenceNumber:   1,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		},
		Payload: []byte{0xAA},
	}
	require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `0102`)))
	require.NoError(t, packet.Header.SetExtension(2, fromHex(t, `0304`)))
	require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `0506`)))

	raw, err := packet.Marshal()
	require.NoError(t, err)

	send, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)
	recv, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)

	encrypted, err := send.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)

	// The clear-text element keeps its payload, both occurrences of ID 1 are transformed.
	clearElementOffset := minSrtpHeaderSize + extensionHeaderSize + 3
	assert.Equal(t, raw[clearElementOffset:clearElementOffset+3], encrypted[clearElementOffset:clearElementOffset+3])

	decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, decrypted)
}

func TestHeaderExtensionEncryptionMixedProfilesRejected(t *testing.T) {
	// One-byte and two-byte profiles must not be mixed within a stream (RFC 5285), so a Context
	// configured for RFC 6904 rejects extension profiles it cannot safely parse.
	cipher, ok := rfc6904Cipher(t, 1).cipher.(*srtpCipherAesCmHmacSha1)
	require.True(t, ok)

	header := &rtp.Header{
		Version:          2,
		SequenceNumber:   1,
		Extension:        true,
		ExtensionProfile: 0x1234,
	}
	raw := fromHex(t, `9000 0001 00000000 00000000 1234 0001 DEADBEEF`)

	_, err := cipher.cryptHeaderExtensions(raw, header, len(raw), 0)
	assert.ErrorIs(t, err, errUnsupportedHeaderExtension)
}

func TestHeaderExtensionEncryptionNoExtensionIsUntouched(t *testing.T) {
	cipher, ok := rfc6904Cipher(t, 1).cipher.(*srtpCipherAesCmHmacSha1)
	require.True(t, ok)

	header := &rtp.Header{Version: 2, SequenceNumber: 1}
	raw := fromHex(t, `8000 0001 00000000 00000000 AABBCCDD`)
	before := bytes.Clone(raw)

	_, err := cipher.cryptHeaderExtensions(raw, header, minSrtpHeaderSize, 0)
	require.NoError(t, err)
	assert.Equal(t, before, raw)
}

func TestHeaderExtensionEncryptionDecryptIntoNewBufferUpdatesHeader(t *testing.T) {
	// When the caller decrypts into a different buffer, the rtp.Header passed in must describe the
	// decrypted extension block rather than the ciphertext it was parsed from.
	send, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)
	recv, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)

	encrypted, err := send.EncryptRTP(nil, rfc6904PlainPacket, nil)
	require.NoError(t, err)

	var header rtp.Header
	_, err = header.Unmarshal(encrypted)
	require.NoError(t, err)

	// Deliberately decrypt into a fresh buffer, which is not the one the header points into.
	decrypted, err := recv.DecryptRTP(make([]byte, 0, 128), encrypted, &header)
	require.NoError(t, err)

	decoded, err := decodedExtensions(decrypted)
	require.NoError(t, err)
	assert.Equal(t, fromHex(t, `414273A475262748`), decoded[1])
	assert.Equal(t, fromHex(t, `8E`), decoded[3])
	assert.Equal(t, fromHex(t, `55996386B395FB`), decoded[4])

	// The re-parsed header must expose the decrypted bytes too.
	assert.Equal(t, fromHex(t, `414273A475262748`), header.GetExtension(1))
}

// decodedExtensions returns the header extension payloads of a marshalled RTP packet by ID.
func decodedExtensions(packet []byte) (map[uint8][]byte, error) {
	var parsed rtp.Packet
	if err := parsed.Unmarshal(packet); err != nil {
		return nil, err
	}

	extensions := make(map[uint8][]byte, len(parsed.Header.Extensions))
	for _, id := range parsed.Header.GetExtensionIDs() {
		extensions[id] = parsed.Header.GetExtension(id)
	}

	return extensions, nil
}

func TestHeaderExtensionEncryptionWithoutPayloadEncryption(t *testing.T) {
	// Header extension encryption is independent of payload encryption: with SRTPNoEncryption the
	// RTP payload travels in the clear while the selected extension stays protected.
	key := make([]byte, 16)
	salt := make([]byte, 14)

	send, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
		SRTPNoEncryption(), SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)
	recv, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
		SRTPNoEncryption(), SRTPHeaderExtensionEncryption(1))
	require.NoError(t, err)

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SequenceNumber:   1,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		},
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `01020304`)))
	require.NoError(t, packet.Header.SetExtension(2, fromHex(t, `05060708`)))
	raw, err := packet.Marshal()
	require.NoError(t, err)

	encrypted, err := send.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)

	var decoded rtp.Packet
	require.NoError(t, decoded.Unmarshal(encrypted))
	// The auth tag follows the payload in an unencrypted SRTP packet, so compare the prefix.
	require.GreaterOrEqual(t, len(decoded.Payload), len(packet.Payload))
	assert.Equal(t, packet.Payload, decoded.Payload[:len(packet.Payload)], "the payload must stay in the clear")
	assert.Equal(t, fromHex(t, `05060708`), decoded.Header.GetExtension(2))
	assert.NotEqual(t, fromHex(t, `01020304`), decoded.Header.GetExtension(1))

	decrypted, err := recv.DecryptRTP(nil, encrypted, nil)
	require.NoError(t, err)
	assert.Equal(t, raw, decrypted)
}

func TestHeaderExtensionEncryptionDisabledOutputIsUnchanged(t *testing.T) {
	// Requirement: when the option is not used, the output is byte-identical to the original
	// implementation, including the authentication tag.
	key := make([]byte, 16)
	salt := make([]byte, 14)

	packet := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			SequenceNumber:   42,
			Timestamp:        0x01020304,
			SSRC:             0xCAFEBABE,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		},
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	require.NoError(t, packet.Header.SetExtension(1, fromHex(t, `01020304`)))
	require.NoError(t, packet.Header.SetExtension(2, fromHex(t, `05060708`)))
	raw, err := packet.Marshal()
	require.NoError(t, err)

	baseline, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80)
	require.NoError(t, err)
	expected, err := baseline.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)

	// Passing no IDs leaves the feature disabled.
	empty, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80,
		SRTPHeaderExtensionEncryption())
	require.NoError(t, err)
	actual, err := empty.EncryptRTP(nil, raw, nil)
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
	assert.Equal(t, raw[:len(raw)-4], actual[:len(raw)-4])
}

func TestHeaderExtensionEncryptionEncryptIntoNewBuffer(t *testing.T) {
	send, err := CreateContext(fromHex(t, rfc6904MasterKey), fromHex(t, rfc6904MasterSalt),
		ProtectionProfileAes128CmHmacSha1_80, SRTPHeaderExtensionEncryption(1, 3, 4))
	require.NoError(t, err)

	source := bytes.Clone(rfc6904PlainPacket)
	dst := make([]byte, 0, 256)

	encrypted, err := send.EncryptRTP(dst, source, nil)
	require.NoError(t, err)
	assert.Equal(t, source, rfc6904PlainPacket, "the plaintext buffer must not be modified")

	var header rtp.Header
	headerLen, err := header.Unmarshal(encrypted)
	require.NoError(t, err)
	assert.Equal(t, minSrtpHeaderSize+len(rfc6904PlainExtension), headerLen)
}
