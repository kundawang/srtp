// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionSRTPHeaderExtensionEncryption(t *testing.T) {
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const testSSRC = 5000

	protectedPayload := []byte{0x51, 0x52, 0x53, 0x54}
	clearPayload := []byte{0x61, 0x62}

	newHeader := func(sequenceNumber uint16) *rtp.Header {
		header := &rtp.Header{Version: 2, SSRC: testSSRC, SequenceNumber: sequenceNumber}
		require.NoError(t, header.SetExtension(1, protectedPayload))
		require.NoError(t, header.SetExtension(2, clearPayload))

		return header
	}

	keys := SessionKeys{
		LocalMasterKey:   fromHex(t, rfc6904MasterKey),
		LocalMasterSalt:  fromHex(t, rfc6904MasterSalt),
		RemoteMasterKey:  fromHex(t, rfc6904MasterKey),
		RemoteMasterSalt: fromHex(t, rfc6904MasterSalt),
	}
	config := &Config{
		Profile: ProtectionProfileAes128CmHmacSha1_80,
		Keys:    keys,
		// Both directions protect extension ID 1 and leave ID 2 readable.
		LocalOptions:  []ContextOption{SRTPHeaderExtensionEncryption(1)},
		RemoteOptions: []ContextOption{SRTPHeaderExtensionEncryption(1)},
	}

	aSession, bSession := buildSessionSRTPPairWithConfig(t, config)
	defer func() {
		assert.NoError(t, aSession.Close())
		assert.NoError(t, bSession.Close())
	}()

	aWriteStream, err := aSession.OpenWriteStream()
	require.NoError(t, err)
	bReadStream, err := bSession.OpenReadStream(testSSRC)
	require.NoError(t, err)

	payload := []byte{0xAA, 0xBB, 0xCC}
	require.NoError(t, aWriteStream.SetWriteDeadline(time.Now().Add(time.Second)))
	_, err = aWriteStream.WriteRTP(newHeader(1), payload)
	require.NoError(t, err)

	var readBuffer [1500]byte
	n, receivedHeader, err := bReadStream.ReadRTP(readBuffer[:])
	require.NoError(t, err)

	var decoded rtp.Packet
	require.NoError(t, decoded.Unmarshal(readBuffer[:n]))
	assert.Equal(t, payload, decoded.Payload)
	assert.Equal(t, uint16(rtp.ExtensionProfileOneByte), receivedHeader.ExtensionProfile)

	// The receiver recovers both extensions: the protected one and the clear-text one.
	assert.Equal(t, protectedPayload, receivedHeader.GetExtension(1))
	assert.Equal(t, clearPayload, receivedHeader.GetExtension(2))
}

func TestSessionSRTPHeaderExtensionEncryptionWrongIDs(t *testing.T) {
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const testSSRC = 5000
	keys := SessionKeys{
		LocalMasterKey:   fromHex(t, rfc6904MasterKey),
		LocalMasterSalt:  fromHex(t, rfc6904MasterSalt),
		RemoteMasterKey:  fromHex(t, rfc6904MasterKey),
		RemoteMasterSalt: fromHex(t, rfc6904MasterSalt),
	}

	// The sender protects ID 1 while the receiver expects ID 2 to be protected. Both still
	// authenticate correctly, but the header is mangled after decryption, so the extensions
	// cannot be recovered.
	config := &Config{
		Profile:       ProtectionProfileAes128CmHmacSha1_80,
		Keys:          keys,
		LocalOptions:  []ContextOption{SRTPHeaderExtensionEncryption(1)},
		RemoteOptions: []ContextOption{SRTPHeaderExtensionEncryption(2)},
	}

	aSession, bSession := buildSessionSRTPPairWithConfig(t, config)
	defer func() {
		assert.NoError(t, aSession.Close())
		assert.NoError(t, bSession.Close())
	}()

	aWriteStream, err := aSession.OpenWriteStream()
	require.NoError(t, err)
	bReadStream, err := bSession.OpenReadStream(testSSRC)
	require.NoError(t, err)

	header := &rtp.Header{Version: 2, SSRC: testSSRC, SequenceNumber: 1}
	require.NoError(t, header.SetExtension(1, []byte{0x11, 0x22, 0x33, 0x44}))

	require.NoError(t, aWriteStream.SetWriteDeadline(time.Now().Add(time.Second)))
	_, err = aWriteStream.WriteRTP(header, []byte{0xAA})
	require.NoError(t, err)

	var readBuffer [1500]byte
	require.NoError(t, bReadStream.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	n, receivedHeader, err := bReadStream.ReadRTP(readBuffer[:])
	require.NoError(t, err)
	require.NotZero(t, n)

	// The packet authenticates (the tag covers the encrypted bytes), so it is delivered, but the
	// element the sender encrypted is not the one the receiver expected. ID 1 therefore still
	// carries the ciphertext instead of the original value.
	assert.NotEqual(t, []byte{0x11, 0x22, 0x33, 0x44}, receivedHeader.GetExtension(1))
}

func buildSessionSRTPPairWithConfig(t *testing.T, config *Config) (*SessionSRTP, *SessionSRTP) {
	t.Helper()

	aPipe, bPipe := net.Pipe()

	if config.LoggerFactory == nil {
		config.LoggerFactory = logging.NewDefaultLoggerFactory()
	}

	aSession, err := NewSessionSRTP(aPipe, config)
	require.NoError(t, err)
	bSession, err := NewSessionSRTP(bPipe, config)
	require.NoError(t, err)

	return aSession, bSession
}
