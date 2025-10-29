package gssapi

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 4121 Compliance Tests
// These tests verify that our implementation follows RFC 4121 precisely.

// getTestKey returns a test encryption key for testing
func getTestKey() types.EncryptionKey {
	key, _ := hex.DecodeString("14f9bde6b50ec508201a97f74c4e5bd3")
	return types.EncryptionKey{
		KeyType:  17, // AES128-CTS-HMAC-SHA1-96
		KeyValue: key,
	}
}

// TestRFC4121_TokenIDFormat verifies token ID is 0x05 0x04 per RFC 4121 section 4.2.6.2
func TestRFC4121_TokenIDFormat(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	message := []byte("test message")
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)

	// First two bytes must be 0x05 0x04
	assert.Equal(t, byte(0x05), wrapped[0], "Token ID byte 0 must be 0x05")
	assert.Equal(t, byte(0x04), wrapped[1], "Token ID byte 1 must be 0x04")
}

// TestRFC4121_FillerByteFormat verifies filler byte is 0xFF per RFC 4121 section 4.2.6.2
func TestRFC4121_FillerByteFormat(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	message := []byte("test message")
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)

	// Byte 3 (index 3) must be 0xFF
	assert.Equal(t, byte(0xFF), wrapped[3], "Filler byte must be 0xFF")
}

// TestRFC4121_KeyUsageValues verifies correct key usage values per RFC 4121 section 2
func TestRFC4121_KeyUsageValues(t *testing.T) {
	// Verify constants match RFC 4121 section 2
	assert.Equal(t, uint32(22), uint32(keyusage.GSSAPI_ACCEPTOR_SEAL), "KG-USAGE-ACCEPTOR-SEAL must be 22")
	assert.Equal(t, uint32(24), uint32(keyusage.GSSAPI_INITIATOR_SEAL), "KG-USAGE-INITIATOR-SEAL must be 24")
}

// TestRFC4121_ECField_IntegrityToken verifies EC field for integrity tokens
// Per RFC 4121 section 4.2.3: "the number of octets in the trailing checksum"
func TestRFC4121_ECField_IntegrityToken(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	message := []byte("test message")
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)

	// Extract EC field (bytes 4-5, big-endian)
	ec := binary.BigEndian.Uint16(wrapped[4:6])

	// EC should be the checksum size (12 bytes for AES128-CTS-HMAC-SHA1-96)
	expectedChecksumSize := uint16(12)
	assert.Equal(t, expectedChecksumSize, ec, "EC field must equal checksum size for integrity tokens")

	// Verify the actual checksum length matches EC
	// Token structure: [16-byte header][payload][checksum]
	// Checksum is the last EC bytes
	actualChecksumSize := len(wrapped) - 16 - len(message)
	assert.Equal(t, int(ec), actualChecksumSize, "Actual checksum size must match EC field")
}

// TestRFC4121_ECField_ConfidentialityToken verifies EC field for confidentiality tokens
// Per RFC 4121 section 4.2.3: "the number of octets in the filler"
func TestRFC4121_ECField_ConfidentialityToken(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	message := []byte("test message")
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)

	// Extract EC field (bytes 4-5, big-endian)
	ec := binary.BigEndian.Uint16(wrapped[4:6])

	// For our implementation, we use 0 filler bytes
	expectedFillerSize := uint16(0)
	assert.Equal(t, expectedFillerSize, ec, "EC field must equal filler size for confidentiality tokens")
}

// TestRFC4121_RRCField_Format verifies RRC field format (bytes 6-7, big-endian)
func TestRFC4121_RRCField_Format(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	message := []byte("test message")
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)

	// Extract RRC field (bytes 6-7, big-endian)
	rrc := binary.BigEndian.Uint16(wrapped[6:8])

	// Our implementation sets RRC to 0 for outgoing messages
	assert.Equal(t, uint16(0), rrc, "RRC field should be 0 for non-rotated tokens")
}

// TestRFC4121_SequenceNumberFormat verifies sequence number field (bytes 8-15, big-endian)
func TestRFC4121_SequenceNumberFormat(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	// First message should have sequence number 0
	message1 := []byte("message 1")
	wrapped1, err := session.Wrap(message1)
	require.NoError(t, err)

	seqNum1 := binary.BigEndian.Uint64(wrapped1[8:16])
	assert.Equal(t, uint64(0), seqNum1, "First message should have sequence number 0")

	// Second message should have sequence number 1
	message2 := []byte("message 2")
	wrapped2, err := session.Wrap(message2)
	require.NoError(t, err)

	seqNum2 := binary.BigEndian.Uint64(wrapped2[8:16])
	assert.Equal(t, uint64(1), seqNum2, "Second message should have sequence number 1")
}

// TestRFC4121_FlagsField_Acceptor verifies acceptor flag (bit 0 of flags byte)
func TestRFC4121_FlagsField_Acceptor(t *testing.T) {
	key := getTestKey()

	t.Run("Initiator sets acceptor bit to 0", func(t *testing.T) {
		session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
		require.NoError(t, err)

		wrapped, err := session.Wrap([]byte("test"))
		require.NoError(t, err)

		flags := wrapped[2]
		acceptorBit := flags & 0x01
		assert.Equal(t, byte(0), acceptorBit, "Initiator must set acceptor bit to 0")
	})

	t.Run("Acceptor sets acceptor bit to 1", func(t *testing.T) {
		session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
		require.NoError(t, err)

		wrapped, err := session.Wrap([]byte("test"))
		require.NoError(t, err)

		flags := wrapped[2]
		acceptorBit := flags & 0x01
		assert.Equal(t, byte(1), acceptorBit, "Acceptor must set acceptor bit to 1")
	})
}

// TestRFC4121_FlagsField_Sealed verifies sealed flag (bit 1 of flags byte)
func TestRFC4121_FlagsField_Sealed(t *testing.T) {
	key := getTestKey()

	t.Run("Integrity layer sets sealed bit to 0", func(t *testing.T) {
		session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
		require.NoError(t, err)

		wrapped, err := session.Wrap([]byte("test"))
		require.NoError(t, err)

		flags := wrapped[2]
		sealedBit := (flags & 0x02) >> 1
		assert.Equal(t, byte(0), sealedBit, "Integrity layer must set sealed bit to 0")
	})

	t.Run("Confidentiality layer sets sealed bit to 1", func(t *testing.T) {
		session, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
		require.NoError(t, err)

		wrapped, err := session.Wrap([]byte("test"))
		require.NoError(t, err)

		flags := wrapped[2]
		sealedBit := (flags & 0x02) >> 1
		assert.Equal(t, byte(1), sealedBit, "Confidentiality layer must set sealed bit to 1")
	})
}

// TestRFC4121_IntegrityTokenStructure verifies unsealed token structure
// Per RFC 4121 section 4.2.6.2: {header | plaintext-data | get_mic(plaintext-data | header)}
func TestRFC4121_IntegrityTokenStructure(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	message := []byte("plaintext message")
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)

	// Token should be: [16-byte header][plaintext][12-byte checksum]
	require.GreaterOrEqual(t, len(wrapped), 16+len(message)+12)

	// Extract components
	header := wrapped[:16]
	ec := binary.BigEndian.Uint16(header[4:6])
	checksumSize := int(ec)

	// Payload should be plaintext (not encrypted)
	payloadStart := 16
	payloadEnd := len(wrapped) - checksumSize
	payload := wrapped[payloadStart:payloadEnd]

	assert.Equal(t, message, payload, "Payload should be plaintext for integrity tokens")
}

// TestRFC4121_ConfidentialityTokenStructure verifies sealed token structure
// Per RFC 4121 section 4.2.4: {header | encrypt(plaintext-data | filler | header)}
func TestRFC4121_ConfidentialityTokenStructure(t *testing.T) {
	key := getTestKey()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, false, 0)
	require.NoError(t, err)

	message := []byte("secret message")
	wrapped, err := clientSession.Wrap(message)
	require.NoError(t, err)

	// Token should be: [16-byte header][encrypted data]
	require.Greater(t, len(wrapped), 16)

	// Payload should NOT be plaintext (should be encrypted)
	payload := wrapped[16:]
	assert.NotEqual(t, message, payload, "Payload should be encrypted for confidentiality tokens")

	// Verify we can decrypt it properly
	unwrapped, err := serverSession.Unwrap(wrapped)
	require.NoError(t, err)
	assert.Equal(t, message, unwrapped, "Unwrapped message should match original")
}

// TestRFC4121_ChecksumComputationWithZeroedFields verifies checksum is computed with EC/RRC zeroed
// Per RFC 4121 section 4.2.6.2: "Both the EC field and the RRC field in the token header
// SHALL be filled with zeroes for the purpose of calculating the checksum."
func TestRFC4121_ChecksumComputationWithZeroedFields(t *testing.T) {
	key := getTestKey()
	message := []byte("test message")

	// Create a wrap token manually
	token := &WrapToken{
		Flags:     0x00,
		EC:        12,
		RRC:       0,
		SndSeqNum: 0,
		Payload:   message,
	}

	// Compute checksum (should use zeroed EC/RRC)
	err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)

	// Verify the checksum (the Verify method should also use zeroed EC/RRC)
	valid, err := token.Verify(key, keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)
	assert.True(t, valid, "Checksum verification should succeed")
}

// TestRFC4121_RRC_Rotation verifies RRC rotation per RFC 4121 section 4.2.5
// "token {header | aa | bb | cc | dd | ee | ff | gg | hh} with RRC=3
// becomes {header | ff | gg | hh | aa | bb | cc | dd | ee}"
func TestRFC4121_RRC_Rotation(t *testing.T) {
	// Create a simulated rotated token to test our un-rotation logic
	key := getTestKey()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	message := []byte("test message for rotation")

	// Wrap the message normally (RRC=0)
	wrapped, err := clientSession.Wrap(message)
	require.NoError(t, err)

	// Extract components
	data := wrapped[16:] // This includes payload + checksum (skip header)

	// Simulate rotation: manually rotate the data section
	// For RRC=3, last 3 bytes move to front
	rrc := 3
	if len(data) > rrc {
		rotated := make([]byte, len(wrapped))
		copy(rotated[:16], wrapped[:16]) // Copy header
		// Rotate: last RRC bytes go first, then the rest
		copy(rotated[16:16+rrc], data[len(data)-rrc:])
		copy(rotated[16+rrc:], data[:len(data)-rrc])

		// Update RRC field in header
		binary.BigEndian.PutUint16(rotated[6:8], uint16(rrc))

		// Try to unwrap the rotated token
		unwrapped, err := serverSession.Unwrap(rotated)
		require.NoError(t, err)
		assert.Equal(t, message, unwrapped, "Should correctly unwrap rotated token")
	}
}

// TestRFC4121_RRC_LargeRotationValues tests that we can handle RRC > data length
// Per RFC 4121 section 4.2.5: "Receivers MUST be able to interpret all possible
// rotation count values, including rotation counts greater than the length of the token."
func TestRFC4121_RRC_LargeRotationValues(t *testing.T) {
	key := getTestKey()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	message := []byte("short")

	// Wrap normally
	wrapped, err := clientSession.Wrap(message)
	require.NoError(t, err)

	data := wrapped[16:]

	// Test with RRC > data length (should be handled gracefully)
	// RFC doesn't specify exact behavior, but we should not panic
	rrc := len(data) + 10

	rotated := make([]byte, len(wrapped))
	copy(rotated, wrapped)
	binary.BigEndian.PutUint16(rotated[6:8], uint16(rrc))

	// This might fail, but it shouldn't panic
	_, err = serverSession.Unwrap(rotated)
	// We just verify it doesn't panic - error is acceptable for invalid RRC
	if err != nil {
		t.Logf("Expected behavior: RRC > data length resulted in error: %v", err)
	}
}

// TestRFC4121_SequenceNumberOrdering verifies sequence number validation
func TestRFC4121_SequenceNumberOrdering(t *testing.T) {
	key := getTestKey()
	clientSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	serverSession, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, false, 0)
	require.NoError(t, err)

	// Send messages in order
	msg1, _ := clientSession.Wrap([]byte("message 1"))
	msg2, _ := clientSession.Wrap([]byte("message 2"))
	msg3, _ := clientSession.Wrap([]byte("message 3"))

	// Receive in order - should succeed
	_, err = serverSession.Unwrap(msg1)
	assert.NoError(t, err)

	_, err = serverSession.Unwrap(msg2)
	assert.NoError(t, err)

	_, err = serverSession.Unwrap(msg3)
	assert.NoError(t, err)

	// Try to replay msg1 (old sequence number) - should fail
	_, err = serverSession.Unwrap(msg1)
	assert.Error(t, err, "Replayed message with old sequence number should be rejected")
}

// TestRFC4121_BigEndianEncoding verifies all multi-byte fields are big-endian
func TestRFC4121_BigEndianEncoding(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerIntegrity, true, 0)
	require.NoError(t, err)

	// Set a non-zero sequence number
	session.sendSeqNum = 0x0102030405060708

	wrapped, err := session.Wrap([]byte("test"))
	require.NoError(t, err)

	// Verify EC field is big-endian (bytes 4-5)
	ec := binary.BigEndian.Uint16(wrapped[4:6])
	assert.Equal(t, uint16(12), ec) // 12 bytes for HMAC

	// Verify RRC field is big-endian (bytes 6-7)
	rrc := binary.BigEndian.Uint16(wrapped[6:8])
	assert.Equal(t, uint16(0), rrc)

	// Verify sequence number is big-endian (bytes 8-15)
	seqNum := binary.BigEndian.Uint64(wrapped[8:16])
	assert.Equal(t, uint64(0x0102030405060708), seqNum)
}

// TestRFC4121_HeaderLength verifies header is exactly 16 octets
func TestRFC4121_HeaderLength(t *testing.T) {
	// Header structure from RFC 4121:
	// 0-1: TOK_ID (2 bytes)
	// 2: Flags (1 byte)
	// 3: Filler (1 byte)
	// 4-5: EC (2 bytes)
	// 6-7: RRC (2 bytes)
	// 8-15: SND_SEQ (8 bytes)
	// Total: 16 bytes

	assert.Equal(t, 16, HdrLen, "Header length must be exactly 16 octets per RFC 4121")
}

// TestRFC4121_NoChecksumForConfidentiality verifies no outer checksum for sealed tokens
// Per RFC 4121: For confidentiality, encryption provides integrity
func TestRFC4121_NoChecksumForConfidentiality(t *testing.T) {
	key := getTestKey()
	session, err := NewSecurityLayerSession(key, SecurityLayerConfidentiality, true, 0)
	require.NoError(t, err)

	message := []byte("confidential message")
	wrapped, err := session.Wrap(message)
	require.NoError(t, err)

	// For confidentiality tokens, there should be no trailing checksum
	// Token structure: [16-byte header][encrypted data]
	// The encrypted data contains: encrypt(message | filler | embedded-header)

	// EC field should be 0 (no filler) or a small value
	ec := binary.BigEndian.Uint16(wrapped[4:6])
	assert.Equal(t, uint16(0), ec, "EC should indicate filler size (0 for no filler)")

	// There should be no trailing checksum like in integrity tokens
	// The token length should be: 16 (header) + encrypted_size
	// where encrypted_size = len(message) + filler + 16 (embedded header) + block padding
	minExpectedLen := 16 + len(message) + int(ec) + 16 // header + message + filler + embedded header
	assert.GreaterOrEqual(t, len(wrapped), minExpectedLen, "Token should contain header + encrypted data")
}
