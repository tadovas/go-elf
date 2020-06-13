package elf

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testData = []byte{
	0x01,
	0x01, 0x02,
	0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

func TestBigEndianIntReads(t *testing.T) {
	reader := BigEndianReader(bytes.NewReader(testData))

	singleByte, err := reader.Uint8()
	assert.NoError(t, err)
	assert.Equal(t, uint8(0x01), singleByte)

	twoByteWord, err := reader.Uint16()
	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0102), twoByteWord)

	fourByteWord, err := reader.Uint32()
	assert.NoError(t, err)
	assert.Equal(t, uint32(0x01020304), fourByteWord)

	eightByteWord, err := reader.Uint64()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0x0102030405060708), eightByteWord)
}

func TestLittleEndianIntReads(t *testing.T) {
	reader := LittleEndianReader(bytes.NewReader(testData))

	singleByte, err := reader.Uint8()
	assert.NoError(t, err)
	assert.Equal(t, uint8(0x01), singleByte)

	twoByteWord, err := reader.Uint16()
	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0201), twoByteWord)

	fourByteWord, err := reader.Uint32()
	assert.NoError(t, err)
	assert.Equal(t, uint32(0x04030201), fourByteWord)

	eightByteWord, err := reader.Uint64()
	assert.NoError(t, err)
	assert.Equal(t, uint64(0x0807060504030201), eightByteWord)
}
