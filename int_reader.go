package elf

import (
	"encoding/binary"
	"fmt"
	"io"
)

type endian interface {
	Uint16([]byte) uint16
	Uint32([]byte) uint32
	Uint64([]byte) uint64
}

type IntReader struct {
	endian endian
	reader io.Reader
}

func BigEndianReader(reader io.Reader) IntReader {
	return IntReader{
		endian: binary.BigEndian,
		reader: reader,
	}
}

func LittleEndianReader(reader io.Reader) IntReader {
	return IntReader{
		endian: binary.LittleEndian,
		reader: reader,
	}
}

func (ir IntReader) Uint8() (uint8, error) {
	buff, err := ir.readBytes(1)
	if err != nil {
		return 0, err
	}
	return buff[0], nil
}

func (ir IntReader) Uint16() (uint16, error) {
	buff, err := ir.readBytes(2)
	if err != nil {
		return 0, err
	}
	return ir.endian.Uint16(buff), nil
}

func (ir IntReader) Uint32() (uint32, error) {
	buff, err := ir.readBytes(4)
	if err != nil {
		return 0, err
	}
	return ir.endian.Uint32(buff), nil
}

func (ir IntReader) Uint64() (uint64, error) {
	buff, err := ir.readBytes(8)
	if err != nil {
		return 0, err
	}
	return ir.endian.Uint64(buff), nil
}

func (ir IntReader) readBytes(size int) ([]byte, error) {
	buff := make([]byte, size)
	_, err := io.ReadFull(ir.reader, buff)
	if err != nil {
		return nil, fmt.Errorf("int of size: %v read: %v", size, err)
	}
	return buff, nil
}

type NativeWordReader struct {
	class ELFClass
	IntReader
}

func (dwr NativeWordReader) ReadNativeWord() (uint64, error) {
	switch dwr.class {
	case ELFClass32:
		val, err := dwr.Uint32()
		return uint64(val), err
	case ELFClass64:
		return dwr.Uint64()
	}
	return 0, fmt.Errorf("unsupported class: %v", dwr.class)
}
