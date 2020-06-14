package elf

import (
	"errors"
	"fmt"
	"strings"
)

type SegmentType uint32

const (
	SegmentTypeNull SegmentType = iota
	SegmentTypeLoad
	SegmentTypeDynLink
	SegmentTypeInterpreterInfo
	SegmentTypeAuxInfo
	SegmentTypeReserved
	SegmentTypeProgramHeaderTable
	SegmentTypeTLS
	SegmentTypeLowOS    = 0x60000000
	SegmentTypeGNUStack = 0x6474E551
	SegmentTypePaxFlags = 0x65041580
	SegmentTypeHiOS     = 0x6FFFFFFF
	SegmentTypeLowProc  = 0x70000000
	SegmentTypeHighProc = 0x7FFFFFFF
)

func (st SegmentType) String() string {
	switch {
	case st < 7:
		return [...]string{"null", "loadable", "dynamic link info", "interpreter info", "aux info", "reserverd", "prog hdr tbl", "TLS template"}[st]
	case st == SegmentTypeGNUStack:
		return "GUN stack"
	case st == SegmentTypePaxFlags:
		return "PAX flags"
	case st >= SegmentTypeLowOS && st <= SegmentTypeHiOS:
		return fmt.Sprintf("OS reserverd: 0x%04X", uint32(st))
	case st >= SegmentTypeLowProc && st <= SegmentTypeHighProc:
		return fmt.Sprintf("proc reserverd: 0x%04X", uint32(st))
	}
	return fmt.Sprintf("unknown segment type: 0x%04X", uint32(st))
}

// PF_X 0x1 Execute
// PF_W 0x2 Write
// PF_R 0x4 Read
type SegmentFlags uint32

func (sf SegmentFlags) HasSet(mask uint32) bool {
	return uint32(sf)&mask > 0
}

func (sf SegmentFlags) Writable() bool {
	return sf.HasSet(0x02)
}

func (sf SegmentFlags) Executable() bool {
	return sf.HasSet(0x01)
}

func (sf SegmentFlags) Readable() bool {
	return sf.HasSet(0x04)
}

func (sf SegmentFlags) String() string {
	var flags []string
	if sf.Executable() {
		flags = append(flags, "x")
	}
	if sf.Readable() {
		flags = append(flags, "r")
	}
	if sf.Writable() {
		flags = append(flags, "w")
	}
	return fmt.Sprintf("0x%04X [%v]", uint32(sf), strings.Join(flags, " "))
}

type Alignment uint64

func (a Alignment) String() string {
	if a < 2 {
		return "none"
	}
	var i int
	for i = 1; i < 64; i++ {
		check := uint64(0x01) << i
		if check == uint64(a) {
			return fmt.Sprintf("%v bits", i)
		}
	}
	panic("i reached end of loop count")
}

type ProgramHeader struct {
	Type            SegmentType   // 4 bytes size
	Flags           SegmentFlags  // 4 bytes (place here on elf64, before align field on elf32
	FileOffset      FileOffset    // 4 bytes on elf32 8 bytes on elf64
	VirtualAddress  MemoryAddress // 4 bytes on elf32 8 bytes on elf64
	PhysicalAddress MemoryAddress // 4 bytes on elf32 8 bytes on elf64
	SizeInFile      uint64        // 4 bytes on elf32 8 bytes on elf64
	SizeInMemory    uint64        // 4 bytes on elf32 8 bytes on elf64
	// flags place for elf32 // 4 bytes
	Alignment Alignment // 4 bytes for elf32 8 bytes on elf64
}

var InvalidProgramHeaderErr = errors.New("invalid program header")

func ReadProgramHeader(nativeReader NativeWordReader) (ProgramHeader, error) {
	var header ProgramHeader

	uint32val, err := nativeReader.Uint32()
	if err != nil {
		return header, fmt.Errorf("%w type read: %v", InvalidProgramHeaderErr, err)
	}
	header.Type = SegmentType(uint32val)

	if nativeReader.Class == ELFClass64 {
		uint32val, err = nativeReader.Uint32()
		if err != nil {
			return header, fmt.Errorf("%w elf64 flags read: %v", InvalidProgramHeaderErr, err)
		}
		header.Flags = SegmentFlags(uint32val)
	}

	wordVal, err := nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w file offset read: %v", InvalidProgramHeaderErr, err)
	}
	header.FileOffset = FileOffset(wordVal)

	wordVal, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w virtual mem addr read: %v", InvalidProgramHeaderErr, err)
	}
	header.VirtualAddress = MemoryAddress(wordVal)

	wordVal, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w physical addr read: %v", InvalidProgramHeaderErr, err)
	}
	header.PhysicalAddress = MemoryAddress(wordVal)

	wordVal, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w segment size in file read: %v", InvalidProgramHeaderErr, err)
	}
	header.SizeInFile = wordVal

	wordVal, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w segment size in mem read: %v", InvalidProgramHeaderErr, err)
	}
	header.SizeInMemory = wordVal

	if nativeReader.Class == ELFClass32 {
		uint32val, err = nativeReader.Uint32()
		if err != nil {
			return header, fmt.Errorf("%w elf32 flags read: %v", InvalidProgramHeaderErr, err)
		}
		header.Flags = SegmentFlags(uint32val)
	}

	wordVal, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w alignment read: %v", InvalidProgramHeaderErr, err)
	}
	header.Alignment = Alignment(wordVal)

	return header, nil
}
