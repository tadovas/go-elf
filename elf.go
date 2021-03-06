package elf

import (
	"errors"
	"fmt"
	"io"
)

var magic = [4]byte{0x7F, 0x45, 0x4c, 0x46}

type ELFClass int

const (
	ELFClass32 ELFClass = iota + 1
	ELFClass64
)

func (ec ELFClass) String() string {
	return [...]string{"", "32bit", "64bit"}[ec]
}

type Endianess int

const (
	LittleEndian Endianess = iota + 1
	BigEndian
)

func (e Endianess) String() string {
	return [...]string{"", "Little endian", "Big endian"}[e]
}

const Version = 1

type OSAbi int

const (
	System_V OSAbi = iota
	HP_UX
	NetBSD
	Linux
	GNU_Hurd
	Solaris
	AIX
	IRIX
	FreeBSD
	Tru64
	Novell_Modesto
	OpenBSD
	OpenVMS
	NonStop_Kernel
	AROS
	Fenix_OS
	CloudABI
	Stratus_Technologies_OpenVOS
)

func (osabi OSAbi) String() string {
	return [...]string{
		"System V",
		"HP UX",
		"NetBSD",
		"Linux",
		"GNU Hurd",
		"Solaris",
		"AIX",
		"IRIX",
		"FreeBSD",
		"Tru64",
		"Novell Modesto",
		"OpenBSD",
		"OpenVMS",
		"NonStop Kernel",
		"AROS",
		"Fenix OS",
		"CloudABI",
		"Stratus Technologies OpenVOS",
	}[osabi]
}

type ABIVersion int

type ObjectType int

const (
	ET_NONE ObjectType = iota
	ET_REL
	ET_EXEC
	ET_DYN
	ET_CORE
	ET_LOOS   = 0x0fe00
	ET_HIOS   = 0x0feff
	ET_LOPROC = 0x0ff00
	ET_HIPROC = 0x0ffff
)

func (ot ObjectType) String() string {
	if ot < 4 {
		return [...]string{"none", "rel", "exec", "dyn", "core"}[ot]
	}
	switch ot {
	case ET_LOOS:
		return "low OS"
	case ET_HIOS:
		return "high OS"
	case ET_LOPROC:
		return "low proc"
	case ET_HIPROC:
		return "high proc"
	}
	return fmt.Sprintf("unknown: %04X", int(ot))
}

type InstructionSet int

const (
	ISNotSpecified  InstructionSet = 0x00
	ISSparc                        = 0x02
	ISx86                          = 0x03
	ISMIPS                         = 0x08
	ISPowerPC                      = 0x14
	ISPowerPC64                    = 0x15
	ISS390WithS390x                = 0x16
	ISARM                          = 0x28
	ISSuperH                       = 0x2A
	ISIA64                         = 0x32
	ISAmd64                        = 0x3E
	ISTMS320C6000                  = 0x8C
	ISAArch64                      = 0xB7
	ISRISCV                        = 0xF3
)

func (is InstructionSet) String() string {
	switch is {
	case ISNotSpecified:
		return "not-specific"
	case ISSparc:
		return "SPARC"
	case ISx86:
		return "x86"
	case ISMIPS:
		return "MIPS"
	case ISPowerPC:
		return "PowerPC"
	case ISPowerPC64:
		return "PowerPC (64-bit)"
	case ISS390WithS390x:
		return "S390, including S390x"
	case ISARM:
		return "ARM"
	case ISSuperH:
		return "SuperH"
	case ISIA64:
		return "IA-64"
	case ISAmd64:
		return "amd64"
	case ISTMS320C6000:
		return "TMS320C6000 Family"
	case ISAArch64:
		return "AArch64"
	case ISRISCV:
		return "RISC-V"
	}
	return fmt.Sprintf("")
}

type MemoryAddress uint64

func (ma MemoryAddress) String() string {
	return fmt.Sprintf("0x%08X", uint64(ma))
}

type FileOffset uint64

func (fo FileOffset) String() string {
	return fmt.Sprintf("0x%08X", uint64(fo))
}

type ArchNativeFlags uint32

func (mf ArchNativeFlags) String() string {
	return fmt.Sprintf("0x%04X", uint32(mf))
}

type TableInfo struct {
	Offset     FileOffset
	EntrySize  uint16
	EntryCount uint16
}

type Header struct {
	// Magic 4 bytes - 0x7F followed by ELF(45 4c 46)
	Class     ELFClass
	Endianess Endianess
	// Version always 1 (one byte)
	OSAbi      OSAbi
	ABIVersion ABIVersion
	// 7 bytes of padding
	// after this point all non 1 byte fields are Endianess dependent
	ObjectType ObjectType     // 2 bytes size
	ISet       InstructionSet // 2 bytes size
	// version 4 bytes - always 1
	EntryPoint         MemoryAddress   // 4 or 8 bytes size depending on Class
	ProgramHeaderTable TableInfo       // 4 or 8 bytes size for offset field - other fields are readed below
	SectionHeaderTable TableInfo       // 4 or 8 bytes size for offset field - other fields are readed below
	ArchNativeFlags    ArchNativeFlags // 4 bytes
	// ProgramHeaderSize  int           2 bytes size of program header entry in table
	// ProgramHeaderCount int           2 bytes count of program header entries in table
	// SectionHeaderSize  int           2 bytes - size of section header entry in table
	// SectionHeaderCount int           2 bytes - count of section header entry in table
	NamesSectionIndex uint16 // 2 bytes - index to section table for section with section names
	// ELF header size is 52 for 32bit ELF or 64 for 64bit ELF
}

var ErrInvalidELF = errors.New("invalid ELF format")

func Read(reader io.Reader) (Header, error) {
	var header Header

	var first4 [4]byte
	_, err := io.ReadFull(reader, first4[:])
	if err != nil {
		return header, fmt.Errorf("%w read magic: %v", ErrInvalidELF, err)
	}
	if first4 != magic {
		return header, fmt.Errorf("%w magic check fail", ErrInvalidELF)
	}

	val, err := singleByte(reader)
	if err != nil {
		return header, fmt.Errorf("%w class read: %v", ErrInvalidELF, err)
	}
	header.Class = ELFClass(val)

	val, err = singleByte(reader)
	if err != nil {
		return header, fmt.Errorf("%w endianess read: %v", ErrInvalidELF, err)
	}
	header.Endianess = Endianess(val)

	version, err := singleByte(reader)
	if err != nil {
		return header, fmt.Errorf("%w version read: %v", ErrInvalidELF, err)
	}
	if version != Version {
		return header, fmt.Errorf("%w uknown version: %v", ErrInvalidELF, version)
	}

	val, err = singleByte(reader)
	if err != nil {
		return header, fmt.Errorf("%w OS ABI read: %v", ErrInvalidELF, err)
	}
	header.OSAbi = OSAbi(val)

	val, err = singleByte(reader)
	if err != nil {
		return header, fmt.Errorf("%w ABI version read: %v", ErrInvalidELF, err)
	}
	header.ABIVersion = ABIVersion(val)

	var padding [7]byte
	_, err = reader.Read(padding[:])
	if err != nil {
		return header, fmt.Errorf("%w padding read: %v", ErrInvalidELF, err)
	}
	// from this point any fields bigger than 1 byte need to be accessed by big/little endian semantics
	nativeReader := header.NativeReader(reader)

	uint16val, err := nativeReader.Uint16()
	if err != nil {
		return header, fmt.Errorf("%w object type read: %v", ErrInvalidELF, err)
	}
	header.ObjectType = ObjectType(uint16val)

	uint16val, err = nativeReader.Uint16()
	if err != nil {
		return header, fmt.Errorf("%w instr set read: %v", ErrInvalidELF, err)
	}
	header.ISet = InstructionSet(uint16val)

	uint32val, err := nativeReader.Uint32()
	if err != nil {
		return header, fmt.Errorf("%w ELF version read: %v", ErrInvalidELF, err)
	}
	if uint32val != 1 {
		return header, fmt.Errorf("%w unexpected ELF version: %v", ErrInvalidELF, uint16val)
	}

	uint64val, err := nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w entrypoint read: %v", ErrInvalidELF, err)
	}
	header.EntryPoint = MemoryAddress(uint64val)

	uint64val, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w program table offset read: %v", ErrInvalidELF, err)
	}
	header.ProgramHeaderTable.Offset = FileOffset(uint64val)

	uint64val, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w section table offset read: %v", ErrInvalidELF, err)
	}
	header.SectionHeaderTable.Offset = FileOffset(uint64val)

	uint32val, err = nativeReader.Uint32()
	if err != nil {
		return header, fmt.Errorf("%w machine flags read: %v", ErrInvalidELF, err)
	}
	header.ArchNativeFlags = ArchNativeFlags(uint32val)

	uint16val, err = nativeReader.Uint16()
	if err != nil {
		return header, fmt.Errorf("%w ELF header size read: %v", ErrInvalidELF, err)
	}
	if header.Class == ELFClass64 && uint16val != 0x040 {
		return header, fmt.Errorf("%w 64bit ELF header unexpected size: %v", ErrInvalidELF, uint16val)
	}
	if header.Class == ELFClass32 && uint16val != 0x034 {
		return header, fmt.Errorf("%w 32bit ELF header unexpected size: %v", ErrInvalidELF, uint16val)
	}

	if err := fillSizeCount(nativeReader, &header.ProgramHeaderTable); err != nil {
		return header, fmt.Errorf("%w program header table size and count read :%v", ErrInvalidELF, err)
	}

	if err := fillSizeCount(nativeReader, &header.SectionHeaderTable); err != nil {
		return header, fmt.Errorf("%w program header table size and count read :%v", ErrInvalidELF, err)
	}

	uint16val, err = nativeReader.Uint16()
	if err != nil {
		return header, fmt.Errorf("%w names section index: %v", ErrInvalidELF, err)
	}
	header.NamesSectionIndex = uint16val

	if header.SectionHeaderTable.EntryCount <= header.NamesSectionIndex {
		return header, fmt.Errorf("%w names section index %v out of bounds for section table: %v", ErrInvalidELF, header.NamesSectionIndex, header.SectionHeaderTable.EntryCount)
	}

	return header, nil
}

func (h Header) NativeReader(reader io.Reader) NativeWordReader {
	intReader := LittleEndianReader(reader)
	if h.Endianess == BigEndian {
		intReader = BigEndianReader(reader)
	}
	return NativeWordReader{
		IntReader: intReader,
		Class:     h.Class,
	}
}

func fillSizeCount(reader NativeWordReader, t *TableInfo) error {
	size, err := reader.Uint16()
	if err != nil {
		return fmt.Errorf("size read: %v", err)
	}
	t.EntrySize = size

	count, err := reader.Uint16()
	if err != nil {
		return fmt.Errorf("count read: %v", err)
	}
	t.EntryCount = count
	return nil
}

func singleByte(reader io.Reader) (int, error) {
	var singleByteBuff [1]byte
	_, err := reader.Read(singleByteBuff[:])
	if err != nil {
		return 0, err
	}
	return int(singleByteBuff[0]) & 0x0FF, nil
}
