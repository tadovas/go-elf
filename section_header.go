package elf

import (
	"errors"
	"fmt"
)

type SectionType uint32

const (
	//0x0	SHT_NULL	Section header table entry unused
	SectionTypeNull SectionType = iota
	//0x1	SHT_PROGBITS	Program data
	SectionTypeProgBits
	//0x2	SHT_SYMTAB	Symbol table
	SectionTypeSymTable
	//0x3	SHT_STRTAB	String table
	SectionTypeStrTable
	//0x4	SHT_RELA	Relocation entries with addends
	SectionTypeRelocEnt
	//0x5	SHT_HASH	Symbol hash table
	SectionTypeSymHash
	//0x6	SHT_DYNAMIC	Dynamic linking information
	SectionTypeDynLinkInfo
	//0x7	SHT_NOTE	Notes
	SectionTypeNotes
	//0x8	SHT_NOBITS	Program space with no data (bss)
	SectionTypeBSS
	//0x9	SHT_REL	Relocation entries, no addends
	SectionTypeRelocEntNA
	//0x0A	SHT_SHLIB	Reserved
	SectionTypeReserved
	//0x0B	SHT_DYNSYM	Dynamic linker symbol table
	SectionTypeDynLinkSymTab
	//0x0E	SHT_INIT_ARRAY	Array of constructors
	SectionTypeArrayOfConstr = iota + 2
	//0x0F	SHT_FINI_ARRAY	Array of destructors
	SectionTypeArrayOfDestr
	//0x10	SHT_PREINIT_ARRAY	Array of pre-constructors
	SectionTypeArrayOfPreConstr
	//0x11	SHT_GROUP	Section group
	SectionTypeSectionGroup
	//0x12	SHT_SYMTAB_SHNDX	Extended section indices
	SectionTypeExtSectionInd
	//0x13	SHT_NUM	Number of defined types.
	SectionTypeDefinedTypesNum
	//0x60000000	SHT_LOOS	Start OS-specific.
	SectionTypeOSSpecific = 0x60000000
)

type SectionFlags uint64

func (sf SectionFlags) String() string {
	return fmt.Sprintf("0x%08X", uint64(sf))
}

func (st SectionType) String() string {
	switch {
	case st < 18:
		return [...]string{
			"NULL",
			"PROGBITS",
			"SYMTAB",
			"STRTAB",
			"RELA",
			"HASH",
			"DYNAMIC",
			"NOTE",
			"NOBITS",
			"REL",
			"SHLIB",
			"DYNSYM",
			"INIT_ARRAY",
			"FINI_ARRAY",
			"PREINIT_ARRAY",
			"GROUP",
			"SYMTAB_SHNDX",
			"NUM",
		}[st]
	case st >= SectionTypeOSSpecific:
		return fmt.Sprintf("OS specific: 0x%08X", uint32(st))
	}
	return fmt.Sprintf("unknown: 0x%08X", uint32(st))
}

type SectionHeader struct {
	NameOffset uint32        // 4 bytes offset to .
	Type       SectionType   // 4 bytes
	Flags      SectionFlags  // 4 or 8 bytes
	Virtual    MemoryAddress // 4 or 8 bytes
	Offset     FileOffset    // 4 or 8 bytes
	Size       uint64        // 4 or 8 bytes
	Link       uint32        // 4 bytes section dependent
	Info       uint32        // 4 bytes section dependent
	Align      Alignment     // 4 or 8 bytes
	EntrySize  uint64        // 4 or 8 bytes
}

var ErrInvalidSectionHeader = errors.New("invalid section header")

func ReadSectionHeader(nativeReader NativeWordReader) (SectionHeader, error) {
	var header SectionHeader

	uint32val, err := nativeReader.Uint32()
	if err != nil {
		return header, fmt.Errorf("%w read name offset: %v", ErrInvalidSectionHeader, err)
	}
	header.NameOffset = uint32val

	uint32val, err = nativeReader.Uint32()
	if err != nil {
		return header, fmt.Errorf("%w read type: %v", ErrInvalidSectionHeader, err)
	}
	header.Type = SectionType(uint32val)

	uint64val, err := nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w read flags: %v", ErrInvalidSectionHeader, err)
	}
	header.Flags = SectionFlags(uint64val)

	uint64val, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w read virtual: %v", ErrInvalidSectionHeader, err)
	}
	header.Virtual = MemoryAddress(uint64val)

	uint64val, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w read file offset: %v", ErrInvalidSectionHeader, err)
	}
	header.Offset = FileOffset(uint64val)

	uint64val, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w read size: %v", ErrInvalidSectionHeader, err)
	}
	header.Size = uint64val

	uint32val, err = nativeReader.Uint32()
	if err != nil {
		return header, fmt.Errorf("%w read link: %v", ErrInvalidSectionHeader, err)
	}
	header.Link = uint32val

	uint32val, err = nativeReader.Uint32()
	if err != nil {
		return header, fmt.Errorf("%w read info: %v", ErrInvalidSectionHeader, err)
	}
	header.Info = uint32val

	uint64val, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w read align: %v", ErrInvalidSectionHeader, err)
	}
	header.Align = Alignment(uint64val)

	uint64val, err = nativeReader.ReadNativeWord()
	if err != nil {
		return header, fmt.Errorf("%w read entry size: %v", ErrInvalidSectionHeader, err)
	}
	header.EntrySize = uint64val

	return header, nil
}
