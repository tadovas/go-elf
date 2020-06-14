package elf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElfReader(t *testing.T) {
	tcs := []struct {
		filename string
	}{
		{
			"helloworld_linux_386",
		},
		{
			"helloworld_linux_amd64",
		},
		{
			"helloworld_linux_ppc64",
		},
	}
	for _, tc := range tcs {
		reader, err := os.Open(filepath.Join("testdata", tc.filename))
		assert.NoError(t, err)
		header, err := Read(reader)
		assert.NoError(t, err)
		t.Logf("%v -> %+v", tc.filename, header)
		nativeReader := header.NativeReader(reader)
		var i uint16
		t.Log("   --- Program header table ---")
		for i = 0; i < header.ProgramHeaderTable.EntryCount; i++ {
			programHeader, err := ReadProgramHeader(nativeReader)
			assert.NoError(t, err)
			t.Logf("   %+v", programHeader)
		}
		t.Log("   --- Section header table ---")
		for i = 0; i < header.SectionHeaderTable.EntryCount; i++ {
			sectionHeader, err := ReadSectionHeader(nativeReader)
			assert.NoError(t, err)
			t.Logf("   %+v", sectionHeader)
		}

	}
}
