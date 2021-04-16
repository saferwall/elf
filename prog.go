package elf

// ELF64ProgramHeader represents the program header table which is an array
// entries describing each program segment (in executable or shared object files)
// sections are grouped into segments for in-memory loading.
type ELF64ProgramHeader struct {
	Type   uint32 // Segment type
	Flags  uint32 // Segment attributes
	Off    uint64 // Offset in file
	Vaddr  uint64 // Virtual Address in memory
	Paddr  uint64 // Reserved
	Filesz uint64 // Size of segment in file
	Memsz  uint64 // Size of segment in memory
	Align  uint64 // Segment alignment
}

// ELF32ProgramHeader represents the program header table which is an array
// entries describing each program segment (in executable or shared object files)
// sections are grouped into segments for in-memory loading.
type ELF32ProgramHeader struct {
	Type   uint32 // Segment type
	Off    uint32 // Offset in file
	Vaddr  uint32 // Virtual Address in memory
	Paddr  uint32 // Reserved
	Filesz uint32 // Size of segment in file
	Memsz  uint32 // Size of segment in memory
	Flags  uint32 // Segment attributes
	Align  uint32 // Segment alignment
}
