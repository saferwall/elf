// Package elf implements a parser for ELF binaries.
// The current file documents the flags as defined in :
// https://refspecs.linuxbase.org/elf/elf.pdf
package elf

import "encoding/binary"

// Indexes in Ident array.
const (
	EI_MAG0       = 0  // Start of magic bytes 0x7f
	EI_MAG1       = 1  // 'E'
	EI_MAG2       = 2  // 'L'
	EI_MAG3       = 3  // 'F'
	EI_CLASS      = 4  // Class of machine.
	EI_DATA       = 5  // Data format.
	EI_VERSION    = 6  // ELF format version.
	EI_OSABI      = 7  // Operating system / ABI identification
	EI_ABIVERSION = 8  // ABI version
	EI_PAD        = 9  // Start of padding (per SVR4 ABI).
	EI_NIDENT     = 16 // Size of e_ident array.
)

// Magic represents the 4 starting bytes representing file defining values.
type Magic [4]byte

const (
	// ELFMAG is the constant prelude to every ELF binary.
	ELFMAG = "\177ELF"
)

func (m Magic) String() string   { return string(m[:]) }
func (m Magic) GoString() string { return string(m[:]) }

// Class takes values of 1 or 2 depending on the architecture 32-bit or 64-bit.
type Class byte

const (
	// ELFCLASSNONE specifies an unknown class.
	ELFCLASSNONE Class = 0
	// ELFCLASS32 specifies 32-bit binaries.
	ELFCLASS32 Class = 1
	// ELFCLASS64 specifies 64-bit binaries.
	ELFCLASS64 Class = 2
)

var classStrings = []flagName{
	{0, "ELFCLASSNONE"},
	{1, "ELFCLASS32"},
	{2, "ELFCLASS64"},
}

func (c Class) String() string   { return stringify(uint32(c), classStrings, false) }
func (c Class) GoString() string { return stringify(uint32(c), classStrings, true) }

// Data takes values of 1 or 2 depending on whether its a little endian or big endian architecture.
type Data byte

const (
	// ELFDATANONE specifes an unknown architecture.
	ELFDATANONE Data = 0
	// DATA2LSB specifies a little-endian architecture 2's complement values lsb at lowest address.
	ELFDATA2LSB Data = 1
	// ELFDATA2MSB specifies a big-endian architecture 2's complement value msb at at lowest address.
	ELFDATA2MSB Data = 2
)

var dataStrings = []flagName{
	{0, "ELFDATANONE"},
	{1, "ELFDATA2LSB"},
	{2, "ELFDATA2MSB"},
}

func (d Data) String() string   { return stringify(uint32(d), dataStrings, false) }
func (d Data) GoString() string { return stringify(uint32(d), dataStrings, true) }

// Version specifies the current ELF version.
type Version byte

const (
	// EV_NONE specifes an unknown version.
	EV_NONE Version = 0
	// EV_CURRENT specifies the only current elf version equal to 1.
	EV_CURRENT Version = 1
)

var versionStrings = []flagName{
	{0, "NONE"},
	{1, "CURRENT"},
}

func (v Version) String() string   { return stringify(uint32(v), versionStrings, false) }
func (v Version) GoString() string { return stringify(uint32(v), versionStrings, true) }

// OSABI specifes the OS ABI version.
type OSABI byte

const (
	ELFOSABI_NONE       OSABI = 0   // UNIX System V ABI
	ELFOSABI_HPUX       OSABI = 1   // HP-UX operating system
	ELFOSABI_NETBSD     OSABI = 2   // NetBSD
	ELFOSABI_LINUX      OSABI = 3   // GNU/Linux
	ELFOSABI_HURD       OSABI = 4   // GNU/Hurd
	ELFOSABI_86OPEN     OSABI = 5   // 86Open common IA32 ABI
	ELFOSABI_SOLARIS    OSABI = 6   // Solaris
	ELFOSABI_AIX        OSABI = 7   // AIX
	ELFOSABI_IRIX       OSABI = 8   // IRIX
	ELFOSABI_FREEBSD    OSABI = 9   // FreeBSD
	ELFOSABI_TRU64      OSABI = 10  // TRU64 UNIX
	ELFOSABI_MODESTO    OSABI = 11  // Novell Modesto
	ELFOSABI_OPENBSD    OSABI = 12  // OpenBSD
	ELFOSABI_OPENVMS    OSABI = 13  // Open VMS
	ELFOSABI_NSK        OSABI = 14  // HP Non-Stop Kernel
	ELFOSABI_AROS       OSABI = 15  // Amiga Research OS
	ELFOSABI_FENIXOS    OSABI = 16  // The FenixOS highly scalable multi-core OS
	ELFOSABI_CLOUDABI   OSABI = 17  // Nuxi CloudABI
	ELFOSABI_ARM        OSABI = 97  // ARM
	ELFOSABI_STANDALONE OSABI = 255 // Standalone (embedded) application
)

var osABIStrings = []flagName{
	{0, "ELFOSABI_NONE"},
	{1, "ELFOSABI_HPUX"},
	{2, "ELFOSABI_NETBSD"},
	{3, "ELFOSABI_LINUX"},
	{4, "ELFOSABI_HURD"},
	{5, "ELFOSABI_86OPEN"},
	{6, "ELFOSABI_SOLARIS"},
	{7, "ELFOSABI_AIX"},
	{8, "ELFOSABI_IRIX"},
	{9, "ELFOSABI_FREEBSD"},
	{10, "ELFOSABI_TRU64"},
	{11, "ELFOSABI_MODESTO"},
	{12, "ELFOSABI_OPENBSD"},
	{13, "ELFOSABI_OPENVMS"},
	{14, "ELFOSABI_NSK"},
	{15, "ELFOSABI_AROS"},
	{16, "ELFOSABI_FENIXOS"},
	{17, "ELFOSABI_CLOUDABI"},
	{97, "ELFOSABI_ARM"},
	{255, "ELFOSABI_STANDALONE"},
}

func (o OSABI) String() string   { return stringify(uint32(o), osABIStrings, false) }
func (o OSABI) GoString() string { return stringify(uint32(o), osABIStrings, true) }

// ABIVersion specifies the ELF ABI Version
// it indicates the specific version of the OS ABI that the binary targets.
type ABIVersion byte

const (
	ELFABIVersion_CURRENT = 0
)

// Type specifies the current binary type (Relocatable object file or Executable binary...)
type Type uint16

const (
	ET_NONE   Type = 0      // Unknown type.
	ET_REL    Type = 1      // Relocatable.
	ET_EXEC   Type = 2      // Executable.
	ET_DYN    Type = 3      // Shared object.
	ET_CORE   Type = 4      // Core file.
	ET_LOOS   Type = 0xfe00 // First operating system specific.
	ET_HIOS   Type = 0xfeff // Last operating system-specific.
	ET_LOPROC Type = 0xff00 // First processor-specific.
	ET_HIPROC Type = 0xffff // Last processor-specific.
)

var typeStrings = []flagName{
	{0, "ET_NONE"},
	{1, "ET_REL"},
	{2, "ET_EXEC"},
	{3, "ET_DYN"},
	{4, "ET_CORE"},
	{0xfe00, "ET_LOOS"},
	{0xfeff, "ET_HIOS"},
	{0xff00, "ET_LOPROC"},
	{0xffff, "ET_HIPROC"},
}

func (t Type) String() string   { return stringify(uint32(t), typeStrings, false) }
func (t Type) GoString() string { return stringify(uint32(t), typeStrings, true) }

type Machine uint16

const (
	EM_NONE          Machine = 0   // Unknown machine.
	EM_M32           Machine = 1   // AT&T WE32100.
	EM_SPARC         Machine = 2   // Sun SPARC.
	EM_386           Machine = 3   // Intel i386.
	EM_68K           Machine = 4   // Motorola 68000.
	EM_88K           Machine = 5   // Motorola 88000.
	EM_860           Machine = 7   // Intel i860.
	EM_MIPS          Machine = 8   // MIPS R3000 Big-Endian only.
	EM_S370          Machine = 9   // IBM System/370.
	EM_MIPS_RS3_LE   Machine = 10  // MIPS R3000 Little-Endian.
	EM_PARISC        Machine = 15  // HP PA-RISC.
	EM_VPP500        Machine = 17  // Fujitsu VPP500.
	EM_SPARC32PLUS   Machine = 18  // SPARC v8plus.
	EM_960           Machine = 19  // Intel 80960.
	EM_PPC           Machine = 20  // PowerPC 32-bit.
	EM_PPC64         Machine = 21  // PowerPC 64-bit.
	EM_S390          Machine = 22  // IBM System/390.
	EM_V800          Machine = 36  // NEC V800.
	EM_FR20          Machine = 37  // Fujitsu FR20.
	EM_RH32          Machine = 38  // TRW RH-32.
	EM_RCE           Machine = 39  // Motorola RCE.
	EM_ARM           Machine = 40  // ARM.
	EM_SH            Machine = 42  // Hitachi SH.
	EM_SPARCV9       Machine = 43  // SPARC v9 64-bit.
	EM_TRICORE       Machine = 44  // Siemens TriCore embedded processor.
	EM_ARC           Machine = 45  // Argonaut RISC Core.
	EM_H8_300        Machine = 46  // Hitachi H8/300.
	EM_H8_300H       Machine = 47  // Hitachi H8/300H.
	EM_H8S           Machine = 48  // Hitachi H8S.
	EM_H8_500        Machine = 49  // Hitachi H8/500.
	EM_IA_64         Machine = 50  // Intel IA-64 Processor.
	EM_MIPS_X        Machine = 51  // Stanford MIPS-X.
	EM_COLDFIRE      Machine = 52  // Motorola ColdFire.
	EM_68HC12        Machine = 53  // Motorola M68HC12.
	EM_MMA           Machine = 54  // Fujitsu MMA.
	EM_PCP           Machine = 55  // Siemens PCP.
	EM_NCPU          Machine = 56  // Sony nCPU.
	EM_NDR1          Machine = 57  // Denso NDR1 microprocessor.
	EM_STARCORE      Machine = 58  // Motorola Star*Core processor.
	EM_ME16          Machine = 59  // Toyota ME16 processor.
	EM_ST100         Machine = 60  // STMicroelectronics ST100 processor.
	EM_TINYJ         Machine = 61  // Advanced Logic Corp. TinyJ processor.
	EM_X86_64        Machine = 62  // Advanced Micro Devices x86-64
	EM_PDSP          Machine = 63  // Sony DSP Processor
	EM_PDP10         Machine = 64  // Digital Equipment Corp. PDP-10
	EM_PDP11         Machine = 65  // Digital Equipment Corp. PDP-11
	EM_FX66          Machine = 66  // Siemens FX66 microcontroller
	EM_ST9PLUS       Machine = 67  // STMicroelectronics ST9+ 8/16 bit microcontroller
	EM_ST7           Machine = 68  // STMicroelectronics ST7 8-bit microcontroller
	EM_68HC16        Machine = 69  // Motorola MC68HC16 Microcontroller
	EM_68HC11        Machine = 70  // Motorola MC68HC11 Microcontroller
	EM_68HC08        Machine = 71  // Motorola MC68HC08 Microcontroller
	EM_68HC05        Machine = 72  // Motorola MC68HC05 Microcontroller
	EM_SVX           Machine = 73  // Silicon Graphics SVx
	EM_ST19          Machine = 74  // STMicroelectronics ST19 8-bit microcontroller
	EM_VAX           Machine = 75  // Digital VAX
	EM_CRIS          Machine = 76  // Axis Communications 32-bit embedded processor
	EM_JAVELIN       Machine = 77  // Infineon Technologies 32-bit embedded processor
	EM_FIREPATH      Machine = 78  // Element 14 64-bit DSP Processor
	EM_ZSP           Machine = 79  // LSI Logic 16-bit DSP Processor
	EM_MMIX          Machine = 80  // Donald Knuth's educational 64-bit processor
	EM_HUANY         Machine = 81  // Harvard University machine-independent object files
	EM_PRISM         Machine = 82  // SiTera Prism
	EM_AVR           Machine = 83  // Atmel AVR 8-bit microcontroller
	EM_FR30          Machine = 84  // Fujitsu FR30
	EM_D10V          Machine = 85  // Mitsubishi D10V
	EM_D30V          Machine = 86  // Mitsubishi D30V
	EM_V850          Machine = 87  // NEC v850
	EM_M32R          Machine = 88  // Mitsubishi M32R
	EM_MN10300       Machine = 89  // Matsushita MN10300
	EM_MN10200       Machine = 90  // Matsushita MN10200
	EM_PJ            Machine = 91  // picoJava
	EM_OPENRISC      Machine = 92  // OpenRISC 32-bit embedded processor
	EM_ARC_COMPACT   Machine = 93  // ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
	EM_XTENSA        Machine = 94  // Tensilica Xtensa Architecture
	EM_VIDEOCORE     Machine = 95  // Alphamosaic VideoCore processor
	EM_TMM_GPP       Machine = 96  // Thompson Multimedia General Purpose Processor
	EM_NS32K         Machine = 97  // National Semiconductor 32000 series
	EM_TPC           Machine = 98  // Tenor Network TPC processor
	EM_SNP1K         Machine = 99  // Trebia SNP 1000 processor
	EM_ST200         Machine = 100 // STMicroelectronics (www.st.com) ST200 microcontroller
	EM_IP2K          Machine = 101 // Ubicom IP2xxx microcontroller family
	EM_MAX           Machine = 102 // MAX Processor
	EM_CR            Machine = 103 // National Semiconductor CompactRISC microprocessor
	EM_F2MC16        Machine = 104 // Fujitsu F2MC16
	EM_MSP430        Machine = 105 // Texas Instruments embedded microcontroller msp430
	EM_BLACKFIN      Machine = 106 // Analog Devices Blackfin (DSP) processor
	EM_SE_C33        Machine = 107 // S1C33 Family of Seiko Epson processors
	EM_SEP           Machine = 108 // Sharp embedded microprocessor
	EM_ARCA          Machine = 109 // Arca RISC Microprocessor
	EM_UNICORE       Machine = 110 // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
	EM_EXCESS        Machine = 111 // eXcess: 16/32/64-bit configurable embedded CPU
	EM_DXP           Machine = 112 // Icera Semiconductor Inc. Deep Execution Processor
	EM_ALTERA_NIOS2  Machine = 113 // Altera Nios II soft-core processor
	EM_CRX           Machine = 114 // National Semiconductor CompactRISC CRX microprocessor
	EM_XGATE         Machine = 115 // Motorola XGATE embedded processor
	EM_C166          Machine = 116 // Infineon C16x/XC16x processor
	EM_M16C          Machine = 117 // Renesas M16C series microprocessors
	EM_DSPIC30F      Machine = 118 // Microchip Technology dsPIC30F Digital Signal Controller
	EM_CE            Machine = 119 // Freescale Communication Engine RISC core
	EM_M32C          Machine = 120 // Renesas M32C series microprocessors
	EM_TSK3000       Machine = 131 // Altium TSK3000 core
	EM_RS08          Machine = 132 // Freescale RS08 embedded processor
	EM_SHARC         Machine = 133 // Analog Devices SHARC family of 32-bit DSP processors
	EM_ECOG2         Machine = 134 // Cyan Technology eCOG2 microprocessor
	EM_SCORE7        Machine = 135 // Sunplus S+core7 RISC processor
	EM_DSP24         Machine = 136 // New Japan Radio (NJR) 24-bit DSP Processor
	EM_VIDEOCORE3    Machine = 137 // Broadcom VideoCore III processor
	EM_LATTICEMICO32 Machine = 138 // RISC processor for Lattice FPGA architecture
	EM_SE_C17        Machine = 139 // Seiko Epson C17 family
	EM_TI_C6000      Machine = 140 // The Texas Instruments TMS320C6000 DSP family
	EM_TI_C2000      Machine = 141 // The Texas Instruments TMS320C2000 DSP family
	EM_TI_C5500      Machine = 142 // The Texas Instruments TMS320C55x DSP family
	EM_TI_ARP32      Machine = 143 // Texas Instruments Application Specific RISC Processor, 32bit fetch
	EM_TI_PRU        Machine = 144 // Texas Instruments Programmable Realtime Unit
	EM_MMDSP_PLUS    Machine = 160 // STMicroelectronics 64bit VLIW Data Signal Processor
	EM_CYPRESS_M8C   Machine = 161 // Cypress M8C microprocessor
	EM_R32C          Machine = 162 // Renesas R32C series microprocessors
	EM_TRIMEDIA      Machine = 163 // NXP Semiconductors TriMedia architecture family
	EM_QDSP6         Machine = 164 // QUALCOMM DSP6 Processor
	EM_8051          Machine = 165 // Intel 8051 and variants
	EM_STXP7X        Machine = 166 // STMicroelectronics STxP7x family of configurable and extensible RISC processors
	EM_NDS32         Machine = 167 // Andes Technology compact code size embedded RISC processor family
	EM_ECOG1         Machine = 168 // Cyan Technology eCOG1X family
	EM_ECOG1X        Machine = 168 // Cyan Technology eCOG1X family
	EM_MAXQ30        Machine = 169 // Dallas Semiconductor MAXQ30 Core Micro-controllers
	EM_XIMO16        Machine = 170 // New Japan Radio (NJR) 16-bit DSP Processor
	EM_MANIK         Machine = 171 // M2000 Reconfigurable RISC Microprocessor
	EM_CRAYNV2       Machine = 172 // Cray Inc. NV2 vector architecture
	EM_RX            Machine = 173 // Renesas RX family
	EM_METAG         Machine = 174 // Imagination Technologies META processor architecture
	EM_MCST_ELBRUS   Machine = 175 // MCST Elbrus general purpose hardware architecture
	EM_ECOG16        Machine = 176 // Cyan Technology eCOG16 family
	EM_CR16          Machine = 177 // National Semiconductor CompactRISC CR16 16-bit microprocessor
	EM_ETPU          Machine = 178 // Freescale Extended Time Processing Unit
	EM_SLE9X         Machine = 179 // Infineon Technologies SLE9X core
	EM_L10M          Machine = 180 // Intel L10M
	EM_K10M          Machine = 181 // Intel K10M
	EM_AARCH64       Machine = 183 // ARM 64-bit Architecture (AArch64)
	EM_AVR32         Machine = 185 // Atmel Corporation 32-bit microprocessor family
	EM_STM8          Machine = 186 // STMicroeletronics STM8 8-bit microcontroller
	EM_TILE64        Machine = 187 // Tilera TILE64 multicore architecture family
	EM_TILEPRO       Machine = 188 // Tilera TILEPro multicore architecture family
	EM_MICROBLAZE    Machine = 189 // Xilinx MicroBlaze 32-bit RISC soft processor core
	EM_CUDA          Machine = 190 // NVIDIA CUDA architecture
	EM_TILEGX        Machine = 191 // Tilera TILE-Gx multicore architecture family
	EM_CLOUDSHIELD   Machine = 192 // CloudShield architecture family
	EM_COREA_1ST     Machine = 193 // KIPO-KAIST Core-A 1st generation processor family
	EM_COREA_2ND     Machine = 194 // KIPO-KAIST Core-A 2nd generation processor family
	EM_ARC_COMPACT2  Machine = 195 // Synopsys ARCompact V2
	EM_OPEN8         Machine = 196 // Open8 8-bit RISC soft processor core
	EM_RL78          Machine = 197 // Renesas RL78 family
	EM_VIDEOCORE5    Machine = 198 // Broadcom VideoCore V processor
	EM_78KOR         Machine = 199 // Renesas 78KOR family
	EM_56800EX       Machine = 200 // Freescale 56800EX Digital Signal Controller (DSC)
	EM_BA1           Machine = 201 // Beyond BA1 CPU architecture
	EM_BA2           Machine = 202 // Beyond BA2 CPU architecture
	EM_XCORE         Machine = 203 // XMOS xCORE processor family
	EM_MCHP_PIC      Machine = 204 // Microchip 8-bit PIC(r) family
	EM_INTEL205      Machine = 205 // Reserved by Intel
	EM_INTEL206      Machine = 206 // Reserved by Intel
	EM_INTEL207      Machine = 207 // Reserved by Intel
	EM_INTEL208      Machine = 208 // Reserved by Intel
	EM_INTEL209      Machine = 209 // Reserved by Intel
	EM_KM32          Machine = 210 // KM211 KM32 32-bit processor
	EM_KMX32         Machine = 211 // KM211 KMX32 32-bit processor
	EM_KMX16         Machine = 212 // KM211 KMX16 16-bit processor
	EM_KMX8          Machine = 213 // KM211 KMX8 8-bit processor
	EM_KVARC         Machine = 214 // KM211 KVARC processor
	EM_CDP           Machine = 215 // Paneve CDP architecture family
	EM_COGE          Machine = 216 // Cognitive Smart Memory Processor
	EM_COOL          Machine = 217 // Bluechip Systems CoolEngine
	EM_NORC          Machine = 218 // Nanoradio Optimized RISC
	EM_CSR_KALIMBA   Machine = 219 // CSR Kalimba architecture family
	EM_Z80           Machine = 220 // Zilog Z80
	EM_VISIUM        Machine = 221 // Controls and Data Services VISIUMcore processor
	EM_FT32          Machine = 222 // FTDI Chip FT32 high performance 32-bit RISC architecture
	EM_MOXIE         Machine = 223 // Moxie processor family
	EM_AMDGPU        Machine = 224 // AMD GPU architecture
	EM_RISCV         Machine = 243 // RISC-V
	EM_LANAI         Machine = 244 // Lanai 32-bit processor
	EM_BPF           Machine = 247 // Linux BPF – in-kernel virtual machine

	// Non-standard or deprecated.
	EM_486         Machine = 6      // Intel i486.
	EM_MIPS_RS4_BE Machine = 10     // MIPS R4000 Big-Endian
	EM_ALPHA_STD   Machine = 41     // Digital Alpha (standard value).
	EM_ALPHA       Machine = 0x9026 // Alpha (written in the absence of an ABI)
)

var machineStrings = []flagName{
	{0, "EM_NONE"},
	{1, "EM_M32"},
	{2, "EM_SPARC"},
	{3, "EM_386"},
	{4, "EM_68K"},
	{5, "EM_88K"},
	{7, "EM_860"},
	{8, "EM_MIPS"},
	{9, "EM_S370"},
	{10, "EM_MIPS_RS3_LE"},
	{15, "EM_PARISC"},
	{17, "EM_VPP500"},
	{18, "EM_SPARC32PLUS"},
	{19, "EM_960"},
	{20, "EM_PPC"},
	{21, "EM_PPC64"},
	{22, "EM_S390"},
	{36, "EM_V800"},
	{37, "EM_FR20"},
	{38, "EM_RH32"},
	{39, "EM_RCE"},
	{40, "EM_ARM"},
	{42, "EM_SH"},
	{43, "EM_SPARCV9"},
	{44, "EM_TRICORE"},
	{45, "EM_ARC"},
	{46, "EM_H8_300"},
	{47, "EM_H8_300H"},
	{48, "EM_H8S"},
	{49, "EM_H8_500"},
	{50, "EM_IA_64"},
	{51, "EM_MIPS_X"},
	{52, "EM_COLDFIRE"},
	{53, "EM_68HC12"},
	{54, "EM_MMA"},
	{55, "EM_PCP"},
	{56, "EM_NCPU"},
	{57, "EM_NDR1"},
	{58, "EM_STARCORE"},
	{59, "EM_ME16"},
	{60, "EM_ST100"},
	{61, "EM_TINYJ"},
	{62, "EM_X86_64"},
	{63, "EM_PDSP"},
	{64, "EM_PDP10"},
	{65, "EM_PDP11"},
	{66, "EM_FX66"},
	{67, "EM_ST9PLUS"},
	{68, "EM_ST7"},
	{69, "EM_68HC16"},
	{70, "EM_68HC11"},
	{71, "EM_68HC08"},
	{72, "EM_68HC05"},
	{73, "EM_SVX"},
	{74, "EM_ST19"},
	{75, "EM_VAX"},
	{76, "EM_CRIS"},
	{77, "EM_JAVELIN"},
	{78, "EM_FIREPATH"},
	{79, "EM_ZSP"},
	{80, "EM_MMIX"},
	{81, "EM_HUANY"},
	{82, "EM_PRISM"},
	{83, "EM_AVR"},
	{84, "EM_FR30"},
	{85, "EM_D10V"},
	{86, "EM_D30V"},
	{87, "EM_V850"},
	{88, "EM_M32R"},
	{89, "EM_MN10300"},
	{90, "EM_MN10200"},
	{91, "EM_PJ"},
	{92, "EM_OPENRISC"},
	{93, "EM_ARC_COMPACT"},
	{94, "EM_XTENSA"},
	{95, "EM_VIDEOCORE"},
	{96, "EM_TMM_GPP"},
	{97, "EM_NS32K"},
	{98, "EM_TPC"},
	{99, "EM_SNP1K"},
	{100, "EM_ST200"},
	{101, "EM_IP2K"},
	{102, "EM_MAX"},
	{103, "EM_CR"},
	{104, "EM_F2MC16"},
	{105, "EM_MSP430"},
	{106, "EM_BLACKFIN"},
	{107, "EM_SE_C33"},
	{108, "EM_SEP"},
	{109, "EM_ARCA"},
	{110, "EM_UNICORE"},
	{111, "EM_EXCESS"},
	{112, "EM_DXP"},
	{113, "EM_ALTERA_NIOS2"},
	{114, "EM_CRX"},
	{115, "EM_XGATE"},
	{116, "EM_C166"},
	{117, "EM_M16C"},
	{118, "EM_DSPIC30F"},
	{119, "EM_CE"},
	{120, "EM_M32C"},
	{131, "EM_TSK3000"},
	{132, "EM_RS08"},
	{133, "EM_SHARC"},
	{134, "EM_ECOG2"},
	{135, "EM_SCORE7"},
	{136, "EM_DSP24"},
	{137, "EM_VIDEOCORE3"},
	{138, "EM_LATTICEMICO32"},
	{139, "EM_SE_C17"},
	{140, "EM_TI_C6000"},
	{141, "EM_TI_C2000"},
	{142, "EM_TI_C5500"},
	{143, "EM_TI_ARP32"},
	{144, "EM_TI_PRU"},
	{160, "EM_MMDSP_PLUS"},
	{161, "EM_CYPRESS_M8C"},
	{162, "EM_R32C"},
	{163, "EM_TRIMEDIA"},
	{164, "EM_QDSP6"},
	{165, "EM_8051"},
	{166, "EM_STXP7X"},
	{167, "EM_NDS32"},
	{168, "EM_ECOG1"},
	{168, "EM_ECOG1X"},
	{169, "EM_MAXQ30"},
	{170, "EM_XIMO16"},
	{171, "EM_MANIK"},
	{172, "EM_CRAYNV2"},
	{173, "EM_RX"},
	{174, "EM_METAG"},
	{175, "EM_MCST_ELBRUS"},
	{176, "EM_ECOG16"},
	{177, "EM_CR16"},
	{178, "EM_ETPU"},
	{179, "EM_SLE9X"},
	{180, "EM_L10M"},
	{181, "EM_K10M"},
	{183, "EM_AARCH64"},
	{185, "EM_AVR32"},
	{186, "EM_STM8"},
	{187, "EM_TILE64"},
	{188, "EM_TILEPRO"},
	{189, "EM_MICROBLAZE"},
	{190, "EM_CUDA"},
	{191, "EM_TILEGX"},
	{192, "EM_CLOUDSHIELD"},
	{193, "EM_COREA_1ST"},
	{194, "EM_COREA_2ND"},
	{195, "EM_ARC_COMPACT2"},
	{196, "EM_OPEN8"},
	{197, "EM_RL78"},
	{198, "EM_VIDEOCORE5"},
	{199, "EM_78KOR"},
	{200, "EM_56800EX"},
	{201, "EM_BA1"},
	{202, "EM_BA2"},
	{203, "EM_XCORE"},
	{204, "EM_MCHP_PIC"},
	{205, "EM_INTEL205"},
	{206, "EM_INTEL206"},
	{207, "EM_INTEL207"},
	{208, "EM_INTEL208"},
	{209, "EM_INTEL209"},
	{210, "EM_KM32"},
	{211, "EM_KMX32"},
	{212, "EM_KMX16"},
	{213, "EM_KMX8"},
	{214, "EM_KVARC"},
	{215, "EM_CDP"},
	{216, "EM_COGE"},
	{217, "EM_COOL"},
	{218, "EM_NORC"},
	{219, "EM_CSR_KALIMBA "},
	{220, "EM_Z80 "},
	{221, "EM_VISIUM "},
	{222, "EM_FT32 "},
	{223, "EM_MOXIE"},
	{224, "EM_AMDGPU"},
	{243, "EM_RISCV"},
	{244, "EM_LANAI"},
	{247, "EM_BPF"},
	/* Non-standard or deprecated. */
	{6, "EM_486"},
	{10, "EM_MIPS_RS4_BE"},
	{41, "EM_ALPHA_STD"},
	{0x9026, "EM_ALPHA"},
}

func (m Machine) String() string   { return stringify(uint32(m), machineStrings, false) }
func (m Machine) GoString() string { return stringify(uint32(m), machineStrings, true) }

// Special section indices.
type SectionIndex int

const (
	SHN_UNDEF     SectionIndex = 0      // Undefined, missing, irrelevant.
	SHN_LORESERVE SectionIndex = 0xff00 // First of reserved range.
	SHN_LOPROC    SectionIndex = 0xff00 // First processor-specific.
	SHN_HIPROC    SectionIndex = 0xff1f // Last processor-specific.
	SHN_LOOS      SectionIndex = 0xff20 // First operating system-specific.
	SHN_HIOS      SectionIndex = 0xff3f // Last operating system-specific.
	SHN_ABS       SectionIndex = 0xfff1 // Absolute values.
	SHN_COMMON    SectionIndex = 0xfff2 // Common data.
	SHN_XINDEX    SectionIndex = 0xffff // Escape; index stored elsewhere.
	SHN_HIRESERVE SectionIndex = 0xffff // Last of reserved range.
)

// Section type.
type SectionType uint32

const (
	SHT_NULL           SectionType = 0          // inactive
	SHT_PROGBITS       SectionType = 1          // program defined information
	SHT_SYMTAB         SectionType = 2          // symbol table section
	SHT_STRTAB         SectionType = 3          // string table section
	SHT_RELA           SectionType = 4          // relocation section with addends
	SHT_HASH           SectionType = 5          // symbol hash table section
	SHT_DYNAMIC        SectionType = 6          // dynamic section
	SHT_NOTE           SectionType = 7          // note section
	SHT_NOBITS         SectionType = 8          // no space section
	SHT_REL            SectionType = 9          // relocation section - no addends
	SHT_SHLIB          SectionType = 10         // reserved - purpose unknown
	SHT_DYNSYM         SectionType = 11         // dynamic symbol table section
	SHT_INIT_ARRAY     SectionType = 14         // Initialization function pointers.
	SHT_FINI_ARRAY     SectionType = 15         // Termination function pointers.
	SHT_PREINIT_ARRAY  SectionType = 16         // Pre-initialization function ptrs.
	SHT_GROUP          SectionType = 17         // Section group.
	SHT_SYMTAB_SHNDX   SectionType = 18         // Section indexes (see SHN_XINDEX).
	SHT_LOOS           SectionType = 0x60000000 // First of OS specific semantics
	SHT_GNU_ATTRIBUTES SectionType = 0x6ffffff5 // GNU object attributes
	SHT_GNU_HASH       SectionType = 0x6ffffff6 // GNU hash table
	SHT_GNU_LIBLIST    SectionType = 0x6ffffff7 // GNU prelink library list
	SHT_GNU_VERDEF     SectionType = 0x6ffffffd // GNU version definition section
	SHT_GNU_VERNEED    SectionType = 0x6ffffffe // GNU version needs section
	SHT_GNU_VERSYM     SectionType = 0x6fffffff // GNU version symbol table
	SHT_HIOS           SectionType = 0x6fffffff // Last of OS specific semantics
	SHT_LOPROC         SectionType = 0x70000000 // reserved range for processor
	SHT_HIPROC         SectionType = 0x7fffffff // specific section header types
	SHT_LOUSER         SectionType = 0x80000000 // reserved range for application
	SHT_HIUSER         SectionType = 0xffffffff // specific indexes
)

// Section flags.
type SectionFlag uint32

const (
	SHF_NONE             SectionFlag = 0x0        // Undefined section flag
	SHF_WRITE            SectionFlag = 0x1        // Section contains writable data.
	SHF_ALLOC            SectionFlag = 0x2        // Section occupies memory.
	SHF_EXECINSTR        SectionFlag = 0x4        // Section contains instructions.
	SHF_MERGE            SectionFlag = 0x10       // Section may be merged.
	SHF_STRINGS          SectionFlag = 0x20       // Section contains strings.
	SHF_INFO_LINK        SectionFlag = 0x40       // sh_info holds section index.
	SHF_LINK_ORDER       SectionFlag = 0x80       // Special ordering requirements.
	SHF_OS_NONCONFORMING SectionFlag = 0x100      // OS-specific processing required.
	SHF_GROUP            SectionFlag = 0x200      // Member of section group.
	SHF_TLS              SectionFlag = 0x400      // Section contains TLS data.
	SHF_COMPRESSED       SectionFlag = 0x800      // Section is compressed.
	SHF_MASKOS           SectionFlag = 0x0ff00000 // OS-specific semantics.
	SHF_MASKPROC         SectionFlag = 0xf0000000 // Processor-specific semantics.
)

// Section compression type.
type CompressionType int

const (
	COMPRESS_ZLIB   CompressionType = 1          // ZLIB compression.
	COMPRESS_LOOS   CompressionType = 0x60000000 // First OS-specific.
	COMPRESS_HIOS   CompressionType = 0x6fffffff // Last OS-specific.
	COMPRESS_LOPROC CompressionType = 0x70000000 // First processor-specific type.
	COMPRESS_HIPROC CompressionType = 0x7fffffff // Last processor-specific type.
)

// Prog.Type
type ProgType int

const (
	PT_NULL              ProgType = 0          // Unused entry.
	PT_LOAD              ProgType = 1          // Loadable segment.
	PT_DYNAMIC           ProgType = 2          // Dynamic linking information segment.
	PT_INTERP            ProgType = 3          // Pathname of interpreter.
	PT_NOTE              ProgType = 4          // Auxiliary information.
	PT_SHLIB             ProgType = 5          // Reserved (not used).
	PT_PHDR              ProgType = 6          // Location of program header itself.
	PT_TLS               ProgType = 7          // Thread local storage segment
	PT_LOOS              ProgType = 0x60000000 // First OS-specific.
	PT_GNU_EH_FRAME      ProgType = 0x6474e550 // Frame unwind information
	PT_GNU_STACK         ProgType = 0x6474e551 // Stack flags
	PT_GNU_RELRO         ProgType = 0x6474e552 // Read only after relocs
	PT_GNU_PROPERTY      ProgType = 0x6474e553 // GNU property
	PT_GNU_MBIND_LO      ProgType = 0x6474e555 // Mbind segments start
	PT_GNU_MBIND_HI      ProgType = 0x6474f554 // Mbind segments finish
	PT_PAX_FLAGS         ProgType = 0x65041580 // PAX flags
	PT_OPENBSD_RANDOMIZE ProgType = 0x65a3dbe6 // Random data
	PT_OPENBSD_WXNEEDED  ProgType = 0x65a3dbe7 // W^X violations
	PT_OPENBSD_BOOTDATA  ProgType = 0x65a41be6 // Boot arguments
	PT_SUNW_EH_FRAME     ProgType = 0x6474e550 // Frame unwind information
	PT_SUNWSTACK         ProgType = 0x6ffffffb // Stack segment
	PT_HIOS              ProgType = 0x6fffffff // Last OS-specific.
	PT_LOPROC            ProgType = 0x70000000 // First processor-specific type.
	PT_ARM_ARCHEXT       ProgType = 0x70000000 // Architecture compatibility
	PT_ARM_EXIDX         ProgType = 0x70000001 // Exception unwind tables
	PT_AARCH64_ARCHEXT   ProgType = 0x70000000 // Architecture compatibility
	PT_AARCH64_UNWIND    ProgType = 0x70000001 // Exception unwind tables
	PT_MIPS_REGINFO      ProgType = 0x70000000 // Register usage
	PT_MIPS_RTPROC       ProgType = 0x70000001 // Runtime procedures
	PT_MIPS_OPTIONS      ProgType = 0x70000002 // Options
	PT_MIPS_ABIFLAGS     ProgType = 0x70000003 // ABI flags
	PT_S390_PGSTE        ProgType = 0x70000000 // 4k page table size
	PT_HIPROC            ProgType = 0x7fffffff // Last processor-specific type.
)

// Prog.Flag
type ProgFlag uint32

const (
	PF_X        ProgFlag = 0x1        // Executable.
	PF_W        ProgFlag = 0x2        // Writable.
	PF_R        ProgFlag = 0x4        // Readable.
	PF_MASKOS   ProgFlag = 0x0ff00000 // Operating system-specific.
	PF_MASKPROC ProgFlag = 0xf0000000 // Processor-specific.
)

// IsValidELFClass validates the ELF class of the binary.
func IsValidELFClass(c Class) bool {
	switch c {
	case ELFCLASS32:
		return true
	case ELFCLASS64:
		return true
	default:
		return false
	}
}

// IsValidByteOrder validates the ELF byte order field.
func IsValidByteOrder(b Data) bool {
	switch b {
	case ELFDATA2LSB:
		return true
	case ELFDATA2MSB:
		return true
	default:
		return false
	}
}

// IsValidVersion validates against the current default version flag EV_CURRENT.
func IsValidVersion(b Version) bool {
	return b == EV_CURRENT
}

// goByteOrder encodes a Data field to a native Go byte order field.
func ByteOrder(b Data) binary.ByteOrder {
	switch b {
	case ELFDATA2LSB:
		return binary.LittleEndian
	case ELFDATA2MSB:
		return binary.BigEndian
	default:
		return binary.LittleEndian
	}
}
