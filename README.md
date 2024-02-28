# Introduction

`dwarf2json` is a Go utility that processes files containing symbol and type
information to generate [Volatility3](https://github.com/volatilityfoundation/volatility3)
Intermediate Symbol File (ISF) JSON output suitable for Linux and macOS
analysis.

[![build](https://github.com/volatilityfoundation/dwarf2json/workflows/build/badge.svg)](https://github.com/volatilityfoundation/dwarf2json/actions?query=workflow%3Abuild)

To build (Go 1.18+ required):
```
  $ go build
```

To run:
```
  $ ./dwarf2json --help
  Usage: ./dwarf2json COMMAND

  A tool for generating intermediate symbol file (ISF)

  Commands:
    linux  generate ISF for Linux analysis
    mac    generate ISF for macOS analysis
```

Note: processing large DWARF files requires a minimum of 8GB RAM.

# Linux Processing
`dwarf2json` supports processing DWARF and symbol table information from ELF
files and symbols from System.map input files to produce ISF for
Linux analysis.

The user is able to select whether to include symbol, type, or both for each
input file.

```
  $ ./dwarf2json linux --help
  Usage: dwarf2json linux [OPTIONS]

      --elf PATH                    ELF file PATH to extract symbol and type information
      --elf-symbols PATH            ELF file PATH to extract only symbol information
      --elf-types PATH              ELF file PATH to extract only type information
      --linux-banner linux_banner   Linux banner value matching linux_banner symbol
      --reference-symbols PATH      ISF reference file PATH with symbol types
      --system-map PATH             System.Map file PATH to extract symbol information
```

For example, to include symbols and types for a given Linux kernel DWARF
file can be done with:
```
  $ ./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-4.4.0-137-generic > output.json
```

Symbol offsets for symbols extracted from symbol table information take
precedence over those extracted from DWARF information. Thus, symbols extracted
from files specified with `--elf-symbols` flag take precedence over symbols
extracted from files specified with `--elf`. Symbol offsets for symbols from
`System.Map`, specified with `--system-map` flag, are the highest precedence. If
there is a conflict between the different symbol information sources, the
offset from `System.Map` will be used.

Providing multiple input files for a given flag is allowed. For example,
`./dwarf2json --elf file1 --elf file2 ...` would process both `file1` and
`file2`. When conflicting symbol or type information is encountered, the data
from the last file specified in the command invocation would take precedence.

## Generating ISF without debug information

In situations when debug information for a given kernel is not available,
`dwarf2json` supports generating an ISF file using the following process:

1. Create a `module.ko` using [Makefile](linux_build_module/Makefile) on the
   system that has the matching kernel. `dwarf2json` uses `module.ko` to \
   extract types matching the target kernel.
2. Collect `Symbols.map` for the target kernel. `dwarf2json` uses `System.map`
   to populate symbol names and addresses (but no types) of the symbols in the
   target kernel.
3. Obtain the `linux_banner` value (e.g., `/proc/version`). `dwarf2json` adds
   `linux_banner` value to the ISF file to enable matching the ISF to the image
   being analyzed.
4. Obtain an ISF file that was created from debug information that will be used
   as a reference. An ISF for a kernel version matching or close to the target
   kernel version would work best. `dwarf2json` uses reference ISF to
   populate the symbol types for the symbols found in `Symbols.map`

The information in (1)-(4) is then provided to `dwarf2json`:

```
$ ./dwarf2json linux --elf-types /path/to/module.ko \
  --system-map /path/to/Syste.map \
  --linux-banner "<linux-banner-string>" \
  --reference-symbols /path/to/reference_symbols.json \
  > output.json
```

Note that `linux_banner` has spaces and needs to be quoted.

# MacOS Processing
`dwarf2json` supports processing DWARF and symbol table information from Mach-O
files to produce ISF for macOS analysis.

The user is able to select whether to include symbol, type, or both for each
input file.

```
  $ ./dwarf2json mac --help
  Usage: dwarf2json mac [OPTIONS]

        --arch NAME            architecture for universal FAT files. NAME is one of {i386|x86_64}
        --macho PATH           Mach-O file PATH to extract symbol and type information
        --macho-symbols PATH   Mach-O file PATH to extract only symbol information
        --macho-types PATH     Mach-O file PATH to extract only type information
```

For example, to include symbols and types for a given macOS kernel DWARF
file and symbols from a macOS kernel can be done with:
```
  $ ./dwarf2json mac --macho /path/kernel.dSYM/Contents/Resources/DWARF/kernel \
    --macho-symbols /path/kernel > output.json
```

Symbol offsets for symbols extracted from symbol table information take
precedence over those extracted from DWARF information. Thus, symbols extracted
from files specified with `--macho-symbols` flag take precedence over symbols
extracted from files specified with `--macho`.


Providing multiple input files for a given flag is allowed. For example,
`./dwarf2json --macho file1 --macho file2 ...` would process both `file1` and
`file2`. When conflicting symbol or type information is encountered, the data
from the last file specified in the command invocation would take precedence.

When processing Mach-O universal FAT binaries, the `--arch` flag needs to be
used to select the architecture for one of the embedded Mach-O files.

For example, generating ISF JSON file for i386 architecture of a OS X 10.7
kernel debug kit can be done with:

```
  $ ./dwarf2json mac --arch i386 \
  --macho mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel \
  --macho-symbols mach_kernel > mach_kernel.json
```
