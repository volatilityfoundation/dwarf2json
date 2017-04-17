`dwarf2json` is a Go utility that takes ELF files with DWARF as input and
generates [Volatilty3](https://github.com/volatilityfoundation/volatility3)
Intermediate Symbol File (ISF) JSON output.

To build (Go required):
```
  $ GOPATH=`pwd`/go go install dwarf2json
```

To run:
```
  $ go/bin/dwarf2json input_ELF_file > output_JSON_file
```
