// utility for converting DWARF in ELF to JSON

package main

import (
	"bytes"
	"crypto/sha1"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DW_OP_addr = 0x3
)

const (
	TOOL_NAME      = "dwarf2json"
	TOOL_VERSION   = "0.3.0"
	FORMAT_VERSION = "3.0.0"
)

type vtypeMetadata struct {
	Source   map[string]string `json:"source"`
	Producer map[string]string `json:"producer"`
	Format   string            `json:"format"`
}

type vtypeStructField struct {
	FieldType map[string]interface{} `json:"type"`
	Offset    int64                  `json:"offset"`
}

type vtypeStruct struct {
	Size   int64                       `json:"size"`
	Fields map[string]vtypeStructField `json:"fields"`
	Kind   string                      `json:"kind"`
}

type vtypeBaseType struct {
	Size   int64  `json:"size"`
	Signed bool   `json:"signed"`
	Kind   string `json:"kind"`
	Endian string `json:"endian"`
}

type vtypeEnum struct {
	Size      int64            `json:"size"`
	Base      string           `json:"base"`
	Constants map[string]int64 `json:"constants"`
}

type vtypeSymbol struct {
	SymbolType map[string]interface{} `json:"type"`
	Address    uint64                 `json:"address"`
}

type vtypeJson struct {
	Metadata  vtypeMetadata            `json:"metadata"`
	BaseTypes map[string]vtypeBaseType `json:"base_types"`
	UserTypes map[string]vtypeStruct   `json:"user_types"`
	Enums     map[string]vtypeEnum     `json:"enums"`
	Symbols   map[string]vtypeSymbol   `json:"symbols"`
}

// This is a very dumbed-down dwarf expression evaluator.
// For now we only support addresses...
func compute_dwarf_expr(buf []byte, addressSize int) (uint64, error) {
	if len(buf) < 5 {
		return 0, errors.New(fmt.Sprintf("Not enough data to compute expression (%d bytes)", len(buf)))
	}

	if buf[0] != DW_OP_addr {
		return 0, errors.New(fmt.Sprintf("Unsupported DWARF opcode 0x%x", buf[0]))
	}

	var retval uint64
	var err error
	reader := bytes.NewReader(buf[1:])
	if addressSize == 4 {
		var retval32 uint32

		err = binary.Read(reader, binary.LittleEndian, &retval32)
		retval = uint64(retval32)
	} else {
		err = binary.Read(reader, binary.LittleEndian, &retval)
	}

	if err != nil {
		return 0, err
	}

	return retval, nil
}

func uint64_of_location(loc *dwarf.Field, addressSize int) uint64 {
	result := uint64(0)

	switch loc.Class {
	default:
		// fmt.Printf("WARNING: unconverted location %v\n", loc.Class)
	case dwarf.ClassAddress:
		result = loc.Val.(uint64)
	case dwarf.ClassConstant:
		result = uint64(loc.Val.(int64))
	// case dwarf.ClassLocListPtr:
	//     fmt.Printf("loclistptr: 0x%x\n", loc.Val.(int64))
	case dwarf.ClassExprLoc:
		val, err := compute_dwarf_expr(loc.Val.([]byte), addressSize)
		if err == nil {
			result = val
		} else {
			// fmt.Printf("WARNING: failed to compute DWARF location expression: %v\n", err)
		}
	}

	return result
}

func struct_name(dwarfStruct *dwarf.StructType) string {
	if dwarfStruct.StructName != "" {
		return dwarfStruct.StructName
	}

	data := sha1.Sum([]byte(dwarfStruct.Defn()))
	return fmt.Sprintf("unnamed_%8x", data[0:8])
}

func enum_name(dwarfEnum *dwarf.EnumType) string {
	if dwarfEnum.EnumName != "" {
		return dwarfEnum.EnumName
	}

	data := sha1.Sum([]byte(dwarfEnum.String()))
	return fmt.Sprintf("unnamed_%8x", data[0:8])
}

func type_name(dwarfType dwarf.Type) map[string]interface{} {
	result := make(map[string]interface{}, 0)

	switch t := dwarfType.(type) {
	default:
		result["kind"] = "unknown"
	case *dwarf.StructType:
		result["kind"] = t.Kind
		result["name"] = struct_name(t)
	case *dwarf.ArrayType:
		result["kind"] = "array"
		if t.Count < 0 {
			result["count"] = 0
		} else {
			result["count"] = t.Count
		}
		result["subtype"] = type_name(t.Type)
	case *dwarf.PtrType:
		result["kind"] = "pointer"
		result["subtype"] = type_name(t.Type)
	case *dwarf.EnumType:
		result["kind"] = "enum"
		result["name"] = enum_name(t)
	case *dwarf.BoolType, *dwarf.CharType, *dwarf.ComplexType, *dwarf.IntType, *dwarf.FloatType, *dwarf.UcharType, *dwarf.UintType:
		result["kind"] = "base"
		result["name"] = t.Common().Name
	case *dwarf.TypedefType:
		result = type_name(t.Type)
	case *dwarf.QualType:
		result = type_name(t.Type)
	case *dwarf.VoidType:
		result["kind"] = "base"
		result["name"] = "void"
	case *dwarf.FuncType:
		result["kind"] = "function"
	}

	return result
}

func new_basetype(dwarfType dwarf.Type, endian string) vtypeBaseType {
	signed := true
	kind := "int"

	switch dwarfType.(type) {
	case *dwarf.UintType:
		signed = false
	case *dwarf.UcharType:
		signed = false
		kind = "char"
	case *dwarf.CharType:
		kind = "char"
	case *dwarf.BoolType:
		kind = "bool"
	case *dwarf.FloatType:
		kind = "float"
	}

	bt :=
		vtypeBaseType{
			Size:   dwarfType.Size(),
			Signed: signed,
			Kind:   kind,
			Endian: endian,
		}

	return bt
}

func metadata(fname string) vtypeMetadata {
	result :=
		vtypeMetadata{
			Source:   make(map[string]string),
			Producer: make(map[string]string),
			Format:   FORMAT_VERSION,
		}

	result.Source["type"] = "dwarf"
	result.Source["file"] = filepath.Base(fname)
	result.Producer["version"] = TOOL_VERSION
	result.Producer["name"] = TOOL_NAME

	return result
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <ELF>\n", TOOL_NAME)
		os.Exit(255)
	}

	elf_file, err := elf.Open(os.Args[1])
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(255)
	}
	defer elf_file.Close()

	var endian string
	if elf_file.ByteOrder == binary.LittleEndian {
		endian = "little"
	} else {
		endian = "big"
	}

	data, err := elf_file.DWARF()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(255)
	}

	// setup the output document
	doc := vtypeJson{
		Metadata:  metadata(os.Args[1]),
		BaseTypes: make(map[string]vtypeBaseType),
		UserTypes: make(map[string]vtypeStruct),
		Enums:     make(map[string]vtypeEnum),
		Symbols:   make(map[string]vtypeSymbol),
	}

	doc.BaseTypes["void"] = vtypeBaseType{Size: 0, Signed: false, Kind: "void", Endian: endian}

	// go through the DWARF
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if entry == nil && err == nil {
			// fmt.Printf("Done!\n")
			break
		}

		if err != nil {
			if err != nil {
				fmt.Printf("%v\n", err)
				os.Exit(255)
			}
		}
		switch entry.Tag {
		case dwarf.TagUnionType:
			fallthrough
		case dwarf.TagStructType:
			genericType, err := data.Type(entry.Offset)
			if err != nil {
				break
			}
			structType, ok := genericType.(*dwarf.StructType)
			if ok != true {
				fmt.Printf("%s is not a StructType?\n", genericType.String())
				break
			}
			if structType.Incomplete == true {
				break
			}
			st :=
				vtypeStruct{
					Size:   structType.Size(),
					Fields: make(map[string]vtypeStructField),
					Kind:   structType.Kind,
				}

			for _, field := range structType.Field {
				if field != nil {
					fieldName := field.Name
					if fieldName == "" {
						fieldName = fmt.Sprintf("unnamed_field_%x", field.ByteOffset)
					}
					vtypeField := vtypeStructField{Offset: field.ByteOffset}
					if field.BitSize != 0 {
						vtypeField.FieldType = make(map[string]interface{})
						vtypeField.FieldType["kind"] = "bitfield"
						vtypeField.FieldType["bit_position"] = field.BitOffset
						vtypeField.FieldType["bit_length"] = field.BitSize
						vtypeField.FieldType["type"] = type_name(field.Type)
					} else {
						vtypeField.FieldType = type_name(field.Type)
					}
					st.Fields[fieldName] = vtypeField
				}
			}

			name := struct_name(structType)
			doc.UserTypes[name] = st
		case dwarf.TagEnumerationType:
			genericType, err := data.Type(entry.Offset)
			if err != nil {
				break
			}
			enumType, ok := genericType.(*dwarf.EnumType)
			if ok != true {
				fmt.Printf("%s is not an EnumType?\n", genericType.String())
				break
			}
			et :=
				vtypeEnum{
					Size:      enumType.ByteSize,
					Base:      "unsigned long", // XXX TODO
					Constants: make(map[string]int64, 0),
				}
			for _, v := range enumType.Val {
				et.Constants[v.Name] = v.Val
			}
			doc.Enums[enum_name(enumType)] = et
		case dwarf.TagVariable:
			name, _ := entry.Val(dwarf.AttrName).(string)
			typOff, _ := entry.Val(dwarf.AttrType).(dwarf.Offset)
			loc := entry.AttrField(dwarf.AttrLocation)
			if name == "" || typOff == 0 {
				// if entry.Val(dwarf.AttrSpecification) != nil {
				//     // Since we are reading all the DWARF,
				//     // assume we will see the variable elsewhere.
				//     break
				// }
				// fmt.Printf("malformed DWARF TagVariable entry?\n")
				break
			}

			var address uint64
			// insert 0 when we don't know the address. ELF symbol table
			// may know it...
			if loc == nil {
				address = 0
			} else {
				address = uint64_of_location(loc, reader.AddressSize())
			}
			sym := vtypeSymbol{Address: address}
			genericType, err := data.Type(typOff)
			if err == nil {
				sym.SymbolType = type_name(genericType)
			}
			doc.Symbols[name] = sym
		case dwarf.TagPointerType:
			if _, present := doc.BaseTypes["pointer"]; !present {
				genericType, err := data.Type(entry.Offset)
				if err != nil {
					break
				}
				doc.BaseTypes["pointer"] =
					vtypeBaseType{Size: genericType.Size(), Signed: false, Kind: "int", Endian: endian}
			}
		case dwarf.TagBaseType:
			genericType, err := data.Type(entry.Offset)
			if err != nil {
				break
			}
			common := genericType.Common()
			if _, present := doc.BaseTypes[common.Name]; !present {
				doc.BaseTypes[common.Name] = new_basetype(genericType, endian)
			}
		}
	}

	// go through the ELF symbols looking for missing addresses
	elfsymbols, err := elf_file.Symbols()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(255)
	}

	voidType := make(map[string]interface{}, 0)
	voidType["kind"] = "base"
	voidType["name"] = "void"

	for _, elfsym := range elfsymbols {
		sym, ok := doc.Symbols[elfsym.Name]
		if ok && sym.Address == 0 {
			sym.Address = elfsym.Value
			doc.Symbols[elfsym.Name] = sym
		} else {
			newsym := vtypeSymbol{Address: elfsym.Value, SymbolType: voidType}
			doc.Symbols[elfsym.Name] = newsym
		}
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(255)
	}
	os.Stdout.Write(b)
}
