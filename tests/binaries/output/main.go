package main

import (
	"debug/elf"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <elf-file>")
		return
	}

	filePath := os.Args[1]
	file, err := elf.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening ELF file: %v\n", err)
		return
	}
	defer file.Close()

	dynSection := file.SectionByType(elf.SHT_DYNAMIC)
	if dynSection == nil {
		fmt.Println("No dynamic section found.")
		return
	}

	dynData, err := dynSection.Data()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading dynamic section: %v\n", err)
		return
	}

	fmt.Println("Dynamic section entries:")
	for i := 0; i < len(dynData); i += 16 {
		tag := elf.DynTag(file.ByteOrder.Uint64(dynData[i:]))
		val := file.ByteOrder.Uint64(dynData[i+8:])
		fmt.Printf("Tag: 0x%016x, Value: 0x%016x\n", uint64(tag), val)
	}
}
