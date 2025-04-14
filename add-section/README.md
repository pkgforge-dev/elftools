### ℹ️ About
A tool to add a minimal Section Header to binaries with `no section header`.<br>
Adds `< 100 Bytes` to original File Size.

### 🖳 Installation
Use [soar](https://github.com/pkgforge/soar) & Run:
```bash
soar add 'add-section#github.com.pkgforge-dev.elftools.source'
```

### 🧰 Usage
```mathematica
❯ add-section --help

Usage: add-section <input_elf> <output_elf>

Options:
  -f, --force           Force processing even if file already has section headers
  -i, --input FILE      Input ELF file
  -o, --output FILE     Output ELF file (directories will be created if needed)
```

### 📔 Examples
```bash
 #Take a UPX compressed binary & try reading Sections
 > file "soar.upx" && readelf -S "soar.upx"
  soar.upx: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), statically linked, no section header
  There are no sections in this file.

 #Add a dummy section to a UPX Compressed Binary
 > add-section -i "soar.upx" -o "/tmp/soar"
  Original ELF info:
    Input file: /tmp/tmp.lFIkq70PBI/soar.upx
    Architecture: 64-bit x86_64
    Section header offset: 0x0
    Number of sections: 0
    Section header entry size: 0 bytes
  File has no section headers. Adding a dummy section.
  Successfully added dummy section header to '/tmp/soar'
  New number of sections: 1

 #Re-read it using file & readelf
 > file "/tmp/soar" && readelf -S "/tmp/soar"
  /tmp/soar: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), statically linked, stripped
  There is 1 section header, starting at offset 0x5086b6:
  Section Header:
    [Nr] Name              Type             Address           Offset
         Size              EntSize          Flags  Link  Info  Align
    [ 0] <no-strings>      PROGBITS         0000000000000000  00000000
         0000000000000000  0000000000000000   A       0     0     0 
```