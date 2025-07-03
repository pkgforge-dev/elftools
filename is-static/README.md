### ℹ️ About
Check if an ELF is Statically Linked.<br>

### 🖳 Installation
Use [soar](https://github.com/pkgforge/soar) & Run:
```bash
soar add 'is-static#github.com.pkgforge-dev.elftools.source'
```

### 🧰 Usage
```mathematica
❯ is-static --help

Analyze ELF binary linking type (Static/Dynamic)

Options:
  -r, --result     Show detailed analysis with evidence
  -v, --verbose    Show verbose output with all indicators
  -s, --simple     Show simple output (static/dynamic/error)
  -c, --confidence Show confidence score
  -a, --arch       Show architecture and bitness information
  -q, --quiet      Suppress non-essential output
  -h, --help       Show this help message

Exit codes:
  0    Binary is statically linked
  1    Binary is dynamically linked
  2    Error (file not found, invalid ELF, etc.)

Examples:
  is-static /bin/ls                    # Simple check
  is-static -r /bin/ls                 # Detailed analysis
  is-static -v /usr/bin/gcc            # Verbose output
  is-static -a /usr/local/bin/static   # Show architecture info
  is-static -c /bin/bash               # Show confidence
  is-static -q /bin/bash               # Quiet mode
```