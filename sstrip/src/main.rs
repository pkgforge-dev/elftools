use std::env;
use std::fs;
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::process;
use goblin::elf::{Elf, program_header};

const VERSION: &str = "0.1.0";
// e_shoff offsets in ELF header (file offset of section header table)
const ELF32_SHOFF_OFFSET: usize = 0x20;
const ELF64_SHOFF_OFFSET: usize = 0x28;
// e_shentsize offsets in ELF header (size of section header entry)
const ELF32_SHENTSIZE_OFFSET: usize = 0x2E;
const ELF64_SHENTSIZE_OFFSET: usize = 0x3A;
// e_shnum offsets in ELF header (number of section headers)
const ELF32_SHNUM_OFFSET: usize = 0x30;
const ELF64_SHNUM_OFFSET: usize = 0x3C;
// e_shstrndx offsets in ELF header (section name string table index)
const ELF32_SHSTRNDX_OFFSET: usize = 0x32;
const ELF64_SHSTRNDX_OFFSET: usize = 0x3E;

fn print_help() {
    let args: Vec<String> = env::args().collect();
    let arg_cmd = args.get(0).map(|s| s.as_str()).unwrap_or("sstrip");

    println!("\nRemove everything not needed by a binary to run\n");
    println!("Usage: {} [OPTIONS] FILE...", arg_cmd);
    println!("  -z, --zeroes        Also discard trailing zero bytes");
    println!("  -h, --help          Display this help and exit");
    println!("  -v, --version       Display version information and exit");
}

fn print_version() {
    //let cmd = env::args().next().unwrap_or_else(|| "add-section".to_string());
    //println!("{} {}", cmd, VERSION);
    println!("{}", VERSION);
}

fn zero_section_headers(data: &mut [u8], is_64bit: bool) {
    // Zero out the section header information in the ELF header
    let (shoff_offset, shentsize_offset, shnum_offset, shstrndx_offset) = if is_64bit {
        (ELF64_SHOFF_OFFSET, ELF64_SHENTSIZE_OFFSET, ELF64_SHNUM_OFFSET, ELF64_SHSTRNDX_OFFSET)
    } else {
        (ELF32_SHOFF_OFFSET, ELF32_SHENTSIZE_OFFSET, ELF32_SHNUM_OFFSET, ELF32_SHSTRNDX_OFFSET)
    };
    
    // Set e_shoff (section header table offset) to 0
    for i in 0..if is_64bit { 8 } else { 4 } {
        data[shoff_offset + i] = 0;
    }
    
    // Set e_shentsize (section header entry size) to 0
    data[shentsize_offset] = 0;
    data[shentsize_offset + 1] = 0;
    
    // Set e_shnum (number of section headers) to 0
    data[shnum_offset] = 0;
    data[shnum_offset + 1] = 0;
    
    // Set e_shstrndx (section header string table index) to 0
    data[shstrndx_offset] = 0;
    data[shstrndx_offset + 1] = 0;
}

fn sstrip_file(filepath: &str, discard_zeroes: bool) -> io::Result<()> {
    // Read the file
    let mut file_data = Vec::new();
    let mut file = fs::File::open(filepath)?;
    file.read_to_end(&mut file_data)?;
    
    // Parse the ELF file
    let elf = match Elf::parse(&file_data) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("Error parsing ELF file {}: {}", filepath, err);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid ELF file"));
        }
    };
    
    // Find the end of the last program header segment
    let mut last_byte = 0;
    
    for phdr in &elf.program_headers {
        // Skip non-loadable segments
        if phdr.p_type != program_header::PT_LOAD {
            continue;
        }
        
        let segment_end = phdr.p_offset as usize + phdr.p_filesz as usize;
        if segment_end > last_byte {
            last_byte = segment_end;
        }
    }
    
    // Ensure last_byte is at least the size of the ELF header + program headers
    let header_size = elf.header.e_ehsize as usize;
    let ph_size = elf.header.e_phentsize as usize * elf.header.e_phnum as usize;
    let min_size = elf.header.e_phoff as usize + ph_size;
    if last_byte < min_size {
        last_byte = min_size;
    }
    
    // Create a mutable copy of the truncated data
    let mut stripped_data = file_data[..last_byte].to_vec();
    
    // Remove section header information from the ELF header
    zero_section_headers(&mut stripped_data, elf.is_64);
    
    // If zeroes option is active, remove trailing zeroes
    if discard_zeroes {
        while let Some(&0) = stripped_data.last() {
            stripped_data.pop();
        }
    }
    
    // Write the stripped file back
    let mut output_file = fs::File::create(filepath)?;
    output_file.write_all(&stripped_data)?;
    
    println!("Stripped {} from {} bytes to {} bytes", filepath, file_data.len(), stripped_data.len());
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_help();
        process::exit(1);
    }
    
    let mut files = Vec::new();
    let mut discard_zeroes = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-z" | "--zeroes" => {
                discard_zeroes = true;
            },
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            },
            "-v" | "--version" => {
                print_version();
                process::exit(0);
            },
            arg if arg.starts_with("-") => {
                eprintln!("Unknown option: {}", arg);
                print_help();
                process::exit(1);
            },
            _ => {
                files.push(args[i].clone());
            }
        }
        i += 1;
    }
    
    if files.is_empty() {
        eprintln!("No input files specified");
        print_help();
        process::exit(1);
    }
    
    for file in files {
        if let Err(err) = sstrip_file(&file, discard_zeroes) {
            eprintln!("Error processing file {}: {}", file, err);
        }
    }
}