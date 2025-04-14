use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

const VERSION: &str = "0.1.2";
fn print_version() {
    //let cmd = env::args().next().unwrap_or_else(|| "add-section".to_string());
    //println!("{} {}", cmd, VERSION);
    println!("{}", VERSION);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Default values
    let mut force_mode = false;
    let mut input_path = String::new();
    let mut output_path = String::new();
    
    // Parse arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--force" => {
                force_mode = true;
                i += 1;
            },
            "-i" | "--input" => {
                if i + 1 < args.len() {
                    input_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: {} option requires an argument", args[i]);
                    process::exit(1);
                }
            },
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output_path = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: {} option requires an argument", args[i]);
                    process::exit(1);
                }
            },
            "-v" | "--version" => {
                print_version();
                process::exit(0);
            },
            _ => {
                // For backward compatibility, allow positional arguments
                if input_path.is_empty() {
                    input_path = args[i].clone();
                } else if output_path.is_empty() {
                    output_path = args[i].clone();
                }
                i += 1;
            }
        }
    }
    
    if input_path.is_empty() || output_path.is_empty() {
        eprintln!("\nAdd a minimal Section Header to binaries with no section headers\n");
        eprintln!("Usage: {} [options] <input_elf> <output_elf>", args[0]);
        eprintln!("Options:");
        eprintln!("  -f, --force           Force processing even if file already has section headers");
        eprintln!("  -i, --input FILE      Input ELF file");
        eprintln!("  -o, --output FILE     Output ELF file (directories will be created if needed)");
        eprintln!("  -v, --version         Show Version");
        process::exit(1);
    }
    
    // Convert input path to real path to avoid symlinks
    let real_input_path = fs::canonicalize(&input_path).unwrap_or_else(|e| {
        eprintln!("Error resolving input path '{}': {}", input_path, e);
        process::exit(1);
    });
    
    // Ensure output directory exists
    if let Some(parent) = Path::new(&output_path).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("Error creating directory '{}': {}", parent.display(), e);
                process::exit(1);
            });
        }
    }
   
    // Read the input file
    let mut input_data = Vec::new();
    let mut input_file = fs::File::open(&real_input_path).unwrap_or_else(|e| {
        eprintln!("Error opening input file '{}': {}", real_input_path.display(), e);
        process::exit(1);
    });
    input_file.read_to_end(&mut input_data)?;
   
    // Verify it's an ELF file by checking magic bytes
    if input_data.len() < 4 || &input_data[0..4] != &[0x7f, b'E', b'L', b'F'] {
        eprintln!("Error: Input file is not an ELF file");
        process::exit(1);
    }
    
    // We'll create a copy of the input file and modify it
    let mut output_data = input_data.clone();
    
    // Parse the ELF header to find needed information
    let is_64bit = output_data[4] == 2;
    let is_little_endian = output_data[5] == 1;
    
    // Get architecture information
    let machine_type = if output_data.len() >= 19 {
        let e_machine = ((output_data[19] as u16) << 8) | (output_data[18] as u16);
        match e_machine {
            0x03 => "x86",
            0x3E => "x86_64",
            0x28 => "arm",
            0xB7 => "aarch64",
            0x08 => "mips",
            0x14 => "powerpc",
            0x15 => "powerpc64",
            0x2B => "sparc",
            0x2C => "sparc64",
            0x32 => "ia64",
            0x3E8 => "riscv",
            _ => "unknown",
        }
    } else {
        "unknown"
    };
    
    // Check endianness matches our assumptions
    if !is_little_endian {
        eprintln!("Error: Only little endian ELF files are supported");
        process::exit(1);
    }
    
    // Determine header size based on architecture
    let elf_header_size = if is_64bit { 64 } else { 52 };
    
    // Read current number of section headers and their offset
    let mut cursor = std::io::Cursor::new(&output_data);
    
    // Position for section header offset depends on 32/64-bit
    let section_header_offset_pos = if is_64bit { 40 } else { 32 };
    cursor.set_position(section_header_offset_pos);
    
    let section_header_offset = if is_64bit {
        cursor.read_u64::<LittleEndian>()?
    } else {
        cursor.read_u32::<LittleEndian>()? as u64
    };
    
    // Position for number of section headers depends on 32/64-bit
    let num_sections_pos = if is_64bit { 60 } else { 48 };
    cursor.set_position(num_sections_pos);
    let num_sections = cursor.read_u16::<LittleEndian>()?;
    
    // Position for section header entry size depends on 32/64-bit
    let sh_entry_size_pos = if is_64bit { 58 } else { 46 };
    cursor.set_position(sh_entry_size_pos);
    let section_header_entry_size = cursor.read_u16::<LittleEndian>()? as usize;
    
    println!("Original ELF info:");
    println!("  Input file: {}", real_input_path.display());
    println!("  Architecture: {}-bit {}", if is_64bit { 64 } else { 32 }, machine_type);
    println!("  Section header offset: 0x{:X}", section_header_offset);
    println!("  Number of sections: {}", num_sections);
    println!("  Section header entry size: {} bytes", section_header_entry_size);
    
    // If there are already sections and force mode is not enabled, exit
    if num_sections > 0 && !force_mode {
        println!("File already has {} section headers. Use -f or --force to process anyway.", num_sections);
        return Ok(());
    }
    
    // If there are already sections, we can optionally just add one more
    if num_sections > 0 {
        println!("File already has {} section headers. Adding one more dummy section.", num_sections);
    } else {
        println!("File has no section headers. Adding a dummy section.");
    }
    
    // Create a new section header table 
    // We'll add one dummy section header to the existing ones
    let new_num_sections = num_sections + 1;
    
    // If there were no sections before, we need to create a null section as the first one
    let add_null_section = num_sections == 0;
    let total_new_sections = if add_null_section { 2 } else { 1 };
    
    // Determine where to put new section headers - append to the end of the file
    let new_section_header_offset = output_data.len() as u64;
    
    // Create dummy section header(s)
    let mut new_section_data = Vec::new();
    
    // If needed, add a null section header first
    if add_null_section {
        // Add null section header (all zeros)
        for _ in 0..section_header_entry_size {
            new_section_data.push(0);
        }
    }
    
    // Add our dummy section header (just a minimal valid one)
    // For 64-bit format
    if is_64bit {
        // sh_name
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_type (SHT_PROGBITS = 1)
        new_section_data.write_u32::<LittleEndian>(1)?;
        // sh_flags (SHF_ALLOC = 2)
        new_section_data.write_u64::<LittleEndian>(2)?;
        // sh_addr
        new_section_data.write_u64::<LittleEndian>(0)?;
        // sh_offset
        new_section_data.write_u64::<LittleEndian>(0)?;
        // sh_size
        new_section_data.write_u64::<LittleEndian>(0)?;
        // sh_link
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_info
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_addralign
        new_section_data.write_u64::<LittleEndian>(0)?;
        // sh_entsize
        new_section_data.write_u64::<LittleEndian>(0)?;
    } else {
        // 32-bit format
        // sh_name
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_type (SHT_PROGBITS = 1)
        new_section_data.write_u32::<LittleEndian>(1)?;
        // sh_flags (SHF_ALLOC = 2)
        new_section_data.write_u32::<LittleEndian>(2)?;
        // sh_addr
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_offset
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_size
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_link
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_info
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_addralign
        new_section_data.write_u32::<LittleEndian>(0)?;
        // sh_entsize
        new_section_data.write_u32::<LittleEndian>(0)?;
    }
    
    // Update the ELF header to point to our new section headers
    // and update the section count
    let mut cursor = std::io::Cursor::new(&mut output_data);
    
    // Update section header offset
    cursor.set_position(section_header_offset_pos);
    if is_64bit {
        cursor.write_u64::<LittleEndian>(new_section_header_offset)?;
    } else {
        cursor.write_u32::<LittleEndian>(new_section_header_offset as u32)?;
    }
    
    // Update number of sections
    cursor.set_position(num_sections_pos);
    cursor.write_u16::<LittleEndian>(new_num_sections)?;
    
    // If we're adding sections for the first time, make sure section entry size is set
    if num_sections == 0 {
        let default_sh_size = if is_64bit { 64 } else { 40 };
        cursor.set_position(sh_entry_size_pos);
        cursor.write_u16::<LittleEndian>(default_sh_size)?;
    }
    
    // Copy any existing section headers if there were any
    if section_header_offset > 0 && num_sections > 0 {
        let section_table_size = section_header_entry_size as u64 * num_sections as u64;
        if section_header_offset + section_table_size <= output_data.len() as u64 {
            let mut section_data = vec![0; section_table_size as usize];
            let mut cursor = std::io::Cursor::new(&output_data);
            cursor.set_position(section_header_offset);
            cursor.read_exact(&mut section_data)?;
            
            // Append the existing section headers
            output_data.extend_from_slice(&section_data);
        }
    }
    
    // Append our new section header(s)
    output_data.extend_from_slice(&new_section_data);
    
    // Write to the output file
    fs::write(&output_path, output_data).unwrap_or_else(|e| {
        eprintln!("Error writing to output file '{}': {}", output_path, e);
        process::exit(1);
    });

    // Set executable permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&output_path).unwrap_or_else(|e| {
            eprintln!("Error getting file metadata '{}': {}", output_path, e);
            process::exit(1);
        });
        let mut perms = metadata.permissions();
        let mode = perms.mode();
        // Add executable bits for user, group and others (equivalent to chmod a+x)
        perms.set_mode(mode | 0o111);
        fs::set_permissions(&output_path, perms).unwrap_or_else(|e| {
            eprintln!("Error setting file permissions '{}': {}", output_path, e);
            process::exit(1);
        });
    }

    println!("Successfully added dummy section header to '{}'", output_path);
    println!("New number of sections: {}", new_num_sections);
    
    Ok(())
}