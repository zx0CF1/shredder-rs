//! PE Forensic Parser - Extraction and validation of executable images.
use crate::error::ShredderError;
use exe::pe::{VecPE, PE};
use exe::{Buffer, SectionCharacteristics};
use std::path::Path;

pub struct ParsedPE {
    pub image_buffer: Vec<u8>,
    pub section_data: Vec<u8>,
    pub section_rva: u32,
    pub file_offset: u32,
    pub entry_rva: u32,
    pub image_base: u64,
    pub raw_instance: VecPE,
    pub section_name: String,
}

impl ParsedPE {
    /// Returns the Absolute Virtual Address of the code base.
    pub fn get_code_base_va(&self) -> u64 {
        self.image_base + self.section_rva as u64
    }

    /// Resolves the local offset of the EntryPoint relative to the target section.
    pub fn get_local_entry_offset(&self) -> Option<usize> {
        if self.entry_rva >= self.section_rva {
            let diff = (self.entry_rva - self.section_rva) as usize;
            if diff < self.section_data.len() {
                return Some(diff);
            }
        }
        None
    }

    /// Calculates the next aligned Virtual Address (PAGE_SIZE alignment).
    pub fn next_available_rva(&self) -> u32 {
        let sections = self.raw_instance.get_section_table().unwrap();
        let max_rva = sections
            .iter()
            .map(|s| s.virtual_address.0 + s.virtual_size)
            .max()
            .unwrap_or(0);

        (max_rva + 0xFFF) & !0xFFF // 4KB Alignment
    }

    /// Calculates the next aligned File Offset (Sector alignment).
    pub fn next_available_file_offset(&self) -> u32 {
        let sections = self.raw_instance.get_section_table().unwrap();
        let max_off = sections
            .iter()
            .map(|s| s.pointer_to_raw_data.0 + s.size_of_raw_data)
            .max()
            .unwrap_or(0);

        (max_off + 0x1FF) & !0x1FF // 512b Alignment
    }
}

pub fn parse_pe(target: &Path) -> Result<ParsedPE, ShredderError> {
    let pe = VecPE::from_disk_file(target)
        .map_err(|_| ShredderError::InvalidPE("FileSystem I/O error or invalid access".into()))?;

    // ISA Enforcement
    let arch = pe
        .get_arch()
        .map_err(|_| ShredderError::InvalidPE("Corrupt NT Headers".into()))?;
    if arch != exe::Arch::X64 {
        return Err(ShredderError::InvalidPE(
            "Unsupported ISA: Engine requires x86_64 target".into(),
        ));
    }

    let image_base = pe.get_image_base().unwrap_or(0x140000000);
    let entry_rva = pe
        .get_entrypoint()
        .map_err(|_| ShredderError::InvalidPE("EP resolution failed".into()))?
        .0;

    // Locate the primary executable container (usually .text)
    let section_table = pe
        .get_section_table()
        .map_err(|_| ShredderError::InvalidPE("Section table missing".into()))?;

    let target_section = section_table
        .iter()
        .find(|s| {
            s.characteristics.contains(SectionCharacteristics::CNT_CODE)
                || s.characteristics
                    .contains(SectionCharacteristics::MEM_EXECUTE)
        })
        .ok_or_else(|| ShredderError::SectionNotFound("No executable payload found".into()))?;

    let rva = target_section.virtual_address.0;
    let offset = target_section.pointer_to_raw_data.0 as usize;
    let size = target_section.size_of_raw_data as usize;

    // Boundary check for malformed images
    if offset + size > pe.as_slice().len() {
        return Err(ShredderError::InvalidPE(
            "Section mapping exceeds physical file size".into(),
        ));
    }

    let name = String::from_utf8_lossy(
        &target_section
            .name
            .iter()
            .map(|c| c.0)
            .take_while(|&b| b != 0)
            .collect::<Vec<u8>>(),
    )
    .into_owned();

    println!("[+] PE Image Base: 0x{:X}", image_base);
    println!("[+] EntryPoint RVA: 0x{:X}", entry_rva);
    println!("[+] Mapping section: {} [Offset: 0x{:X}]", name, offset);

    Ok(ParsedPE {
        image_buffer: pe.as_slice().to_vec(),
        section_data: pe.as_slice()[offset..offset + size].to_vec(),
        section_rva: rva,
        file_offset: offset as u32,
        entry_rva,
        image_base,
        raw_instance: pe,
        section_name: name,
    })
}
