//! Core Mutation Engine - Polymorphic instruction shredding & context preservation.
use crate::error::ShredderError;
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, Register,
};
use rand::seq::SliceRandom;
use rand::Rng;

#[derive(Clone)]
pub struct ShredderConfig {
    pub base_ip: u64,
    pub block_separation: u64,
    pub junk_count: usize,
    pub use_junk: bool,
}

impl Default for ShredderConfig {
    fn default() -> Self {
        Self {
            base_ip: 0x10000,
            block_separation: 0x80, // Tighter packing for shellcode targets
            junk_count: 3,
            use_junk: false,
        }
    }
}

pub struct ShreddedCode {
    pub nodes: Vec<MutationNode>,
    pub entry_point: u64,
    pub total_size: usize,
}

pub struct MutationNode {
    pub id: usize,
    pub rip: u64,
    pub raw_bytes: Vec<u8>,
}

/// Generates opaque predicates and junk instructions.
/// Focuses on preserving EFLAGS to avoid breaking conditional jumps.
fn generate_opaque_junk(count: usize) -> Vec<Instruction> {
    let mut rng = rand::rng();
    let mut junk = Vec::with_capacity(count * 4);

    // Using scratch registers that are less likely to hold critical pointers in small blocks
    let volatile_regs = [Register::R10, Register::R11, Register::R12];

    for _ in 0..count {
        let reg = volatile_regs[rng.random_range(0..volatile_regs.len())];

        // Context sandwich: Save state
        junk.push(Instruction::with1(Code::Push_r64, reg).unwrap());
        junk.push(Instruction::with(Code::Pushfq));

        // Polymorphic junk variety
        match rng.random_range(0..4) {
            0 => junk.push(Instruction::with2(Code::Xor_rm64_r64, reg, reg).unwrap()),
            1 => junk.push(
                Instruction::with2(
                    Code::Lea_r64_m,
                    reg,
                    iced_x86::MemoryOperand::with_base(reg),
                )
                .unwrap(),
            ),
            2 => junk.push(Instruction::with2(Code::Btr_rm64_imm8, reg, 1).unwrap()),
            _ => junk.push(
                Instruction::with2(Code::Rol_rm64_imm8, reg, rng.random_range(1..4)).unwrap(),
            ),
        }

        // Restore state
        junk.push(Instruction::with(Code::Popfq));
        junk.push(Instruction::with1(Code::Pop_r64, reg).unwrap());
    }
    junk
}

pub fn shred(
    payload: &[u8],
    original_rip: u64,
    config: ShredderConfig,
) -> Result<ShreddedCode, ShredderError> {
    let decoder = Decoder::with_ip(64, payload, original_rip, DecoderOptions::NONE);
    let instructions: Vec<Instruction> = decoder.into_iter().filter(|i| !i.is_invalid()).collect();

    if instructions.is_empty() {
        return Err(ShredderError::EncodingError(
            "Zero valid instructions decoded".into(),
        ));
    }

    let n = instructions.len();
    let mut rng = rand::rng();

    // Non-linear physical layout generation
    let mut physical_map: Vec<usize> = (0..n).collect();
    physical_map.shuffle(&mut rng);

    let mut virtual_to_physical_rip = vec![0u64; n];
    for (pos, &idx) in physical_map.iter().enumerate() {
        virtual_to_physical_rip[idx] = config.base_ip + (pos as u64 * config.block_separation);
    }

    let mut logical_nodes = Vec::new();
    for (idx, ins) in instructions.iter().enumerate() {
        let mut node_ins = Vec::new();

        // 1. Prologue Junk
        if config.use_junk {
            node_ins.extend(generate_opaque_junk(config.junk_count));
        }

        // 2. Real Instruction (with IP-relative fixups)
        let mut patched_ins = *ins;
        if patched_ins.is_call_near()
            || patched_ins.is_jmp_near()
            || patched_ins.is_ip_rel_memory_operand()
        {
            let target = ins.near_branch_target();
            if target != 0 {
                patched_ins.set_near_branch64(target);
            }
        }
        node_ins.push(patched_ins);

        // 3. Epilogue / Control Flow Linker
        if idx < n - 1 {
            let next_rip = virtual_to_physical_rip[idx + 1];
            node_ins.push(Instruction::with_branch(Code::Jmp_rel32_64, next_rip).unwrap());
        }
        logical_nodes.push(node_ins);
    }

    // Encoding phase
    let mut blocks = Vec::new();
    for (pos, &idx) in physical_map.iter().enumerate() {
        let rip = config.base_ip + (pos as u64 * config.block_separation);
        blocks.push(InstructionBlock::new(&logical_nodes[idx], rip));
    }

    let encoded = BlockEncoder::encode_slice(64, &blocks, BlockEncoderOptions::NONE)
        .map_err(|e| ShredderError::EncodingError(e.to_string()))?;

    let final_nodes = encoded
        .iter()
        .enumerate()
        .map(|(i, r)| MutationNode {
            id: physical_map[i],
            rip: r.rip,
            raw_bytes: r.code_buffer.clone(),
        })
        .collect();

    Ok(ShreddedCode {
        nodes: final_nodes,
        entry_point: virtual_to_physical_rip[0],
        total_size: encoded.iter().map(|r| r.code_buffer.len()).sum(),
    })
}

pub fn assemble_mutated_flow(shredded: &ShreddedCode, base_rva: u64) -> Vec<u8> {
    let stream_end = shredded
        .nodes
        .iter()
        .map(|n| (n.rip - base_rva) as usize + n.raw_bytes.len())
        .max()
        .unwrap_or(0);

    let mut stream = vec![0xCCu8; stream_end]; // Using INT3 (0xCC) for padding, more common in debug/research
    for node in &shredded.nodes {
        let offset = (node.rip - base_rva) as usize;
        stream[offset..offset + node.raw_bytes.len()].copy_from_slice(&node.raw_bytes);
    }
    stream
}
