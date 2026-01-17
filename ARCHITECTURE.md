# Shredder Engine v2 - Technical Specification

Shredder is a post-compilation polymorphic engine for x86_64. It implements instruction-level fragmentation to break linear control-flow analysis, transforming standard execution into a non-linear graph of jump-linked nodes.

---

## 🏗️ Internal Architecture

The engine operates as a multi-stage pipeline, treating the binary as a malleable stream of instructions rather than a static file.

### 1. PE Forensic Parser (`src/pe_parser.rs`)
Handles target image acquisition and structural validation.
- **ISA Enforcement:** Validates NT headers to ensure x86_64 compatibility (PE32+).
- **RVA Resolution:** Locates the EntryPoint and maps its physical offset within the primary code container (usually `.text`).
- **Boundary Analysis:** Calculates available slack space and alignment requirements for the injection stage.

### 2. Mutation Core (`src/shredder.rs`)
The engine's orchestrator. It uses `iced-x86` for high-fidelity decoding and encoding.
1. **Instruction Decomposition:** Each mnemonic is treated as an independent **Mutation Node**.
2. **Context Preservation:** Injects opaque predicates and junk code that strictly preserve `EFLAGS` and volatile registers to maintain execution integrity.
3. **Control-Flow Linking:** Appends relative JMPs to each node to reconstruct the logical path across a randomized physical layout.
4. **Physical Shuffle:** Implements a non-linear layout strategy. Node `n` and node `n+1` are never adjacent in the final binary, defeating linear sweep disassemblers.

### 3. Image Rebuilder (`src/pe_rebuilder.rs`)
Performs a surgical injection of the mutated payload.
- **Section Injection:** Creates and maps a new `.shred` section. 
- **NT Header Orchestration:** Patches the `AddressOfEntryPoint` and updates `SizeOfImage`.
- **Checksum Invalidation:** Resets the PE checksum to 0, ensuring the OS loader doesn't reject the modified binary.
- **Padding & Alignment:** Uses `0xCC` (INT3) padding for unmapped space, facilitating debugging and identifying illegal execution flows.

---

## 🔄 Execution Flow (Mutation Pipeline)

1. **Loader Hand-off:** The OS maps the PE and transfers control to the new RVA in `.shred`.
2. **The Labyrinth:** Execution enters a sequence of:
    - **Prologue:** Opaque junk (XOR/ROL/LEA) + state backup.
    - **Payload:** The original instruction (with IP-relative fixups).
    - **Epilogue:** State restore + JMP to the next randomized node.
3. **Logic Preservation:** Despite the physical chaos, the logical state remains 100% consistent with the original binary.

---

## 🛠️ Usage & Integration

### CLI Access
```powershell
# Basic usage for PE transformation
cargo run -- <input.exe> <output.exe>
```

## Transformation Modes
**Linear:** Minimal fragmentation for performance testing.

**Stealth:** Full polymorphic mutation with context protection (recommended for evasion).

## ⚠️ Research Status & Roadmap
**Relocation Handling:** Current focus is on implementing a relocation engine for arbitrary .bin blobs (e.g., CobaltStrike beacons).

**RIP-Relative Fixups:** Improving the handling of data-dependent instructions when moved to external sections.

**CFG Recovery Resistance:** Exploring indirect JMP tables to further obfuscate the control-flow graph.