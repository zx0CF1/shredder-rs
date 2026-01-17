//! Shredder Engine - Obfuscador de código x86_64
//!
//! Este módulo provee herramientas para:
//! - Parsear archivos PE (.exe)
//! - Ofuscar código mediante shredding (fragmentación + junk insertion)
//! - Reconstruir PEs con código ofuscado

pub mod error;
pub mod pe_parser;
pub mod pe_rebuilder;
pub mod shredder;

pub use error::ShredderError;
pub use pe_parser::ParsedPE;
pub use pe_rebuilder::rebuild_pe;
pub use shredder::{shred, ShreddedCode, ShredderConfig};
