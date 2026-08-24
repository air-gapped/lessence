//! lessence - Intelligent log compression via pattern-based folding

pub mod cli;
pub mod config;
pub mod folder;
pub mod ingest;
pub mod normalize;
pub mod patterns;

pub use config::Config;
pub use folder::{PatternFolder, apply_pii_masking};
