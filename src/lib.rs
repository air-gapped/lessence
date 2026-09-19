//! lessence - Intelligent log compression via pattern-based folding

pub mod anonymize;
pub mod briefing;
pub mod cli;
pub mod config;
pub mod diff;
pub mod distill;
pub mod folder;
pub mod ingest;
pub mod normalize;
pub mod output;
pub mod patterns;
pub mod sanitize;
pub mod skill;

pub use config::Config;
pub use folder::{PatternFolder, apply_pii_masking};
