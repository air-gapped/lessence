// Simple output format support for multi-format implementation
// This is a basic implementation to support the CLI --format flag

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Text,
    Markdown,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "text" | "plain" => Ok(OutputFormat::Text),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "json" => Err(anyhow::anyhow!(
                "Error: Invalid format 'json'. Supported formats: text, markdown"
            )),
            _ => Err(anyhow::anyhow!(
                "Error: Invalid format '{}'. Supported formats: text, markdown", s
            )),
        }
    }

}