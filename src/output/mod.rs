// Simple output format support for multi-format implementation
// This is a basic implementation to support the CLI --format flag

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Text,
    Markdown,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "text" | "plain" => Ok(OutputFormat::Text),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "json" | "jsonl" => Ok(OutputFormat::Json),
            _ => Err(anyhow::anyhow!(
                "Error: Invalid format '{s}'. Supported formats: text, markdown, json"
            )),
        }
    }
}
