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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_text() {
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("plain".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
    }

    #[test]
    fn parse_markdown() {
        assert_eq!(
            "markdown".parse::<OutputFormat>().unwrap(),
            OutputFormat::Markdown
        );
        assert_eq!(
            "md".parse::<OutputFormat>().unwrap(),
            OutputFormat::Markdown
        );
    }

    #[test]
    fn parse_json() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("jsonl".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!("TEXT".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert_eq!("Json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    }

    #[test]
    fn parse_invalid() {
        assert!("xml".parse::<OutputFormat>().is_err());
    }
}
