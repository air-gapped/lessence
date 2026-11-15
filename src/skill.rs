const SKILL: &str = include_str!("../.claude/skills/lessence/SKILL.md");
const FLAGS: &str = include_str!("../.claude/skills/lessence/references/flags.md");

pub const TOPICS: &[&str] = &["skill", "flags"];

/// `skill` is SKILL.md with a provenance note inserted after its YAML
/// frontmatter, so the file still starts with `---` at byte 0 as the skill
/// loaders require; `flags` is references/flags.md with the note on top.
pub fn render(topic: &str, version: &str) -> Option<String> {
    let note = provenance(version);
    match topic {
        "skill" => Some(with_provenance_after_frontmatter(SKILL, &note)),
        "flags" => Some(format!("{note}\n{FLAGS}")),
        _ => None,
    }
}

fn provenance(version: &str) -> String {
    format!(
        "<!-- Printed by `lessence --skill` from lessence {version}. The installed \
         `lessence --help` is authoritative over anything this text remembers about \
         flags; re-run `lessence --skill` after upgrading. -->\n"
    )
}

const FRONTMATTER_OPEN: &str = "---\n";
const FRONTMATTER_CLOSE: &str = "\n---\n";

fn with_provenance_after_frontmatter(text: &str, note: &str) -> String {
    if let Some(rest) = text.strip_prefix(FRONTMATTER_OPEN)
        && let Some(end) = rest.find(FRONTMATTER_CLOSE)
    {
        let frontmatter_end = FRONTMATTER_OPEN.len() + end + FRONTMATTER_CLOSE.len();
        return format!(
            "{}\n{note}{}",
            &text[..frontmatter_end - 1],
            &text[frontmatter_end..]
        );
    }
    format!("{note}\n{text}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_skill_keeps_its_frontmatter_at_byte_zero() {
        let out = render("skill", "9.9.9 (test)").unwrap();
        assert!(out.starts_with("---\nname: lessence\n"), "{}", &out[..40]);
        let after = out.find("\n---\n").unwrap() + 5;
        assert!(
            out[after..]
                .starts_with("<!-- Printed by `lessence --skill` from lessence 9.9.9 (test)."),
            "{}",
            &out[after..after + 80]
        );
        assert!(out.ends_with(&SKILL[SKILL.len() - 40..]));
    }

    #[test]
    fn the_flags_topic_is_the_reference_with_the_note_on_top() {
        let out = render("flags", "9.9.9").unwrap();
        assert!(out.starts_with("<!-- Printed by"));
        assert!(out.contains("# lessence — Complete Flag Reference"));
    }

    #[test]
    fn an_unknown_topic_is_none() {
        assert!(render("recipes", "9.9.9").is_none());
    }

    #[test]
    fn text_without_frontmatter_gets_the_note_first() {
        assert!(with_provenance_after_frontmatter("# plain\n", "N\n").starts_with("N\n"));
    }
}
