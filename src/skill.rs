//! `--skill`: the agent skill, shipped inside the binary (lessence-xo4).
//!
//! The skill documents this binary's behaviour, so it is embedded at build
//! time from the same commit and printed by the binary itself, the way
//! `herdr --skill` does it. There is no second copy to drift: an installed
//! skill is the one that was verified against the build that printed it.

/// The skill body, `.claude/skills/lessence/SKILL.md` at build time.
const SKILL: &str = include_str!("../.claude/skills/lessence/SKILL.md");
/// The complete flag reference the skill points to.
const FLAGS: &str = include_str!("../.claude/skills/lessence/references/flags.md");

/// The topics `--skill` can print.
pub const TOPICS: &[&str] = &["skill", "flags"];

/// The text `--skill <topic>` prints, or `None` for an unknown topic.
///
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

fn with_provenance_after_frontmatter(text: &str, note: &str) -> String {
    // Frontmatter is the first `---` line up to the next `---` line.
    if let Some(rest) = text.strip_prefix("---\n")
        && let Some(end) = rest.find("\n---\n")
    {
        let split = 4 + end + 5;
        return format!("{}\n{note}{}", &text[..split - 1], &text[split..]);
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
