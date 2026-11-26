//! Slash-command expansion: invoking a skill as `/name args…` expands the
//! skill body into the conversation as a tagged message, with `$ARGUMENT`
//! substitution — adopted from the Cloudflare OS context gatekeeper.
//!
//! The expansion is DATA injected into a chat, never an instruction channel
//! with authority: the tag names the skill and collection so a reader (and
//! an audit) can always see where the text came from.

use crate::context_library::collection::ContextLibrary;

/// Slash expansion failures.
#[derive(Debug, PartialEq, Eq)]
pub enum SlashError {
    UnknownCommand(String),
    Ambiguous {
        name: String,
        collections: Vec<String>,
    },
}

impl std::fmt::Display for SlashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCommand(name) => write!(f, "unknown slash command /{name}"),
            Self::Ambiguous { name, collections } => {
                write!(
                    f,
                    "ambiguous slash command /{name}: found in collections {collections:?}"
                )
            }
        }
    }
}

impl std::error::Error for SlashError {}

/// Expand `/name arguments` for `account`. Returns the tagged expansion.
///
/// `$ARGUMENT` (all occurrences) in the skill body is replaced by the
/// argument text; when the body carries no `$ARGUMENT` and arguments were
/// given, they are appended as a trailing line, so nothing the user typed
/// is silently dropped.
pub fn expand_slash_command(
    library: &ContextLibrary,
    account: &str,
    command: &str,
) -> Result<String, SlashError> {
    let stripped = command.strip_prefix('/').unwrap_or(command);
    let (name, args) = match stripped.split_once(char::is_whitespace) {
        Some((n, a)) => (n, a.trim()),
        None => (stripped, ""),
    };
    let matches: Vec<_> = library
        .skills_visible_to(account)
        .into_iter()
        .filter(|(_, s)| s.name == name)
        .collect();
    match matches.as_slice() {
        [] => Err(SlashError::UnknownCommand(name.to_string())),
        [(collection, skill)] => {
            let mut body = if skill.body.contains("$ARGUMENT") {
                skill.body.replace("$ARGUMENT", args)
            } else if args.is_empty() {
                skill.body.clone()
            } else {
                format!("{}\n\nArguments: {}", skill.body, args)
            };
            if !body.ends_with('\n') {
                body.push('\n');
            }
            Ok(format!(
                "<skill name=\"{}\" collection=\"{}\">\n{}</skill>",
                skill.name, collection, body
            ))
        }
        _ => Err(SlashError::Ambiguous {
            name: name.to_string(),
            collections: matches.iter().map(|(c, _)| c.to_string()).collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_library::collection::{Collection, Visibility};

    fn library() -> ContextLibrary {
        let mut lib = ContextLibrary::new();
        let mut c = Collection::new("codex", Visibility::Public, "org");
        c.put_skill(
            "---\nname: summarize\ndescription: Summarize text.\n---\nSummarize the following:\n$ARGUMENT",
        )
        .unwrap();
        c.put_skill("---\nname: greet\ndescription: Greeting.\n---\nSay hello politely.")
            .unwrap();
        lib.add_collection(c).unwrap();
        lib
    }

    #[test]
    fn substitutes_argument() {
        let lib = library();
        let out = expand_slash_command(&lib, "bob", "/summarize the Q3 report").unwrap();
        assert!(out.contains("Summarize the following:\nthe Q3 report"));
        assert!(out.starts_with("<skill name=\"summarize\" collection=\"codex\">"));
    }

    #[test]
    fn appends_args_when_no_placeholder() {
        let lib = library();
        let out = expand_slash_command(&lib, "bob", "/greet warmly").unwrap();
        assert!(out.contains("Arguments: warmly"));
    }

    #[test]
    fn unknown_command_is_an_error() {
        let lib = library();
        assert_eq!(
            expand_slash_command(&lib, "bob", "/nope").unwrap_err(),
            SlashError::UnknownCommand("nope".into())
        );
    }

    #[test]
    fn private_skills_do_not_expand_for_others() {
        let mut lib = library();
        let mut p = Collection::new("alice-notes", Visibility::Private, "alice");
        p.put_skill("---\nname: private-skill\ndescription: p.\n---\nsecret")
            .unwrap();
        lib.add_collection(p).unwrap();
        assert!(expand_slash_command(&lib, "bob", "/private-skill").is_err());
        assert!(expand_slash_command(&lib, "alice", "/private-skill").is_ok());
    }

    #[test]
    fn ambiguity_is_named_not_guessed() {
        let mut lib = library();
        let mut c2 = Collection::new("other", Visibility::Public, "org");
        c2.put_skill("---\nname: greet\ndescription: Another greeting.\n---\nHi.")
            .unwrap();
        lib.add_collection(c2).unwrap();
        let err = expand_slash_command(&lib, "bob", "/greet").unwrap_err();
        assert!(matches!(err, SlashError::Ambiguous { .. }));
    }
}
