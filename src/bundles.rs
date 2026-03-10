#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleAlias {
    pub alias: String,
    pub name: String,
    /// If true, this agent needs a shell alias with WSH_GUARD + BASH_ENV wrapping.
    pub wrap: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub name: String,
    pub description: String,
    pub manifests: Vec<String>,
    pub aliases: Vec<BundleAlias>,
    /// If true, `wsh setup` will offer to guard ALL shell sessions (export WSH_GUARD=1)
    pub guard_all_sessions: bool,
}

pub fn get_bundle(name: &str) -> Option<Bundle> {
    if let Ok(config) = crate::registry::fetch_bundle(name) {
        return Some(Bundle {
            name: config.bundle.name,
            description: config.bundle.description,
            manifests: config.manifests.include,
            aliases: config
                .agents
                .into_iter()
                .filter(|agent| {
                    !agent.alias.eq_ignore_ascii_case("aider")
                        && !agent.name.eq_ignore_ascii_case("aider")
                })
                .map(|agent| BundleAlias {
                    alias: agent.alias,
                    name: agent.name,
                    wrap: agent.wrap,
                })
                .collect(),
            guard_all_sessions: config.setup.guard_all_sessions,
        });
    }
    None
}

pub fn list_bundles() -> Vec<Bundle> {
    let Ok(names) = crate::registry::list_available_bundles() else {
        return Vec::new();
    };
    names
        .into_iter()
        .filter_map(|name| get_bundle(&name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Bundle, BundleAlias};

    #[test]
    fn maps_bundle_config_to_bundle_struct() {
        let config = crate::registry::BundleConfig {
            bundle: crate::registry::BundleMeta {
                name: "codex".to_string(),
                description: "Coding agents".to_string(),
                version: "1.0.0".to_string(),
            },
            setup: crate::registry::BundleSetup {
                guard_all_sessions: false,
                shell_guard: true,
                prompt_lock: true,
                claude_pretool_hook: false,
            },
            agents: vec![crate::registry::BundleAgent {
                name: "codex".to_string(),
                alias: "codex".to_string(),
                wrap: true,
            }],
            manifests: crate::registry::BundleManifests {
                include: vec!["warrant-sh/git".to_string()],
            },
        };

        let bundle = Bundle {
            name: config.bundle.name,
            description: config.bundle.description,
            manifests: config.manifests.include,
            aliases: config
                .agents
                .into_iter()
                .map(|agent| BundleAlias {
                    alias: agent.alias,
                    name: agent.name,
                    wrap: agent.wrap,
                })
                .collect(),
            guard_all_sessions: config.setup.guard_all_sessions,
        };
        assert_eq!(bundle.name, "codex");
        assert_eq!(bundle.aliases.len(), 1);
        assert_eq!(bundle.aliases[0].alias, "codex");
        assert!(bundle.aliases[0].wrap);
        assert_eq!(bundle.manifests, vec!["warrant-sh/git".to_string()]);
    }

    #[test]
    fn parses_bundle_toml_manifest_list() {
        let text = r#"
[bundle]
name = "codex"
description = "Coding agents"
version = "1.0.0"

[setup]
guard_all_sessions = false
shell_guard = true
prompt_lock = true
claude_pretool_hook = false

[[agents]]
name = "codex"
alias = "codex"

[manifests]
include = ["warrant-sh/git", "warrant-sh/coreutils"]
"#;

        let parsed: crate::registry::BundleConfig = toml::from_str(text).expect("parse bundle");
        assert_eq!(
            parsed.manifests.include,
            vec![
                "warrant-sh/git".to_string(),
                "warrant-sh/coreutils".to_string()
            ]
        );
    }
}
