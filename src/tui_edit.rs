use std::io;
use std::path::Path;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

use crate::draft::{Draft, DraftDecision, build_capability_meta, read_draft, write_draft};
use crate::manifest::{Manifest, ManifestPackagePolicy, ManifestToolPolicy};

enum ScopePhase {
    SelectKey,
    EditValues,
}

struct ScopeEditState {
    phase: ScopePhase,
    keys: Vec<String>,
    selected_key: usize,
    input: String,
}

pub fn edit_draft_tui(draft_path: &Path, manifest: &Manifest) -> Result<(), String> {
    let mut draft = read_draft(draft_path).map_err(|err| err.to_string())?;
    draft.capability_meta = build_capability_meta(manifest);

    let mut capabilities = draft.capabilities.keys().cloned().collect::<Vec<_>>();
    capabilities.sort();
    if capabilities.is_empty() {
        return Err("draft contains no capabilities".to_string());
    }

    enable_raw_mode().map_err(|err| err.to_string())?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|err| err.to_string())?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|err| err.to_string())?;

    let mut selected = 0usize;
    let mut dirty = false;
    let mut quit_armed = false;
    let mut status = "Arrows/j/k move, <space> toggle, s scope edit, w save, q quit".to_string();
    let mut scope_edit: Option<ScopeEditState> = None;

    loop {
        terminal
            .draw(|frame| {
                render(
                    frame,
                    &draft,
                    &capabilities,
                    selected,
                    &status,
                    scope_edit.as_ref(),
                    &manifest.tool_policy,
                )
            })
            .map_err(|err| err.to_string())?;

        if !event::poll(Duration::from_millis(250)).map_err(|err| err.to_string())? {
            continue;
        }
        let Event::Key(key) = event::read().map_err(|err| err.to_string())? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if let Some(edit) = &mut scope_edit {
            match edit.phase {
                ScopePhase::SelectKey => match key.code {
                    KeyCode::Esc => {
                        scope_edit = None;
                        status = "Scope edit cancelled".to_string();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        edit.selected_key = edit.selected_key.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if edit.selected_key + 1 < edit.keys.len() {
                            edit.selected_key += 1;
                        }
                    }
                    KeyCode::Char(ch) if ch.is_ascii_digit() => {
                        if let Some(idx) = ch.to_digit(10) {
                            let idx = idx as usize;
                            if idx >= 1 && idx <= edit.keys.len() {
                                edit.selected_key = idx - 1;
                            }
                        }
                    }
                    KeyCode::Enter => {
                        let key = &edit.keys[edit.selected_key];
                        let capability = &capabilities[selected];
                        edit.input = draft
                            .capabilities
                            .get(capability)
                            .and_then(|entry| entry.scopes.get(key))
                            .map(|values| values.join(","))
                            .unwrap_or_default();
                        edit.phase = ScopePhase::EditValues;
                        status = format!("Editing scope '{key}'");
                    }
                    _ => {}
                },
                ScopePhase::EditValues => match key.code {
                    KeyCode::Esc => {
                        scope_edit = None;
                        status = "Scope edit cancelled".to_string();
                    }
                    KeyCode::Backspace => {
                        edit.input.pop();
                    }
                    KeyCode::Char(ch) => {
                        edit.input.push(ch);
                    }
                    KeyCode::Enter => {
                        let capability = &capabilities[selected];
                        let key = edit.keys[edit.selected_key].clone();
                        let raw = format!("{key}={}", edit.input.trim());
                        match apply_scope_assignment(&mut draft, capability, &raw, &edit.keys) {
                            Ok(msg) => {
                                dirty = true;
                                status = msg;
                                scope_edit = None;
                            }
                            Err(err) => {
                                status = err;
                            }
                        }
                    }
                    _ => {}
                },
            }
            continue;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                selected = selected.saturating_sub(1);
                quit_armed = false;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if selected + 1 < capabilities.len() {
                    selected += 1;
                }
                quit_armed = false;
            }
            KeyCode::Char(' ') => {
                let capability = &capabilities[selected];
                if let Some(entry) = draft.capabilities.get_mut(capability) {
                    entry.decision = cycle_decision(entry.decision);
                    dirty = true;
                    quit_armed = false;
                    status = format!(
                        "{capability} set to {}",
                        decision_text(entry.decision).to_uppercase()
                    );
                }
            }
            KeyCode::Char('s') => {
                let capability = &capabilities[selected];
                let allowed = draft
                    .capability_meta
                    .get(capability)
                    .map(|item| item.scope_keys.clone())
                    .unwrap_or_default();
                if allowed.is_empty() {
                    status = format!("No manifest scopes available for {capability}");
                } else if allowed.len() == 1 {
                    let key = allowed[0].clone();
                    let input = draft
                        .capabilities
                        .get(capability)
                        .and_then(|entry| entry.scopes.get(&key))
                        .map(|values| values.join(","))
                        .unwrap_or_default();
                    scope_edit = Some(ScopeEditState {
                        phase: ScopePhase::EditValues,
                        keys: allowed,
                        selected_key: 0,
                        input,
                    });
                    status = format!("Editing scope '{key}'");
                } else {
                    scope_edit = Some(ScopeEditState {
                        phase: ScopePhase::SelectKey,
                        keys: allowed,
                        selected_key: 0,
                        input: String::new(),
                    });
                    status =
                        "Scope editor: select a scope key, then enter values. Wildcards with * are supported."
                            .to_string();
                }
            }
            KeyCode::Char('w') => {
                write_draft(draft_path, &draft, false).map_err(|err| err.to_string())?;
                break;
            }
            KeyCode::Char('q') => {
                if dirty && !quit_armed {
                    quit_armed = true;
                    status = "Unsaved changes. Press q again to discard, or w to save.".to_string();
                } else {
                    break;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn risk_color(risk: Option<&str>) -> Color {
    match risk {
        Some("low") => Color::Green,
        Some("moderate") => Color::Yellow,
        Some("high") => Color::Red,
        Some("critical") => Color::Red,
        _ => Color::White,
    }
}

fn risk_style(risk: Option<&str>) -> Style {
    let color = risk_color(risk);
    let style = Style::default().fg(color);
    if risk == Some("critical") {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

fn render(
    frame: &mut Frame<'_>,
    draft: &Draft,
    capabilities: &[String],
    selected: usize,
    status: &str,
    scope_edit: Option<&ScopeEditState>,
    tool_policy: &ManifestToolPolicy,
) {
    let policy_lines = build_tool_policy_lines(tool_policy);
    let has_policy = !policy_lines.is_empty();
    let policy_height = (policy_lines.len() as u16 + 2).min(8);

    let chunks = if has_policy {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(9),
                Constraint::Length(policy_height),
                Constraint::Length(3),
            ])
            .split(frame.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10),
                Constraint::Length(9),
                Constraint::Length(3),
            ])
            .split(frame.area())
    };
    let help_area = chunks[1];
    let status_area = *chunks.last().unwrap();

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[0]);

    let mut list_state = ListState::default();
    list_state.select(Some(selected));

    let items = capabilities
        .iter()
        .map(|capability| {
            let decision = draft
                .capabilities
                .get(capability)
                .map(|entry| decision_text(entry.decision))
                .unwrap_or("review");
            let meta = draft.capability_meta.get(capability);
            let risk_text = meta.and_then(|m| m.risk.as_deref()).unwrap_or("");
            let label = meta
                .map(|m| m.label.as_str())
                .unwrap_or(capability.as_str());
            if risk_text.is_empty() {
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{label} ")),
                    Span::styled(format!("[{decision}]"), Style::default().fg(Color::Cyan)),
                ]))
            } else {
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{label} ")),
                    Span::styled(format!("[{decision}]"), Style::default().fg(Color::Cyan)),
                    Span::raw(" "),
                    Span::styled(format!("({risk_text})"), risk_style(Some(risk_text))),
                ]))
            }
        })
        .collect::<Vec<_>>();

    let list = List::new(items)
        .block(
            Block::default()
                .title("Capabilities")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    frame.render_stateful_widget(list, top[0], &mut list_state);

    let selected_capability = &capabilities[selected];
    let selected_entry = draft.capabilities.get(selected_capability);
    let cap_meta = draft.capability_meta.get(selected_capability);

    let mut detail_lines = Vec::<Line<'static>>::new();

    // Header: capability name + risk
    let risk_text = cap_meta.and_then(|m| m.risk.as_deref());
    let mut header_spans = vec![Span::styled(
        selected_capability.clone(),
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if let Some(risk) = risk_text {
        header_spans.push(Span::raw("  "));
        header_spans.push(Span::styled(format!("{risk} risk"), risk_style(Some(risk))));
    }
    detail_lines.push(Line::from(header_spans));

    // Decision
    detail_lines.push(Line::from(format!(
        "Decision: {}",
        selected_entry
            .map(|entry| decision_text(entry.decision).to_uppercase())
            .unwrap_or_else(|| "REVIEW".to_string())
    )));
    detail_lines.push(Line::from(""));

    // Description
    if let Some(meta) = cap_meta {
        if let Some(desc) = &meta.description {
            detail_lines.push(Line::from(desc.clone()));
        }
        if let Some(example) = &meta.command_example {
            detail_lines.push(Line::from(Span::styled(
                format!("Example: {example}"),
                Style::default().fg(Color::DarkGray),
            )));
        }

        // Scopes
        if !meta.scope_keys.is_empty() {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(Span::styled(
                "Scopes:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for key in &meta.scope_keys {
                let desc = meta
                    .scope_descriptions
                    .get(key)
                    .map(|d| d.as_str())
                    .unwrap_or("");
                let examples = meta.scope_examples.get(key);
                let examples_str = examples
                    .filter(|v| !v.is_empty())
                    .map(|v| format!(" (e.g. {})", v.join(", ")));
                if desc.is_empty() {
                    detail_lines.push(Line::from(format!(
                        "  {key}{}",
                        examples_str.unwrap_or_default()
                    )));
                } else {
                    detail_lines.push(Line::from(format!(
                        "  {key} - {desc}{}",
                        examples_str.unwrap_or_default()
                    )));
                }
            }
        }
    }

    // Current scope values
    detail_lines.push(Line::from(""));
    if let Some(entry) = selected_entry {
        if entry.scopes.is_empty() {
            detail_lines.push(Line::from("Current scopes: <none set>"));
        } else {
            detail_lines.push(Line::from("Current scopes:"));
            for (key, values) in &entry.scopes {
                detail_lines.push(Line::from(format!("  {key} = {}", values.join(", "))));
            }
        }
    }

    let details = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title("Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(details, top[1]);

    let help = Paragraph::new(vec![
        Line::from("Controls:"),
        Line::from("  Up/Down or j/k: move"),
        Line::from("  Space: cycle decision allow -> deny -> review"),
        Line::from("  s: open scope editor"),
        Line::from("  w: save and exit"),
        Line::from("  q: quit (double q if unsaved)"),
    ])
    .block(
        Block::default()
            .title("Help")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );
    frame.render_widget(help, help_area);

    if has_policy {
        let policy_widget = Paragraph::new(policy_lines)
            .block(
                Block::default()
                    .title("Tool Policy")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Magenta)),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(policy_widget, chunks[2]);
    }

    let status_text = if let Some(edit) = scope_edit {
        match edit.phase {
            ScopePhase::SelectKey => {
                format!("Pick scope: {}", edit.keys.join(", "))
            }
            ScopePhase::EditValues => {
                let key = &edit.keys[edit.selected_key];
                let examples = cap_meta
                    .and_then(|m| m.scope_examples.get(key))
                    .cloned()
                    .unwrap_or_default();
                let examples_hint = if examples.is_empty() {
                    "no examples from manifest".to_string()
                } else {
                    format!("examples: {}", examples.join(", "))
                };
                format!(
                    "Scope '{key}': {}  ({examples_hint}; comma-separated; supports * wildcard; Enter=apply, Esc=cancel)",
                    edit.input,
                )
            }
        }
    } else {
        status.to_string()
    };
    let status_widget = Paragraph::new(status_text).block(
        Block::default()
            .title("Status")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(status_widget, status_area);

    if let Some(edit) = scope_edit {
        let mut overlay = centered_rect(70, 35, frame.area());
        if overlay.height > 2 {
            overlay.y += 1;
            overlay.height -= 2;
        }
        frame.render_widget(Clear, overlay);

        let lines = match edit.phase {
            ScopePhase::SelectKey => {
                let mut lines = vec![
                    Line::from(Span::styled(
                        "Select Scope Key",
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
                    Line::from("Use Up/Down or 1-9, Enter to continue, Esc to cancel"),
                    Line::from(""),
                ];
                for (idx, key) in edit.keys.iter().enumerate() {
                    let desc = cap_meta
                        .and_then(|m| m.scope_descriptions.get(key))
                        .map(|d| format!(" - {d}"))
                        .unwrap_or_default();
                    if idx == edit.selected_key {
                        lines.push(Line::from(format!("> {}. {key}{desc}", idx + 1)));
                    } else {
                        lines.push(Line::from(format!("  {}. {key}{desc}", idx + 1)));
                    }
                }
                lines
            }
            ScopePhase::EditValues => {
                let key = &edit.keys[edit.selected_key];
                let examples = cap_meta
                    .and_then(|m| m.scope_examples.get(key))
                    .cloned()
                    .unwrap_or_default();
                let desc = cap_meta
                    .and_then(|m| m.scope_descriptions.get(key))
                    .cloned()
                    .unwrap_or_default();
                let examples_hint = if examples.is_empty() {
                    "<none provided>".to_string()
                } else {
                    examples.join(", ")
                };
                let mut modal_lines = vec![Line::from(Span::styled(
                    format!("Edit Scope: {key}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ))];
                if !desc.is_empty() {
                    modal_lines.push(Line::from(desc));
                }
                modal_lines.extend([
                    Line::from("Comma-separated values; * wildcard is supported"),
                    Line::from(format!("Examples: {examples_hint}")),
                    Line::from("Empty input removes this scope key"),
                    Line::from("Enter to apply, Esc to cancel"),
                    Line::from(""),
                    Line::from(format!("Value: {}", edit.input)),
                ]);
                modal_lines
            }
        };

        let modal = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::default()
                .title("Scope Editor")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        );
        frame.render_widget(modal, overlay);
    }
}

fn build_tool_policy_lines(policy: &ManifestToolPolicy) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    if !policy.deny_flags.is_empty() {
        let desc = policy
            .deny_flags_description
            .as_deref()
            .unwrap_or("Denied flags");
        lines.push(Line::from(Span::styled(
            format!("{desc}:"),
            Style::default().fg(Color::Red),
        )));
        for flag in &policy.deny_flags {
            lines.push(Line::from(Span::styled(
                format!("  {flag}"),
                Style::default().fg(Color::Red),
            )));
        }
    }

    if !policy.strip_env.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("Strip env: {}", policy.strip_env.join(", ")),
            Style::default().fg(Color::Yellow),
        )));
    }

    if policy.allow_inline_execution {
        lines.push(Line::from(Span::styled(
            "Inline execution: allowed".to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
    }

    if policy.package_policy != ManifestPackagePolicy::Open {
        let policy_name = match policy.package_policy {
            ManifestPackagePolicy::Denylist => "denylist",
            ManifestPackagePolicy::Allowlist => "allowlist",
            ManifestPackagePolicy::Open => unreachable!(),
        };
        let eco = policy.package_ecosystem.as_deref().unwrap_or("unknown");
        lines.push(Line::from(Span::styled(
            format!("Packages: {policy_name} ({eco})"),
            Style::default().fg(Color::Cyan),
        )));
    }

    if !policy.paths.is_empty() {
        lines.push(Line::from(format!("Paths: {}", policy.paths.join(", "))));
    }

    lines
}

fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    area: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1]);
    horizontal[1]
}

fn apply_scope_assignment(
    draft: &mut Draft,
    capability: &str,
    raw: &str,
    allowed_scope_keys: &[String],
) -> Result<String, String> {
    let (key_raw, values_raw) = raw
        .split_once('=')
        .ok_or_else(|| "invalid scope input. use key=value1,value2".to_string())?;
    let key = key_raw.trim();
    if key.is_empty() {
        return Err("scope key cannot be empty".to_string());
    }
    if !allowed_scope_keys.iter().any(|k| k == key) {
        return Err(format!(
            "unknown scope key '{key}'. available: {}",
            allowed_scope_keys.join(", ")
        ));
    }

    let entry = draft
        .capabilities
        .get_mut(capability)
        .ok_or_else(|| format!("capability '{capability}' not found in draft"))?;

    let values_raw = values_raw.trim();
    if values_raw.is_empty() {
        entry.scopes.remove(key);
        return Ok(format!("Removed scope '{key}' from {capability}"));
    }

    let values = values_raw
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err("scope values cannot be empty".to_string());
    }
    entry.scopes.insert(key.to_string(), values.clone());
    Ok(format!(
        "Set scope '{key}' for {capability} to {}",
        values.join(", ")
    ))
}

fn decision_text(decision: DraftDecision) -> &'static str {
    match decision {
        DraftDecision::Allow => "allow",
        DraftDecision::Deny => "deny",
        DraftDecision::Review => "review",
    }
}

fn cycle_decision(decision: DraftDecision) -> DraftDecision {
    match decision {
        DraftDecision::Allow => DraftDecision::Deny,
        DraftDecision::Deny => DraftDecision::Review,
        DraftDecision::Review => DraftDecision::Allow,
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::draft::{Draft, DraftCapability, DraftDecision, DraftMeta, DraftMetadata};

    use super::{apply_scope_assignment, cycle_decision};

    fn sample_draft() -> Draft {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            "git.push".to_string(),
            DraftCapability {
                decision: DraftDecision::Review,
                scopes: BTreeMap::new(),
            },
        );
        Draft {
            draft: DraftMeta {
                schema: "warrant.draft.v1".to_string(),
                manifest: "official/git@1.0.0".to_string(),
                manifest_hash: String::new(),
                tool: "git".to_string(),
                state: "editable".to_string(),
            },
            capabilities,
            metadata: DraftMetadata::default(),
            capability_meta: BTreeMap::new(),
        }
    }

    #[test]
    fn cycle_decision_rotates_all_states() {
        assert_eq!(cycle_decision(DraftDecision::Allow), DraftDecision::Deny);
        assert_eq!(cycle_decision(DraftDecision::Deny), DraftDecision::Review);
        assert_eq!(cycle_decision(DraftDecision::Review), DraftDecision::Allow);
    }

    #[test]
    fn apply_scope_assignment_sets_values() {
        let mut draft = sample_draft();
        let msg = apply_scope_assignment(
            &mut draft,
            "git.push",
            "remote=origin,upstream",
            &["remote".to_string(), "branch".to_string()],
        )
        .expect("set should succeed");
        assert!(msg.contains("Set scope 'remote'"));
        let push = draft
            .capabilities
            .get("git.push")
            .expect("capability exists");
        assert_eq!(
            push.scopes.get("remote"),
            Some(&vec!["origin".to_string(), "upstream".to_string()])
        );
    }

    #[test]
    fn apply_scope_assignment_removes_values_with_empty_rhs() {
        let mut draft = sample_draft();
        {
            let push = draft
                .capabilities
                .get_mut("git.push")
                .expect("capability exists");
            push.scopes
                .insert("remote".to_string(), vec!["origin".to_string()]);
        }

        let msg = apply_scope_assignment(
            &mut draft,
            "git.push",
            "remote=",
            &["remote".to_string(), "branch".to_string()],
        )
        .expect("remove should succeed");
        assert!(msg.contains("Removed scope 'remote'"));
        let push = draft
            .capabilities
            .get("git.push")
            .expect("capability exists");
        assert!(!push.scopes.contains_key("remote"));
    }

    #[test]
    fn apply_scope_assignment_rejects_unknown_scope_key() {
        let mut draft = sample_draft();
        let err = apply_scope_assignment(
            &mut draft,
            "git.push",
            "not_allowed=main",
            &["remote".to_string(), "branch".to_string()],
        )
        .expect_err("unknown key should fail");
        assert!(err.contains("unknown scope key"));
    }

    #[test]
    fn apply_scope_assignment_rejects_invalid_format() {
        let mut draft = sample_draft();
        let err = apply_scope_assignment(
            &mut draft,
            "git.push",
            "remote",
            &["remote".to_string(), "branch".to_string()],
        )
        .expect_err("missing = should fail");
        assert!(err.contains("invalid scope input"));
    }
}
