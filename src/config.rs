use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub loops: LoopConfig,
    pub budget: BudgetConfig,
    pub shell: ShellConfig,
    pub pricing: Vec<ModelPrice>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoopConfig {
    /// Identical calls (same tool and input) allowed with no file edit in between.
    pub max_identical_calls: u32,
    /// How many recent calls are remembered for identical-call detection.
    pub window: u32,
    /// Failures of the same call in a row, with no file edit in between.
    pub max_consecutive_failures: u32,
    /// Failures of the same call across the whole session, edits or not.
    pub max_total_failures_per_call: u32,
    /// Consecutive brakeline denials before the whole run is stopped.
    pub max_denials_before_stop: u32,
    /// Tools whose successful use counts as progress (resets loop counters).
    pub progress_tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BudgetConfig {
    pub max_tool_calls: Option<u64>,
    pub max_session_minutes: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub max_output_tokens: Option<u64>,
    /// Factory credits, as reported by Droid for the session.
    pub max_factory_credits: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShellConfig {
    pub block_catastrophic: bool,
    pub block_force_push: bool,
    pub snapshot_before_destructive: bool,
    /// Extra substrings that make a shell command blocked outright.
    pub blocked_substrings: Vec<String>,
}

/// Prices in USD per million tokens. The first entry whose `model_contains`
/// is a substring of the model name wins; an empty match string is a fallback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPrice {
    pub model_contains: String,
    pub input: f64,
    pub output: f64,
    pub cache_write: f64,
    pub cache_read: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            loops: LoopConfig::default(),
            budget: BudgetConfig::default(),
            shell: ShellConfig::default(),
            pricing: default_pricing(),
        }
    }
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            max_identical_calls: 5,
            window: 40,
            max_consecutive_failures: 3,
            max_total_failures_per_call: 12,
            max_denials_before_stop: 3,
            progress_tools: [
                "Edit",
                "Write",
                "MultiEdit",
                "NotebookEdit",
                "Create",
                "ApplyPatch",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_tool_calls: Some(800),
            max_session_minutes: Some(8 * 60),
            max_cost_usd: Some(50.0),
            max_output_tokens: None,
            max_factory_credits: None,
        }
    }
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            block_catastrophic: true,
            block_force_push: true,
            snapshot_before_destructive: true,
            blocked_substrings: Vec::new(),
        }
    }
}

fn price(model: &str, input: f64, output: f64, cache_write: f64, cache_read: f64) -> ModelPrice {
    ModelPrice {
        model_contains: model.to_string(),
        input,
        output,
        cache_write,
        cache_read,
    }
}

/// Published list prices at the time of writing. Users should verify and
/// override these in config; they only drive the cost estimate.
pub fn default_pricing() -> Vec<ModelPrice> {
    vec![
        price("opus", 5.0, 25.0, 6.25, 0.50),
        price("sonnet", 3.0, 15.0, 3.75, 0.30),
        price("haiku", 1.0, 5.0, 1.25, 0.10),
        price("", 3.0, 15.0, 3.75, 0.30),
    ]
}

impl Config {
    pub fn price_for(&self, model: &str) -> Option<&ModelPrice> {
        let model = model.to_ascii_lowercase();
        self.pricing
            .iter()
            .find(|p| model.contains(&p.model_contains.to_ascii_lowercase()))
    }

    /// Apply a project-level config on top of the user config. A repository
    /// is untrusted input, so it may only make limits stricter, never looser.
    pub fn tighten_with(&mut self, project: &ProjectConfig) {
        let l = &mut self.loops;
        let p = &project.loops;
        // Floors keep a hostile repo from making every session unusable.
        min_into(&mut l.max_identical_calls, p.max_identical_calls, 3);
        if let Some(w) = p.window {
            l.window = l.window.max(w.min(MAX_PROJECT_WINDOW));
        }
        min_into(
            &mut l.max_consecutive_failures,
            p.max_consecutive_failures,
            2,
        );
        min_into(
            &mut l.max_total_failures_per_call,
            p.max_total_failures_per_call,
            3,
        );
        min_into(&mut l.max_denials_before_stop, p.max_denials_before_stop, 2);

        let b = &mut self.budget;
        let pb = &project.budget;
        b.max_tool_calls = min_opt(b.max_tool_calls, pb.max_tool_calls.filter(|v| *v > 0));
        b.max_session_minutes = min_opt(
            b.max_session_minutes,
            pb.max_session_minutes.filter(|v| *v > 0),
        );
        b.max_output_tokens = min_opt(b.max_output_tokens, pb.max_output_tokens.filter(|v| *v > 0));
        b.max_factory_credits = min_opt(
            b.max_factory_credits,
            pb.max_factory_credits.filter(|v| *v > 0),
        );
        b.max_cost_usd = match (b.max_cost_usd, pb.max_cost_usd.filter(|c| *c > 0.0)) {
            (Some(a), Some(c)) => Some(a.min(c)),
            (a, c) => a.or(c),
        };

        let s = &mut self.shell;
        let ps = &project.shell;
        s.block_catastrophic |= ps.block_catastrophic.unwrap_or(false);
        s.block_force_push |= ps.block_force_push.unwrap_or(false);
        s.snapshot_before_destructive |= ps.snapshot_before_destructive.unwrap_or(false);
        for extra in &ps.blocked_substrings {
            // Very short patterns ("e") would block nearly every command.
            if extra.trim().len() >= MIN_PROJECT_PATTERN && !s.blocked_substrings.contains(extra) {
                s.blocked_substrings.push(extra.clone());
            }
        }
        // Pricing stays user-controlled: a repo must not be able to make spend look cheaper.
    }

    /// A budget of 0 in the user config means "no limit".
    fn normalize(&mut self) {
        let b = &mut self.budget;
        b.max_tool_calls = b.max_tool_calls.filter(|v| *v > 0);
        b.max_session_minutes = b.max_session_minutes.filter(|v| *v > 0);
        b.max_output_tokens = b.max_output_tokens.filter(|v| *v > 0);
        b.max_factory_credits = b.max_factory_credits.filter(|v| *v > 0);
        b.max_cost_usd = b.max_cost_usd.filter(|v| *v > 0.0);
        self.shell
            .blocked_substrings
            .retain(|s| !s.trim().is_empty());
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.loops.window >= 2, "loops.window must be at least 2");
        anyhow::ensure!(
            self.loops.max_identical_calls >= 2,
            "loops.max_identical_calls must be at least 2"
        );
        anyhow::ensure!(
            self.loops.max_consecutive_failures >= 1 && self.loops.max_total_failures_per_call >= 1,
            "failure limits must be at least 1"
        );
        anyhow::ensure!(
            self.loops.max_denials_before_stop >= 1,
            "loops.max_denials_before_stop must be at least 1"
        );
        if let Some(cost) = self.budget.max_cost_usd {
            anyhow::ensure!(
                cost.is_finite() && cost >= 0.0,
                "budget.max_cost_usd must be a non-negative number"
            );
        }
        for p in &self.pricing {
            for v in [p.input, p.output, p.cache_write, p.cache_read] {
                anyhow::ensure!(
                    v.is_finite() && v >= 0.0,
                    "prices must be non-negative numbers"
                );
            }
        }
        Ok(())
    }
}

/// Project-level settings. Every field is optional so that only values the
/// project actually states are applied (and only ever to tighten).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectConfig {
    pub loops: ProjectLoops,
    pub budget: ProjectBudget,
    pub shell: ProjectShell,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectLoops {
    pub max_identical_calls: Option<u32>,
    pub window: Option<u32>,
    pub max_consecutive_failures: Option<u32>,
    pub max_total_failures_per_call: Option<u32>,
    pub max_denials_before_stop: Option<u32>,
}

const MAX_PROJECT_WINDOW: u32 = 500;
const MIN_PROJECT_PATTERN: usize = 4;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectBudget {
    pub max_tool_calls: Option<u64>,
    pub max_session_minutes: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub max_output_tokens: Option<u64>,
    pub max_factory_credits: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectShell {
    pub block_catastrophic: Option<bool>,
    pub block_force_push: Option<bool>,
    pub snapshot_before_destructive: Option<bool>,
    pub blocked_substrings: Vec<String>,
}

fn min_into(target: &mut u32, candidate: Option<u32>, floor: u32) {
    if let Some(v) = candidate {
        *target = (*target).min(v.max(floor));
    }
}

fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

pub fn user_config_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("BRAKELINE_CONFIG").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(path));
    }
    home_dir().map(|h| h.join(".config").join("brakeline").join("config.toml"))
}

pub fn project_config_path(cwd: &Path) -> PathBuf {
    cwd.join(".brakeline.toml")
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .map(Some)
            .with_context(|| format!("invalid config {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

pub fn load_user() -> Result<Config> {
    let Some(path) = user_config_path() else {
        return Ok(Config::default());
    };
    let mut cfg: Config = read_toml(&path)?.unwrap_or_default();
    cfg.validate()
        .with_context(|| format!("invalid config {}", path.display()))?;
    cfg.normalize();
    Ok(cfg)
}

/// Loads the user config (or defaults) and tightens it with the project config.
pub fn load(cwd: Option<&Path>) -> Result<Config> {
    let mut cfg = load_user()?;
    if let Some(cwd) = cwd
        && let Some(project) = read_toml::<ProjectConfig>(&project_config_path(cwd))?
    {
        cfg.tighten_with(&project);
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_config_cannot_loosen_limits() {
        let mut user = Config::default();
        let project: ProjectConfig = toml::from_str(
            r#"
            [loops]
            max_identical_calls = 50
            max_consecutive_failures = 2
            [budget]
            max_cost_usd = 1000.0
            max_tool_calls = 100
            [shell]
            block_catastrophic = false
            blocked_substrings = ["terraform destroy"]
            "#,
        )
        .unwrap();
        user.tighten_with(&project);
        assert_eq!(user.loops.max_identical_calls, 5);
        assert_eq!(user.loops.max_consecutive_failures, 2);
        assert_eq!(user.budget.max_cost_usd, Some(50.0));
        assert_eq!(user.budget.max_tool_calls, Some(100));
        assert!(user.shell.block_catastrophic);
        assert_eq!(user.shell.blocked_substrings, vec!["terraform destroy"]);
    }

    #[test]
    fn project_can_add_a_budget_the_user_left_unset() {
        let mut user = Config::default();
        user.budget.max_output_tokens = None;
        let project: ProjectConfig =
            toml::from_str("[budget]\nmax_output_tokens = 10000\n").unwrap();
        user.tighten_with(&project);
        assert_eq!(user.budget.max_output_tokens, Some(10_000));
    }

    #[test]
    fn fields_a_project_omits_leave_user_settings_alone() {
        let mut user = Config::default();
        user.loops.max_identical_calls = 9;
        user.budget.max_cost_usd = Some(80.0);
        let project: ProjectConfig = toml::from_str("[budget]\nmax_tool_calls = 50\n").unwrap();
        user.tighten_with(&project);
        assert_eq!(user.loops.max_identical_calls, 9);
        assert_eq!(user.budget.max_cost_usd, Some(80.0));
        assert_eq!(user.budget.max_tool_calls, Some(50));
    }

    #[test]
    fn project_zero_never_disables_a_limit() {
        let mut user = Config::default();
        let project: ProjectConfig =
            toml::from_str("[loops]\nmax_identical_calls = 0\n[budget]\nmax_cost_usd = 0.0\n")
                .unwrap();
        user.tighten_with(&project);
        assert_eq!(user.loops.max_identical_calls, 3, "clamped to the floor");
        assert_eq!(user.budget.max_cost_usd, Some(50.0));
    }

    #[test]
    fn hostile_project_cannot_wedge_sessions() {
        let mut user = Config::default();
        let project: ProjectConfig = toml::from_str(
            "[loops]\nmax_denials_before_stop = 1\nmax_consecutive_failures = 1\nwindow = 4000000000\n\
             [shell]\nblocked_substrings = [\"e\", \" rm \", \"terraform destroy\"]\n",
        )
        .unwrap();
        user.tighten_with(&project);
        assert_eq!(user.loops.max_denials_before_stop, 2);
        assert_eq!(user.loops.max_consecutive_failures, 2);
        assert_eq!(user.loops.window, MAX_PROJECT_WINDOW);
        assert_eq!(user.shell.blocked_substrings, vec!["terraform destroy"]);
    }

    #[test]
    fn project_cannot_set_pricing_or_progress_tools() {
        assert!(toml::from_str::<ProjectConfig>("[[pricing]]\nmodel_contains = \"\"\n").is_err());
        assert!(toml::from_str::<ProjectConfig>("[loops]\nprogress_tools = []\n").is_err());
    }

    #[test]
    fn price_lookup_falls_back() {
        let cfg = Config::default();
        assert_eq!(cfg.price_for("claude-opus-5").unwrap().output, 25.0);
        assert_eq!(cfg.price_for("some-new-model").unwrap().model_contains, "");
    }

    #[test]
    fn example_config_matches_defaults() {
        let text = include_str!("../examples/config.toml");
        let cfg: Config = toml::from_str(text).unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(toml::from_str::<Config>("[budget]\nmax_dollars = 3\n").is_err());
    }
}
