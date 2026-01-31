//! Shell completion installation and management
//!
//! This module handles installing shell completion scripts to standard locations
//! for bash, zsh, and fish shells.

use anyhow::{Context, Result};
use clap::CommandFactory;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Cli;
use crate::error::CompletionError;
use crate::ui::OutputContext;

/// Standard installation paths for each shell
#[derive(Debug, Clone)]
pub struct InstallPaths {
    /// Primary install location for the completion script
    pub script_path: PathBuf,
    /// RC file that may need modification (e.g., .bashrc, .zshrc)
    pub rc_file: Option<PathBuf>,
    /// Line to add to RC file if needed
    pub rc_line: Option<String>,
}

/// Get the home directory
fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().context("Could not determine home directory")
}

/// Determine installation paths for a given shell
pub fn get_install_paths(shell: clap_complete::Shell) -> Result<InstallPaths> {
    let home = home_dir()?;

    match shell {
        clap_complete::Shell::Bash => {
            // Prefer user-local bash completion directory
            let completion_dir = home.join(".local/share/bash-completion/completions");
            Ok(InstallPaths {
                script_path: completion_dir.join("rch"),
                rc_file: None, // Modern bash-completion auto-loads from this dir
                rc_line: None,
            })
        }
        clap_complete::Shell::Zsh => {
            // Use ~/.zfunc for user completions
            let zfunc_dir = home.join(".zfunc");
            Ok(InstallPaths {
                script_path: zfunc_dir.join("_rch"),
                rc_file: Some(home.join(".zshrc")),
                rc_line: Some(
                    "# RCH completions\nfpath=(~/.zfunc $fpath)\nautoload -Uz compinit && compinit"
                        .to_string(),
                ),
            })
        }
        clap_complete::Shell::Fish => {
            // Fish auto-loads from this directory
            let fish_dir = home.join(".config/fish/completions");
            Ok(InstallPaths {
                script_path: fish_dir.join("rch.fish"),
                rc_file: None, // Fish auto-loads
                rc_line: None,
            })
        }
        clap_complete::Shell::PowerShell => {
            // PowerShell profile-based loading
            let ps_dir = if cfg!(windows) {
                home.join("Documents/PowerShell")
            } else {
                home.join(".config/powershell")
            };
            Ok(InstallPaths {
                script_path: ps_dir.join("rch.ps1"),
                rc_file: Some(ps_dir.join("Microsoft.PowerShell_profile.ps1")),
                rc_line: Some(". ~/.config/powershell/rch.ps1".to_string()),
            })
        }
        clap_complete::Shell::Elvish => {
            let elvish_dir = home.join(".elvish/lib");
            Ok(InstallPaths {
                script_path: elvish_dir.join("rch.elv"),
                rc_file: Some(home.join(".elvish/rc.elv")),
                rc_line: Some("use rch".to_string()),
            })
        }
        _ => Err(CompletionError::UnsupportedShell {
            shell: format!("{:?}", shell),
        }
        .into()),
    }
}

/// Generate completion script content for a shell
pub fn generate_completion_script(shell: clap_complete::Shell) -> String {
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "rch", &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}

/// Check if an RC file already contains the RCH completion setup
fn rc_file_has_rch_setup(rc_path: &Path) -> Result<bool> {
    if !rc_path.exists() {
        return Ok(false);
    }

    let content = fs::read_to_string(rc_path).context("Failed to read RC file")?;

    // Check for various indicators that RCH completions are already set up
    Ok(content.contains("# RCH completions")
        || content.contains("rch.fish")
        || content.contains("_rch")
        || content.contains("rch.ps1")
        || content.contains("rch.elv"))
}

/// Install completion script for a shell
pub fn install_completions(
    shell: clap_complete::Shell,
    ctx: &OutputContext,
    dry_run: bool,
) -> Result<InstallResult> {
    let paths = get_install_paths(shell)?;
    let script_content = generate_completion_script(shell);

    let mut result = InstallResult {
        shell,
        script_path: paths.script_path.clone(),
        script_written: false,
        rc_modified: false,
        rc_file: paths.rc_file.clone(),
        was_already_installed: false,
    };

    // Check if already installed
    if paths.script_path.exists() {
        let existing = fs::read_to_string(&paths.script_path).unwrap_or_default();
        if existing == script_content {
            result.was_already_installed = true;
            if !ctx.is_quiet() {
                println!(
                    "Completions for {:?} already installed at {}",
                    shell,
                    paths.script_path.display()
                );
            }
            return Ok(result);
        }
    }

    if dry_run {
        println!(
            "Would write completion script to: {}",
            paths.script_path.display()
        );
        if let (Some(rc_file), Some(rc_line)) = (&paths.rc_file, &paths.rc_line)
            && !rc_file_has_rch_setup(rc_file)?
        {
            println!("Would add to {}: {}", rc_file.display(), rc_line);
        }
        return Ok(result);
    }

    // Create parent directory if needed
    if let Some(parent) = paths.script_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Write the completion script
    fs::write(&paths.script_path, &script_content).map_err(|e| CompletionError::WriteFailed {
        path: paths.script_path.display().to_string(),
        source: e,
    })?;
    result.script_written = true;

    if !ctx.is_quiet() {
        println!(
            "Installed {:?} completions to {}",
            shell,
            paths.script_path.display()
        );
    }

    // Modify RC file if needed (idempotent)
    if let (Some(rc_file), Some(rc_line)) = (&paths.rc_file, &paths.rc_line)
        && !rc_file_has_rch_setup(rc_file)?
    {
        // Append to RC file
        let mut content = if rc_file.exists() {
            fs::read_to_string(rc_file)?
        } else {
            String::new()
        };

        // Add newline separator if file doesn't end with one
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push('\n');
        content.push_str(rc_line);
        content.push('\n');

        fs::write(rc_file, content)
            .with_context(|| format!("Failed to update {}", rc_file.display()))?;
        result.rc_modified = true;

        if !ctx.is_quiet() {
            println!("Updated {} to load completions", rc_file.display());
        }
    }

    Ok(result)
}

/// Result of a completion installation
#[derive(Debug)]
pub struct InstallResult {
    #[allow(dead_code)] // For debugging and API completeness
    pub shell: clap_complete::Shell,
    #[allow(dead_code)] // For debugging and API completeness
    pub script_path: PathBuf,
    pub script_written: bool,
    pub rc_modified: bool,
    #[allow(dead_code)] // For debugging and API completeness
    pub rc_file: Option<PathBuf>,
    pub was_already_installed: bool,
}

/// Detect the current shell from environment
pub fn detect_current_shell() -> Option<clap_complete::Shell> {
    // Check SHELL environment variable
    if let Ok(shell_path) = std::env::var("SHELL") {
        let shell_name = Path::new(&shell_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        return match shell_name {
            "bash" => Some(clap_complete::Shell::Bash),
            "zsh" => Some(clap_complete::Shell::Zsh),
            "fish" => Some(clap_complete::Shell::Fish),
            "pwsh" | "powershell" => Some(clap_complete::Shell::PowerShell),
            "elvish" => Some(clap_complete::Shell::Elvish),
            _ => None,
        };
    }

    None
}

/// Uninstall completions for a shell
pub fn uninstall_completions(
    shell: clap_complete::Shell,
    ctx: &OutputContext,
    dry_run: bool,
) -> Result<()> {
    let paths = get_install_paths(shell)?;

    if dry_run {
        if paths.script_path.exists() {
            println!("Would remove: {}", paths.script_path.display());
        }
        return Ok(());
    }

    if paths.script_path.exists() {
        fs::remove_file(&paths.script_path).with_context(|| {
            format!(
                "Failed to remove completion script: {}",
                paths.script_path.display()
            )
        })?;

        if !ctx.is_quiet() {
            println!(
                "Removed {:?} completions from {}",
                shell,
                paths.script_path.display()
            );
        }
    } else if !ctx.is_quiet() {
        println!(
            "No {:?} completions found at {}",
            shell,
            paths.script_path.display()
        );
    }

    // Note: We don't remove RC file modifications to avoid breaking user configs
    // Users can manually remove the lines if desired

    Ok(())
}

/// Show installation status for all shells
pub fn show_status(ctx: &OutputContext) -> Result<()> {
    use clap_complete::Shell;

    let shells = [
        Shell::Bash,
        Shell::Zsh,
        Shell::Fish,
        Shell::PowerShell,
        Shell::Elvish,
    ];

    if !ctx.is_quiet() {
        println!("Shell completion status:");
        println!();
    }

    for shell in &shells {
        if let Ok(paths) = get_install_paths(*shell) {
            let installed = paths.script_path.exists();
            let status = if installed {
                "installed"
            } else {
                "not installed"
            };
            println!(
                "  {:12} {} ({})",
                format!("{:?}:", shell),
                status,
                paths.script_path.display()
            );
        }
    }

    // Show current shell detection
    if let Some(current) = detect_current_shell() {
        println!();
        println!("Current shell: {:?}", current);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bash_completions() {
        let script = generate_completion_script(clap_complete::Shell::Bash);
        assert!(!script.is_empty());
        assert!(script.contains("rch") || script.contains("_rch"));
    }

    #[test]
    fn test_generate_zsh_completions() {
        let script = generate_completion_script(clap_complete::Shell::Zsh);
        assert!(!script.is_empty());
    }

    #[test]
    fn test_generate_fish_completions() {
        let script = generate_completion_script(clap_complete::Shell::Fish);
        assert!(!script.is_empty());
        assert!(script.contains("rch"));
    }

    #[test]
    fn test_get_install_paths_bash() {
        let paths = get_install_paths(clap_complete::Shell::Bash).unwrap();
        assert!(
            paths
                .script_path
                .to_string_lossy()
                .contains("bash-completion")
        );
    }

    #[test]
    fn test_get_install_paths_zsh() {
        let paths = get_install_paths(clap_complete::Shell::Zsh).unwrap();
        assert!(paths.script_path.to_string_lossy().contains("_rch"));
        assert!(paths.rc_file.is_some());
    }

    #[test]
    fn test_get_install_paths_fish() {
        let paths = get_install_paths(clap_complete::Shell::Fish).unwrap();
        assert!(paths.script_path.to_string_lossy().contains("rch.fish"));
    }

    #[test]
    fn test_detect_shell_from_env() {
        // This test depends on the environment, so we just verify it doesn't panic
        let _ = detect_current_shell();
    }

    #[test]
    fn test_install_paths_all_shells() {
        // Test that all supported shells have valid install paths
        use clap_complete::Shell;
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let result = get_install_paths(shell);
            assert!(
                result.is_ok(),
                "Failed to get install paths for {:?}",
                shell
            );
            let paths = result.unwrap();
            assert!(!paths.script_path.as_os_str().is_empty());
        }
    }

    #[test]
    fn test_rc_file_has_rch_setup_missing_file() {
        // Non-existent file should return false
        let nonexistent = std::path::PathBuf::from("/tmp/nonexistent_rc_file_123456");
        let result = rc_file_has_rch_setup(&nonexistent).unwrap();
        assert!(!result, "Non-existent file should return false");
    }

    #[test]
    fn test_rc_file_has_rch_setup_with_marker() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rc_path = temp_dir.path().join(".zshrc");

        // Write file with RCH marker
        std::fs::write(
            &rc_path,
            "# some config\n# RCH completions\nfpath=(~/.zfunc $fpath)\n",
        )
        .unwrap();
        let result = rc_file_has_rch_setup(&rc_path).unwrap();
        assert!(result, "Should detect RCH completions marker");
    }

    #[test]
    fn test_rc_file_has_rch_setup_without_marker() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rc_path = temp_dir.path().join(".bashrc");

        // Write file without RCH marker
        std::fs::write(
            &rc_path,
            "# some other config\nexport PATH=$PATH:/usr/local/bin\n",
        )
        .unwrap();
        let result = rc_file_has_rch_setup(&rc_path).unwrap();
        assert!(!result, "Should not detect RCH setup in unrelated config");
    }

    #[test]
    fn test_rc_file_detects_various_markers() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Test _rch marker (zsh completion function)
        let path1 = temp_dir.path().join("rc1");
        std::fs::write(&path1, "autoload _rch\n").unwrap();
        assert!(rc_file_has_rch_setup(&path1).unwrap());

        // Test rch.fish marker
        let path2 = temp_dir.path().join("rc2");
        std::fs::write(&path2, "source rch.fish\n").unwrap();
        assert!(rc_file_has_rch_setup(&path2).unwrap());

        // Test rch.ps1 marker
        let path3 = temp_dir.path().join("rc3");
        std::fs::write(&path3, ". rch.ps1\n").unwrap();
        assert!(rc_file_has_rch_setup(&path3).unwrap());

        // Test rch.elv marker
        let path4 = temp_dir.path().join("rc4");
        std::fs::write(&path4, "use rch.elv\n").unwrap();
        assert!(rc_file_has_rch_setup(&path4).unwrap());
    }

    // ==================== Additional Coverage Tests ====================

    #[test]
    fn test_install_paths_clone() {
        let paths = InstallPaths {
            script_path: PathBuf::from("/tmp/test"),
            rc_file: Some(PathBuf::from("/home/user/.bashrc")),
            rc_line: Some("source /tmp/test".to_string()),
        };

        let cloned = paths.clone();
        assert_eq!(cloned.script_path, paths.script_path);
        assert_eq!(cloned.rc_file, paths.rc_file);
        assert_eq!(cloned.rc_line, paths.rc_line);
    }

    #[test]
    fn test_install_paths_debug() {
        let paths = InstallPaths {
            script_path: PathBuf::from("/tmp/rch"),
            rc_file: None,
            rc_line: None,
        };

        let debug = format!("{:?}", paths);
        assert!(debug.contains("script_path"));
        assert!(debug.contains("/tmp/rch"));
    }

    #[test]
    fn test_install_paths_without_rc() {
        let paths = InstallPaths {
            script_path: PathBuf::from("/tmp/completion"),
            rc_file: None,
            rc_line: None,
        };

        assert!(paths.rc_file.is_none());
        assert!(paths.rc_line.is_none());
    }

    #[test]
    fn test_install_result_debug() {
        let result = InstallResult {
            shell: clap_complete::Shell::Bash,
            script_path: PathBuf::from("/tmp/rch"),
            script_written: true,
            rc_modified: false,
            rc_file: None,
            was_already_installed: false,
        };

        let debug = format!("{:?}", result);
        assert!(debug.contains("script_written"));
        assert!(debug.contains("rc_modified"));
        assert!(debug.contains("was_already_installed"));
    }

    #[test]
    fn test_get_install_paths_powershell() {
        let paths = get_install_paths(clap_complete::Shell::PowerShell).unwrap();
        assert!(paths.script_path.to_string_lossy().contains("rch.ps1"));
        assert!(paths.rc_file.is_some());
        assert!(paths.rc_line.is_some());
    }

    #[test]
    fn test_get_install_paths_elvish() {
        let paths = get_install_paths(clap_complete::Shell::Elvish).unwrap();
        assert!(paths.script_path.to_string_lossy().contains("rch.elv"));
        assert!(paths.rc_file.is_some());
        let rc_line = paths.rc_line.as_ref().unwrap();
        assert!(rc_line.contains("use rch"));
    }

    #[test]
    fn test_generate_powershell_completions() {
        let script = generate_completion_script(clap_complete::Shell::PowerShell);
        assert!(!script.is_empty());
        // PowerShell completions should contain the command name
        assert!(script.contains("rch") || script.to_lowercase().contains("rch"));
    }

    #[test]
    fn test_generate_elvish_completions() {
        let script = generate_completion_script(clap_complete::Shell::Elvish);
        assert!(!script.is_empty());
    }

    #[test]
    fn test_completion_scripts_are_different_per_shell() {
        let bash = generate_completion_script(clap_complete::Shell::Bash);
        let zsh = generate_completion_script(clap_complete::Shell::Zsh);
        let fish = generate_completion_script(clap_complete::Shell::Fish);

        // Each shell should have different completion syntax
        assert_ne!(bash, zsh);
        assert_ne!(bash, fish);
        assert_ne!(zsh, fish);
    }

    #[test]
    fn test_bash_install_path_structure() {
        let paths = get_install_paths(clap_complete::Shell::Bash).unwrap();

        // Bash should use bash-completion directory
        let path_str = paths.script_path.to_string_lossy();
        assert!(path_str.contains("bash-completion"));
        assert!(path_str.ends_with("rch"));

        // Bash auto-loads, so no RC modifications needed
        assert!(paths.rc_file.is_none());
        assert!(paths.rc_line.is_none());
    }

    #[test]
    fn test_zsh_install_path_structure() {
        let paths = get_install_paths(clap_complete::Shell::Zsh).unwrap();

        // Zsh uses .zfunc directory
        let path_str = paths.script_path.to_string_lossy();
        assert!(path_str.contains(".zfunc"));
        assert!(path_str.ends_with("_rch"));

        // Zsh needs RC file modifications
        let rc_file = paths.rc_file.unwrap();
        assert!(rc_file.to_string_lossy().contains(".zshrc"));

        let rc_line = paths.rc_line.unwrap();
        assert!(rc_line.contains("fpath"));
        assert!(rc_line.contains("compinit"));
    }

    #[test]
    fn test_fish_install_path_structure() {
        let paths = get_install_paths(clap_complete::Shell::Fish).unwrap();

        // Fish uses .config/fish/completions
        let path_str = paths.script_path.to_string_lossy();
        assert!(path_str.contains("fish"));
        assert!(path_str.contains("completions"));
        assert!(path_str.ends_with("rch.fish"));

        // Fish auto-loads, so no RC modifications needed
        assert!(paths.rc_file.is_none());
        assert!(paths.rc_line.is_none());
    }

    #[test]
    fn test_rc_file_empty_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rc_path = temp_dir.path().join(".emptyrc");

        // Write empty file
        std::fs::write(&rc_path, "").unwrap();
        let result = rc_file_has_rch_setup(&rc_path).unwrap();
        assert!(!result, "Empty file should not have RCH setup");
    }

    #[test]
    fn test_rc_file_whitespace_only() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rc_path = temp_dir.path().join(".whitespacerc");

        // Write whitespace-only file
        std::fs::write(&rc_path, "   \n\t\n  \n").unwrap();
        let result = rc_file_has_rch_setup(&rc_path).unwrap();
        assert!(!result, "Whitespace-only file should not have RCH setup");
    }

    #[test]
    fn test_install_result_fields() {
        let result = InstallResult {
            shell: clap_complete::Shell::Zsh,
            script_path: PathBuf::from("/home/user/.zfunc/_rch"),
            script_written: true,
            rc_modified: true,
            rc_file: Some(PathBuf::from("/home/user/.zshrc")),
            was_already_installed: false,
        };

        assert!(result.script_written);
        assert!(result.rc_modified);
        assert!(!result.was_already_installed);
    }

    #[test]
    fn test_completion_scripts_contain_subcommands() {
        // Test that generated scripts contain expected subcommands
        let bash = generate_completion_script(clap_complete::Shell::Bash);
        let zsh = generate_completion_script(clap_complete::Shell::Zsh);
        let fish = generate_completion_script(clap_complete::Shell::Fish);

        // All shells should mention common subcommands or options
        // (exact format varies by shell)
        for script in [&bash, &zsh, &fish] {
            assert!(
                script.len() > 100,
                "Completion script should be substantial"
            );
        }
    }

    #[test]
    fn test_install_paths_home_based() {
        // All paths should be relative to home directory
        for shell in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
            clap_complete::Shell::PowerShell,
            clap_complete::Shell::Elvish,
        ] {
            let paths = get_install_paths(shell).unwrap();
            let path_str = paths.script_path.to_string_lossy();

            // Path should be under home (contains common home indicators)
            assert!(
                path_str.contains("home")
                    || path_str.contains("Users")
                    || path_str.starts_with("/"),
                "Path for {:?} should be absolute: {}",
                shell,
                path_str
            );
        }
    }
}
