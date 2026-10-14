//! Parsing only: these tests never load host configuration or contact a worker.
use super::*;

#[test]
fn exact_runtime_alias_and_named_tools_share_one_lossless_requirement_vector() {
    for verb in ["exec", "admit"] {
        let cli = Cli::try_parse_from([
            "rch",
            verb,
            "--job",
            "--require-tool",
            "clang",
            "--require-toolchain",
            "node@26.7.0",
            "--require-toolchain",
            "bun@1.3.0",
            "--",
            "node",
            "script.js",
        ])
        .unwrap();
        let (requirements, command) = match cli.command.unwrap() {
            Commands::Exec {
                require_tool,
                command,
                ..
            }
            | Commands::Admit {
                require_tool,
                command,
                ..
            } => (require_tool, command),
            _ => panic!("wrong command"),
        };
        assert_eq!(requirements, ["clang", "node@26.7.0", "bun@1.3.0"]);
        assert_eq!(command, ["node", "script.js"]);
    }
}

#[test]
fn exact_runtime_invalid_constraints_are_rejected_before_dispatch() {
    for verb in ["exec", "admit"] {
        for flag in ["--require-tool", "--require-toolchain"] {
            for requirement in [
                "node@26",
                "node@26.7",
                "node@^26.7.0",
                "bun@latest",
                "rust@1.90.0",
            ] {
                assert!(
                    Cli::try_parse_from([
                        "rch",
                        verb,
                        "--job",
                        flag,
                        requirement,
                        "--",
                        "node",
                        "script.js"
                    ])
                    .is_err(),
                    "{verb} {flag} {requirement}"
                );
            }
        }
    }
}

#[test]
fn runtime_requirement_flags_after_separator_belong_to_the_user_command() {
    let cli = Cli::try_parse_from([
        "rch",
        "exec",
        "--job",
        "--require-toolchain",
        "node@26.7.0",
        "--",
        "node",
        "script.js",
        "--require-toolchain",
        "bun@1.3.0",
    ])
    .unwrap();
    let Some(Commands::Exec {
        require_tool,
        command,
        ..
    }) = cli.command
    else {
        panic!("wrong command");
    };
    assert_eq!(require_tool, ["node@26.7.0"]);
    assert_eq!(
        command,
        ["node", "script.js", "--require-toolchain", "bun@1.3.0"]
    );
}
