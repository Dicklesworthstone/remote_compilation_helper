//! CC/CXX/AR native-tool wrappers (bead L006; plan §101).
//!
//! Build scripts (the `cc` crate, cmake, hand-rolled makefiles)
//! invoke native tools through the `CC`/`CXX`/`AR` environment
//! variables. RABS intercepts by pointing those variables at its
//! wrappers while preserving the REAL tool in a sidecar variable the
//! wrapper resolves at exec time. The wrappers follow the tiny-
//! wrapper discipline exactly:
//!
//! - FAIL-OPEN: daemon unreachable, unsupported invocation, or any
//!   doubt → exec the real tool with BYTE-UNTOUCHED argv and
//!   environment. The build never blocks on RABS.
//! - a user-set `CC=clang-19` is the real tool — preserved exactly,
//!   never clobbered; an unset variable falls back to the platform
//!   default;
//! - injection round-trips: resolving the sidecar recovers exactly
//!   what the build would have used stock (the identity acceptance);
//! - delegation always streams (there is no buffered variant to
//!   accidentally pick) and rides the transcript frontier.

/// The intercepted native tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeTool {
    /// C compiler (`CC`).
    Cc,
    /// C++ compiler (`CXX`).
    Cxx,
    /// Archiver (`AR`).
    Ar,
}

/// Every intercepted tool (exhaustive; a new tool extends here).
pub const ALL_TOOLS: [NativeTool; 3] = [NativeTool::Cc, NativeTool::Cxx, NativeTool::Ar];

impl NativeTool {
    /// The environment variable build systems read.
    #[must_use]
    pub const fn env_var(self) -> &'static str {
        match self {
            Self::Cc => "CC",
            Self::Cxx => "CXX",
            Self::Ar => "AR",
        }
    }

    /// The sidecar variable holding the REAL tool for the wrapper.
    #[must_use]
    pub const fn sidecar_var(self) -> &'static str {
        match self {
            Self::Cc => "RCH_REAL_CC",
            Self::Cxx => "RCH_REAL_CXX",
            Self::Ar => "RCH_REAL_AR",
        }
    }

    /// The wrapper binary's name.
    #[must_use]
    pub const fn wrapper_name(self) -> &'static str {
        match self {
            Self::Cc => "rch-cc",
            Self::Cxx => "rch-cxx",
            Self::Ar => "rch-ar",
        }
    }

    /// The platform-default tool when the variable is unset.
    #[must_use]
    pub const fn platform_default(self) -> &'static str {
        match self {
            Self::Cc => "cc",
            Self::Cxx => "c++",
            Self::Ar => "ar",
        }
    }
}

/// One injected variable assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvAssignment {
    /// Variable name.
    pub var: &'static str,
    /// Value to set.
    pub value: String,
}

/// Build the injection plan: for each tool, point the build-facing
/// variable at the wrapper and preserve the real tool (the user's
/// setting, or the platform default) in the sidecar.
///
/// `user_env` — the (var, value) pairs the user's environment already
/// carries for `CC`/`CXX`/`AR`.
#[must_use]
pub fn injection_plan(user_env: &[(String, String)], wrapper_dir: &str) -> Vec<EnvAssignment> {
    let mut plan = Vec::new();
    for tool in ALL_TOOLS {
        let real = user_env
            .iter()
            .find(|(var, _)| var == tool.env_var())
            .map_or_else(
                || tool.platform_default().to_owned(),
                |(_, value)| value.clone(), // user's tool, exactly
            );
        plan.push(EnvAssignment {
            var: tool.env_var(),
            value: format!("{wrapper_dir}/{}", tool.wrapper_name()),
        });
        plan.push(EnvAssignment {
            var: tool.sidecar_var(),
            value: real,
        });
    }
    plan
}

/// Resolve the real tool inside a wrapper (what exec uses).
#[must_use]
pub fn resolve_real_tool(tool: NativeTool, env: &[(String, String)]) -> String {
    env.iter()
        .find(|(var, _)| var == tool.sidecar_var())
        .map_or_else(
            || tool.platform_default().to_owned(),
            |(_, value)| value.clone(),
        )
}

/// Why a wrapper failed open (recorded, never fatal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOpenCause {
    /// The daemon was unreachable.
    DaemonUnreachable,
    /// The invocation used flags the parser does not understand.
    UnsupportedInvocation,
    /// The sidecar variable was missing (wrapper invoked outside an
    /// RCH session): pass through to the platform default.
    NoSidecar,
}

/// The wrapper's decision for one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapperAction {
    /// Delegate to the daemon: ALWAYS streaming, on the transcript
    /// frontier (no buffered variant exists to pick).
    Delegate {
        /// The tool being delegated.
        tool: NativeTool,
        /// The invocation argv (after `argv[0]`).
        args: Vec<String>,
    },
    /// Fail open: exec the real tool with the argv BYTE-UNTOUCHED.
    FailOpen {
        /// The real tool to exec.
        real_tool: String,
        /// The original argv, exactly as received.
        args: Vec<String>,
        /// Why (recorded for diagnostics, never fatal).
        cause: FailOpenCause,
    },
}

/// Decide a wrapper invocation.
#[must_use]
pub fn decide(
    tool: NativeTool,
    args: &[String],
    env: &[(String, String)],
    daemon_reachable: bool,
    invocation_understood: bool,
) -> WrapperAction {
    let has_sidecar = env.iter().any(|(var, _)| var == tool.sidecar_var());
    if !has_sidecar {
        return WrapperAction::FailOpen {
            real_tool: tool.platform_default().to_owned(),
            args: args.to_vec(),
            cause: FailOpenCause::NoSidecar,
        };
    }
    if !daemon_reachable {
        return WrapperAction::FailOpen {
            real_tool: resolve_real_tool(tool, env),
            args: args.to_vec(),
            cause: FailOpenCause::DaemonUnreachable,
        };
    }
    if !invocation_understood {
        return WrapperAction::FailOpen {
            real_tool: resolve_real_tool(tool, env),
            args: args.to_vec(),
            cause: FailOpenCause::UnsupportedInvocation,
        };
    }
    WrapperAction::Delegate {
        tool,
        args: args.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_owned()
    }

    #[test]
    fn injection_preserves_the_users_tools_exactly() {
        // A user-set CC is the real tool — never clobbered.
        let user = vec![(s("CC"), s("clang-19"))];
        let plan = injection_plan(&user, "/opt/rch/bin");
        let get = |var: &str| {
            plan.iter()
                .find(|a| a.var == var)
                .map(|a| a.value.clone())
                .expect("assigned")
        };
        assert_eq!(get("CC"), "/opt/rch/bin/rch-cc");
        assert_eq!(get("RCH_REAL_CC"), "clang-19", "user's compiler, exactly");
        // Unset CXX/AR fall back to platform defaults.
        assert_eq!(get("CXX"), "/opt/rch/bin/rch-cxx");
        assert_eq!(get("RCH_REAL_CXX"), "c++");
        assert_eq!(get("RCH_REAL_AR"), "ar");
        // All three tools covered: 2 assignments each.
        assert_eq!(plan.len(), 6);
    }

    #[test]
    fn injection_round_trips_to_stock_for_every_tool() {
        // THE identity half of the acceptance: resolving the sidecar
        // recovers exactly what the build would have used stock.
        let user = vec![
            (s("CC"), s("clang-19")),
            (s("CXX"), s("clang++-19")),
            (s("AR"), s("llvm-ar")),
        ];
        let plan = injection_plan(&user, "/opt/rch/bin");
        let injected: Vec<(String, String)> = plan
            .iter()
            .map(|a| (a.var.to_owned(), a.value.clone()))
            .collect();
        for (tool, stock) in [
            (NativeTool::Cc, "clang-19"),
            (NativeTool::Cxx, "clang++-19"),
            (NativeTool::Ar, "llvm-ar"),
        ] {
            assert_eq!(resolve_real_tool(tool, &injected), stock);
        }
    }

    #[test]
    fn fail_open_execs_the_real_tool_byte_untouched() {
        // THE behavioral half: on any doubt the wrapper execs the
        // real tool with the ORIGINAL argv — stock behavior.
        let env = vec![(s("RCH_REAL_CC"), s("clang-19"))];
        let args = vec![s("-O2"), s("-c"), s("foo.c"), s("-o"), s("foo.o")];
        // Daemon down.
        assert_eq!(
            decide(NativeTool::Cc, &args, &env, false, true),
            WrapperAction::FailOpen {
                real_tool: s("clang-19"),
                args: args.clone(),
                cause: FailOpenCause::DaemonUnreachable,
            }
        );
        // Unsupported invocation (weird flags): same discipline.
        assert_eq!(
            decide(NativeTool::Cc, &args, &env, true, false),
            WrapperAction::FailOpen {
                real_tool: s("clang-19"),
                args: args.clone(),
                cause: FailOpenCause::UnsupportedInvocation,
            }
        );
        // Outside an RCH session (no sidecar): platform default.
        assert_eq!(
            decide(NativeTool::Cc, &args, &[], true, true),
            WrapperAction::FailOpen {
                real_tool: s("cc"),
                args: args.clone(),
                cause: FailOpenCause::NoSidecar,
            }
        );
        // The build NEVER blocks: every fail-open carries an exec
        // target — there is no refuse/abort variant at all.
        match decide(NativeTool::Cc, &args, &env, false, false) {
            WrapperAction::Delegate { .. } | WrapperAction::FailOpen { .. } => {}
        }
    }

    #[test]
    fn delegation_is_streaming_by_construction() {
        // Healthy path delegates; the Delegate variant has no buffer
        // flag and no frontier choice — streaming on the transcript
        // frontier is the ONLY shape (structural, by destructure).
        let env = vec![(s("RCH_REAL_AR"), s("ar"))];
        let args = vec![s("crus"), s("libfoo.a"), s("foo.o")];
        match decide(NativeTool::Ar, &args, &env, true, true) {
            WrapperAction::Delegate { tool, args: got } => {
                assert_eq!(tool, NativeTool::Ar);
                assert_eq!(got, args);
            }
            WrapperAction::FailOpen { .. } => panic!("healthy path must delegate"),
        }
    }

    #[test]
    fn tool_table_is_exhaustive_and_distinct() {
        // Wire-facing names pinned; sidecars never collide with the
        // build-facing variables.
        for tool in ALL_TOOLS {
            assert_ne!(tool.env_var(), tool.sidecar_var());
            assert!(tool.sidecar_var().starts_with("RCH_REAL_"));
        }
        assert_eq!(
            ALL_TOOLS.map(NativeTool::env_var),
            ["CC", "CXX", "AR"] // pinned: build systems read these
        );
    }
}
