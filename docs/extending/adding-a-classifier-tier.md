# Adding a Classifier Tier

This guide explains how to extend RCH's 5-tier command classification system.

## Overview

The classifier uses a tiered approach for performance:
- **Tier 0**: Instant reject (< 0.01ms)
- **Tier 1**: Structure analysis (< 0.1ms)
- **Tier 2**: SIMD keyword filter (< 0.2ms)
- **Tier 3**: Negative pattern check (< 0.5ms)
- **Tier 4**: Full classification (< 5ms)

Each tier acts as a filter - commands must pass all previous tiers to reach the next one.

## When to Add a New Tier

Consider adding a tier when:
- New command patterns aren't handled by existing tiers
- Performance optimization requires early rejection
- Special handling for a category of commands

## Implementation Steps

### 1. Understand the Current Flow

In `rch-common/src/patterns.rs`:

```rust
pub fn classify_command(command: &str) -> ClassificationResult {
    // Tier 0: Instant reject
    if command.is_empty() {
        return ClassificationResult::local(ClassificationReason::Empty);
    }

    // Tier 1: Structure analysis
    if has_complex_shell_structure(command) {
        return ClassificationResult::local(ClassificationReason::ComplexShellStructure);
    }

    // Tier 2: SIMD keyword filter
    if !has_compilation_keyword(command) {
        return ClassificationResult::local(ClassificationReason::NoCompilationKeyword);
    }

    // Tier 3: Negative pattern check
    if matches_negative_pattern(command) {
        return ClassificationResult::local(ClassificationReason::NegativePattern);
    }

    // Tier 4: Full classification
    full_classify(command)
}
```

### 2. Define the New Tier

Create the tier function:

```rust
// Example: Tier 2.5 - Project context check
fn has_required_project_context(command: &str, context: &CommandContext) -> bool {
    // Check if the project has the necessary build files
    match parse_build_tool(command) {
        Some(BuildTool::Cargo) => context.has_file("Cargo.toml"),
        Some(BuildTool::Make) => context.has_file("Makefile"),
        Some(BuildTool::Cmake) => context.has_file("CMakeLists.txt"),
        Some(BuildTool::Bun) => context.has_file("package.json"),
        None => false,
    }
}
```

### 3. Insert into Classification Pipeline

Add the tier at the appropriate position:

```rust
pub fn classify_command(command: &str, context: &CommandContext) -> ClassificationResult {
    // Tiers 0-2 unchanged...

    // NEW: Tier 2.5 - Project context check
    if !has_required_project_context(command, context) {
        return ClassificationResult::local(
            ClassificationReason::MissingProjectContext
        );
    }

    // Tiers 3-4 unchanged...
}
```

### 4. Add Classification Reason

In `rch-common/src/types.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationReason {
    // Existing reasons...
    Empty,
    ComplexShellStructure,
    NoCompilationKeyword,
    NegativePattern,

    // NEW
    MissingProjectContext,

    // Full classification results
    CompilationDetected(CompilationKind),
}
```

### 5. Update Tests

Add comprehensive tests in `rch-common/src/patterns/tests.rs`:

```rust
#[test]
fn test_tier_2_5_project_context() {
    // Without project context
    let context = CommandContext::empty();
    let result = classify_command("cargo build", &context);
    assert!(result.is_local());
    assert_eq!(result.reason, ClassificationReason::MissingProjectContext);

    // With project context
    let context = CommandContext::with_file("Cargo.toml");
    let result = classify_command("cargo build", &context);
    assert!(result.is_remote());
}

#[test]
fn test_tier_2_5_performance() {
    let context = CommandContext::cached(); // Pre-scanned
    let start = Instant::now();

    for _ in 0..10_000 {
        classify_command("cargo build", &context);
    }

    let elapsed = start.elapsed();
    let per_call = elapsed / 10_000;

    // Must be < 0.3ms to fit between Tier 2 and Tier 3
    assert!(per_call < Duration::from_micros(300));
}
```

### 6. Update Documentation

Add the tier to `docs/architecture/classifier.md`:

```markdown
### Tier 2.5: Project Context Check (NEW)
- **Latency**: ~0.25ms
- **Purpose**: Verify project has required build files
- **Method**: Check for Cargo.toml, Makefile, etc.
```

## Performance Considerations

### Tier Placement

Place tiers by their cost:
- Cheapest checks first (avoid expensive operations if possible)
- High-rejection-rate checks early (filter out most commands quickly)

### SIMD Optimization

For string matching, use `memchr` for SIMD acceleration:

```rust
use memchr::memmem;

fn contains_keyword_simd(haystack: &str, needle: &str) -> bool {
    memmem::find(haystack.as_bytes(), needle.as_bytes()).is_some()
}
```

### Caching

For expensive checks, consider caching:

```rust
struct ClassificationCache {
    project_context: HashMap<PathBuf, CachedContext>,
    ttl: Duration,
}

impl ClassificationCache {
    fn get_context(&mut self, path: &Path) -> &CachedContext {
        // Return cached or compute and cache
    }
}
```

## Example: Adding Language Detection Tier

Full example of adding a tier that detects programming language:

```rust
// rch-common/src/patterns/language.rs

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectLanguage {
    Rust,
    Cpp,
    C,
    TypeScript,
    JavaScript,
    Unknown,
}

impl ProjectLanguage {
    pub fn detect(working_dir: &Path) -> Self {
        if working_dir.join("Cargo.toml").exists() {
            return ProjectLanguage::Rust;
        }
        if working_dir.join("package.json").exists() {
            if working_dir.join("tsconfig.json").exists() {
                return ProjectLanguage::TypeScript;
            }
            return ProjectLanguage::JavaScript;
        }
        if working_dir.join("CMakeLists.txt").exists()
            || working_dir.join("Makefile").exists()
        {
            // Check for .cpp or .c files
            if has_cpp_files(working_dir) {
                return ProjectLanguage::Cpp;
            }
            return ProjectLanguage::C;
        }
        ProjectLanguage::Unknown
    }
}

pub fn command_matches_language(command: &str, language: ProjectLanguage) -> bool {
    match language {
        ProjectLanguage::Rust => command.contains("cargo") || command.contains("rustc"),
        ProjectLanguage::Cpp | ProjectLanguage::C => {
            command.contains("gcc") || command.contains("clang") ||
            command.contains("make") || command.contains("cmake")
        }
        ProjectLanguage::TypeScript | ProjectLanguage::JavaScript => {
            command.contains("bun") || command.contains("npm") || command.contains("node")
        }
        ProjectLanguage::Unknown => true, // Allow all when unknown
    }
}
```

Integration:

```rust
// In classify_command()

// Tier 2.5: Language consistency check
let language = ProjectLanguage::detect(&context.working_dir);
if language != ProjectLanguage::Unknown && !command_matches_language(command, language) {
    return ClassificationResult::local(
        ClassificationReason::LanguageMismatch {
            detected: language,
            command_suggests: infer_language_from_command(command),
        }
    );
}
```

## Testing Your Tier

### Unit Tests

```bash
cargo test -p rch-common tier_name
```

### Integration Tests

```bash
# Test with real commands
echo '{"tool":"Bash","input":{"command":"cargo build"}}' | cargo run --bin rch -- hook test
```

### Performance Benchmarks

```bash
cargo bench -p rch-common classifier
```

Ensure your tier doesn't break performance budgets:
- Tier 0-2: < 0.2ms total
- Tier 3: < 0.5ms total
- Tier 4: < 5ms total
