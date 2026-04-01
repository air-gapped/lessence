## Context

lessence currently hardcodes `io::stdin()` as its only input source. The processing pipeline (normalize → group → fold → output) operates on a `BufRead` trait object, so it's already abstracted from the input source. The change is isolated to `src/main.rs` — the CLI argument parsing and the input reading setup.

## Goals / Non-Goals

**Goals:**
- Accept optional positional file arguments via clap
- Fall back to stdin when no files are given
- Support `-` as explicit stdin
- Concatenate multiple files into one stream
- Warn and skip unreadable files

**Non-Goals:**
- Built-in glob expansion (shell handles this)
- Binary file detection (can be added later as a separate change)
- Per-file output separation (e.g., headers between files like `head`)
- Recursive directory traversal

## Decisions

### 1. Positional args via `Vec<PathBuf>` in clap derive

Add to the `Cli` struct:

```rust
/// Input files (reads stdin if none given, use - for explicit stdin)
#[arg(value_name = "FILE")]
files: Vec<PathBuf>,
```

Empty vec = stdin. This is the idiomatic clap pattern used by ripgrep, bat, and jq.

**Alternative**: Using `Option<Vec<PathBuf>>` — rejected because an empty vec already signals "no files," making `Option` redundant.

### 2. Input abstraction via `Box<dyn BufRead>`

Create a helper function that returns a vec of readers:

```rust
fn open_inputs(files: &[PathBuf]) -> Vec<Box<dyn BufRead>> {
    if files.is_empty() {
        return vec![Box::new(BufReader::new(io::stdin().lock()))];
    }
    // For each file: open it, or warn and skip on error
    // For "-": return stdin
}
```

The main loop chains these readers and processes lines identically to the current single-stdin path.

**Alternative**: A custom `enum Input { Stdin, File(File) }` — rejected as overengineered for this use case. `Box<dyn BufRead>` is simpler and sufficient.

### 3. Concatenate files (not separate output per file)

Multiple files are treated as one continuous log stream, same as `cat file1 file2 | lessence`. This matches the primary use case: compressing logs from multiple sources into one view.

**Alternative**: Adding `--per-file` mode with headers — deferred. Can be a future change if users ask for it.

### 4. Error handling: warn and continue

On file open failure, emit `lessence: <path>: <error>` to stderr (matching grep/cat convention) and continue processing remaining files. Exit code is non-zero only if ALL inputs fail.

## Risks / Trade-offs

- [stdin consumed once] If `-` appears multiple times in the argument list, the second read gets EOF silently. → Detect and warn on stderr, or just document the behavior (grep does the same).
- [Flag ambiguity] A filename starting with `--` could be confused for a flag. → clap handles this via `--` separator: `lessence -- --weird-filename.log`. Standard Unix convention.
