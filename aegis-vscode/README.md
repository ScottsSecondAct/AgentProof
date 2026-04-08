# Aegis Policy Language — VS Code Extension

Language support for the [Aegis Policy Language](https://github.com/automaguard/automaguard) (`.aegis`) and compiled bytecode inspector (`.aegisc`). Part of the [AutomaGuard](https://github.com/automaguard/automaguard) formal verification engine for production AI agents.

## Features

### Syntax Highlighting

Full grammar coverage for `.aegis` source files:

- **Temporal operators** — `always`, `eventually`, `never`, `until`, `before`, `after`, `next`, `within`
- **Verdict keywords** — `allow`, `deny`, `audit`, `redact`
- **Quantifiers** — `any`, `all`, `none`, `exists`, `count`
- **Action keywords** — `log`, `notify`, `escalate`, `block`, `tag`, `rate_limit`, `quota`
- **Type keywords** — `int`, `float`, `bool`, `string`, `duration`, `List`, `Map`, `Set`
- **Severity levels** — `critical`, `high`, `medium`, `low`, `info`
- **Predicate operators** — `contains`, `matches`, `starts_with`, `ends_with`
- **Special variables** — `context`, `event`
- **Annotations** — `@author(...)`, `@version(...)`, `@environment(...)`
- Duration literals (`5m`, `300ms`, `1h`), raw strings (`r"..."`), regex literals (`/pattern/flags`)

### Diagnostics

Errors and warnings from `aegisc check` appear inline in the editor and in the **Problems** panel with correct file, line, and column. Runs automatically on save (see [Settings](#settings)).

### Snippets

20 snippets covering common patterns. Trigger via IntelliSense or type the prefix:

| Prefix | Inserts |
|---|---|
| `policy` | Full policy block with rate limit and rule |
| `on` | Event rule block |
| `deny` | Deny rule with condition |
| `audit` | Audit rule with tag |
| `rate_limit` | Rate limit constraint |
| `quota` | Quota constraint |
| `proof` | Proof block with `always` invariant |
| `invariant-always` | `always(φ)` — must hold on every event |
| `invariant-eventually` | `eventually(φ) within T` — must hold before deadline |
| `invariant-never` | `never(φ)` — must never hold |
| `invariant-after` | `after(condition, trigger)` — holds after trigger fires |
| `invariant-until` | `φ until ψ` |
| `def` | Helper function definition |
| `type` | Custom type declaration |
| `let` | Policy-level binding |
| `import` / `from` | Import statements |
| `any(` / `all(` / `none(` | Quantifier expressions |
| `count(` | Count expression |
| `data-guard` | Complete data guard policy template |
| `exfil-guard` | Exfiltration guard proof template |

### `.aegisc` Bytecode Inspector

Opening a compiled `.aegisc` file shows a structured inspector instead of binary content:

- **Header** — magic validation, format version, flags, payload size
- **Policy metadata** — name, severity, scopes, compiler version, source hash
- **Rules table** — event types, verdicts, severity per rule
- **State machines** — compiled temporal invariants with kind, state count, transition count
- **Constraints** — rate limits and quotas
- **Full JSON** — collapsible panel with the complete raw payload

## Commands

Access via `Ctrl+Shift+P` (Command Palette), editor title bar buttons, or right-click context menu.

| Command | Keybinding | Description |
|---|---|---|
| **Aegis: Check Policy** | `Ctrl+Shift+;` / `Cmd+Shift+;` | Type-checks the current `.aegis` file. Errors appear in the Problems panel. A status bar message confirms the result. |
| **Aegis: Compile Policy** | `Ctrl+Shift+B` / `Cmd+Shift+B` | Compiles to `.aegisc` bytecode alongside the source file. Output goes to the **Aegis** output channel. |
| **Aegis: Dump Compiled IR as JSON** | — | Compiles and opens the full IR as pretty-printed JSON in a side pane. Useful for inspecting what the compiler produced. |

Check and Compile also appear as icon buttons in the editor title bar when a `.aegis` file is active, and in the right-click context menu in both the editor and the Explorer.

## Settings

| Setting | Default | Description |
|---|---|---|
| `aegis.compilerPath` | `"aegisc"` | Path to the `aegisc` binary. Defaults to `aegisc` on PATH. The extension auto-discovers the binary at `aegis-compiler/target/release/aegisc` and `aegis-compiler/target/debug/aegisc` relative to the workspace root before falling back to PATH. Set an absolute path to override. |
| `aegis.checkOnSave` | `true` | Run `aegisc check` automatically when a `.aegis` file is saved. |
| `aegis.maxDiagnostics` | `100` | Maximum number of diagnostics reported per file. |

## Requirements

- The `aegisc` compiler binary must be built. From the repository root:

  ```sh
  cd aegis-compiler
  cargo build --release
  ```

  The extension will find it automatically at `aegis-compiler/target/release/aegisc`.

## Building the Extension

```sh
cd aegis-vscode
npm install
npm run compile      # compile TypeScript
npm run package      # produce aegis-language-0.1.0.vsix
```

Install locally:

```sh
code --install-extension aegis-language-0.1.0.vsix
```
