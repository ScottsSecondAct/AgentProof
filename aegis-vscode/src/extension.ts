import * as vscode from "vscode";
import * as cp from "child_process";
import * as path from "path";
import * as fs from "fs";

// ═══════════════════════════════════════════════════════════════════════
//  Extension entry point
// ═══════════════════════════════════════════════════════════════════════

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("aegis");
  context.subscriptions.push(diagnostics);

  // Offer to activate Aegis file icons on first install, but only if the
  // user hasn't already seen the prompt and the current icon theme isn't ours.
  const iconPromptKey = "aegis.iconPromptShown";
  const alreadyPrompted = context.globalState.get<boolean>(iconPromptKey, false);
  if (!alreadyPrompted) {
    context.globalState.update(iconPromptKey, true);
    const currentTheme = vscode.workspace
      .getConfiguration("workbench")
      .get<string>("iconTheme");
    if (currentTheme !== "aegis-icons") {
      vscode.window
        .showInformationMessage(
          "Aegis: Enable Aegis file icons for .aegis and .aegisc files?",
          "Enable",
          "Not now"
        )
        .then((choice) => {
          if (choice === "Enable") {
            vscode.workspace
              .getConfiguration("workbench")
              .update("iconTheme", "aegis-icons", vscode.ConfigurationTarget.Global);
          }
        });
    }
  }

  // Run check on the active .aegis editor at startup if one is open
  const activeEditor = vscode.window.activeTextEditor;
  if (activeEditor && activeEditor.document.languageId === "aegis") {
    runCheck(activeEditor.document.uri, diagnostics);
  }

  // Check on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.languageId !== "aegis") {
        return;
      }
      const cfg = vscode.workspace.getConfiguration("aegis", doc.uri);
      if (cfg.get<boolean>("checkOnSave", true)) {
        runCheck(doc.uri, diagnostics);
      }
    })
  );

  // Clear diagnostics when a .aegis file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      if (doc.languageId === "aegis") {
        diagnostics.delete(doc.uri);
      }
    })
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("aegis.check", async () => {
      const uri = activeAegisUri();
      if (!uri) {
        return;
      }
      await runCheck(uri, diagnostics, true);
    }),

    vscode.commands.registerCommand("aegis.compile", async () => {
      const uri = activeAegisUri();
      if (!uri) {
        return;
      }
      await runCompile(uri);
    }),

    vscode.commands.registerCommand("aegis.dump", async () => {
      const uri = activeAegisUri();
      if (!uri) {
        return;
      }
      await runDump(uri);
    })
  );

  // Register the .aegisc custom readonly editor
  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(
      "aegis.aegiscInspector",
      new AegiscEditorProvider(context),
      {
        supportsMultipleEditorsPerDocument: false,
        webviewOptions: { retainContextWhenHidden: true },
      }
    )
  );

  console.log("Aegis Policy Language extension activated");
}

export function deactivate(): void {}

// ═══════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════

function activeAegisUri(): vscode.Uri | undefined {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage("No active editor.");
    return undefined;
  }
  if (
    editor.document.languageId !== "aegis" &&
    !editor.document.fileName.endsWith(".aegis")
  ) {
    vscode.window.showErrorMessage("Active file is not an .aegis policy.");
    return undefined;
  }
  return editor.document.uri;
}

function compilerPath(uri: vscode.Uri): string {
  const cfg = vscode.workspace.getConfiguration("aegis", uri);
  const configured = cfg.get<string>("compilerPath", "aegisc");

  // If the user explicitly set a non-default path, honour it as-is.
  if (configured !== "aegisc") {
    return configured;
  }

  // Auto-discover: prefer release build, fall back to debug build, then PATH.
  const workspaceFolders = vscode.workspace.workspaceFolders;
  const roots: string[] = workspaceFolders
    ? workspaceFolders.map((f) => f.uri.fsPath)
    : [path.dirname(uri.fsPath)];

  const candidates = roots.flatMap((root) => [
    path.join(root, "aegis-compiler", "target", "release", "aegisc"),
    path.join(root, "aegis-compiler", "target", "debug", "aegisc"),
  ]);

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // Last resort: assume it is on PATH.
  return "aegisc";
}

// ═══════════════════════════════════════════════════════════════════════
//  aegisc check — populate VS Code diagnostics
// ═══════════════════════════════════════════════════════════════════════

async function runCheck(
  uri: vscode.Uri,
  diagnosticCollection: vscode.DiagnosticCollection,
  showFeedback = false
): Promise<void> {
  const compiler = compilerPath(uri);
  const filePath = uri.fsPath;
  const fileName = path.basename(filePath);

  const statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusItem.text = `$(sync~spin) aegisc: checking ${fileName}…`;
  statusItem.show();

  return new Promise((resolve) => {
    cp.exec(
      `"${compiler}" check "${filePath}"`,
      { cwd: path.dirname(filePath) },
      (err, _stdout, stderr) => {
        statusItem.dispose();

        // Compiler not found: ENOENT means the binary doesn't exist
        if (err && (err as NodeJS.ErrnoException).code === "ENOENT") {
          vscode.window.showErrorMessage(
            `Aegis: compiler not found at "${compiler}". ` +
              `Set aegis.compilerPath in settings or build the compiler with ` +
              `"cargo build -p aegis-compiler".`
          );
          resolve();
          return;
        }

        const output = stderr || "";
        const parsed = parseDiagnostics(output, uri);
        diagnosticCollection.set(uri, parsed);

        if (showFeedback) {
          if (parsed.length === 0) {
            vscode.window.setStatusBarMessage(`$(check) aegisc: ${fileName} — no errors`, 4000);
          } else {
            const errors = parsed.filter(
              (d) => d.severity === vscode.DiagnosticSeverity.Error
            ).length;
            const warnings = parsed.filter(
              (d) => d.severity === vscode.DiagnosticSeverity.Warning
            ).length;
            const parts: string[] = [];
            if (errors > 0) { parts.push(`${errors} error${errors !== 1 ? "s" : ""}`); }
            if (warnings > 0) { parts.push(`${warnings} warning${warnings !== 1 ? "s" : ""}`); }
            vscode.window.setStatusBarMessage(`$(error) aegisc: ${parts.join(", ")}`, 6000);
          }
        }

        resolve();
      }
    );
  });
}

// Diagnostic output format produced by DiagnosticSink::render():
//
//   error[E0001]: message text
//     --> relative/path/file.aegis:11:10
//
//   warning[W0001]: message text
//     --> relative/path/file.aegis:5:3
//     note: additional context (file.aegis:4:1)
//
// Lines are separated by blank lines. We collect (severity, code, message)
// from the header line and (file, line, col) from the --> line.

function parseDiagnostics(
  output: string,
  fileUri: vscode.Uri
): vscode.Diagnostic[] {
  const results: vscode.Diagnostic[] = [];
  const lines = output.split("\n");
  const headerRe = /^(error|warning)\[([A-Z0-9]+)\]:\s+(.+)$/;
  const locationRe = /^\s+-->\s+(.+):(\d+):(\d+)\s*$/;

  let i = 0;
  while (i < lines.length) {
    const headerMatch = lines[i].match(headerRe);
    if (!headerMatch) {
      i++;
      continue;
    }

    const [, severityStr, code, message] = headerMatch;
    const severity =
      severityStr === "error"
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;

    // Scan forward for the location line
    let location: { file: string; line: number; col: number } | undefined;
    let j = i + 1;
    while (j < lines.length && lines[j].trim() !== "") {
      const locMatch = lines[j].match(locationRe);
      if (locMatch) {
        location = {
          file: locMatch[1],
          line: parseInt(locMatch[2], 10),
          col: parseInt(locMatch[3], 10),
        };
        break;
      }
      j++;
    }

    if (location) {
      // Resolve the file path relative to the checked file's directory
      const resolvedPath = path.isAbsolute(location.file)
        ? location.file
        : path.resolve(path.dirname(fileUri.fsPath), location.file);

      const diagnosticUri = vscode.Uri.file(resolvedPath);
      const targetUri =
        diagnosticUri.fsPath === fileUri.fsPath ? fileUri : diagnosticUri;

      // VS Code uses 0-based line/column; aegisc uses 1-based
      const range = new vscode.Range(
        location.line - 1,
        Math.max(0, location.col - 1),
        location.line - 1,
        Math.max(0, location.col - 1) + 80 // extend to end of likely token
      );

      const diag = new vscode.Diagnostic(range, message, severity);
      diag.code = code;
      diag.source = "aegisc";

      // Attach to the correct file URI
      // (diagnostics for the active file accumulate; cross-file diagnostics
      // are surfaced on save of the primary file)
      if (targetUri.fsPath === fileUri.fsPath) {
        results.push(diag);
      }
    }

    i = j + 1;
  }

  const cfg = vscode.workspace.getConfiguration("aegis", fileUri);
  const maxDiags = cfg.get<number>("maxDiagnostics", 100);
  return results.slice(0, maxDiags);
}

// ═══════════════════════════════════════════════════════════════════════
//  aegisc compile
// ═══════════════════════════════════════════════════════════════════════

async function runCompile(uri: vscode.Uri): Promise<void> {
  const compiler = compilerPath(uri);
  const filePath = uri.fsPath;
  const outputPath = filePath.replace(/\.aegis$/, ".aegisc");

  const channel = getOutputChannel();
  channel.show(true);
  channel.appendLine(`\n[aegis] Compiling ${path.basename(filePath)}...`);

  return new Promise((resolve) => {
    cp.exec(
      `"${compiler}" compile "${filePath}" -o "${outputPath}"`,
      { cwd: path.dirname(filePath) },
      (err, _stdout, stderr) => {
        const output = (stderr || "").trim();
        if (output) {
          channel.appendLine(output);
        }
        if (err) {
          channel.appendLine(`[aegis] Compilation failed (exit ${err.code})`);
          vscode.window.showErrorMessage(
            `Aegis: compilation failed — see Output panel for details.`
          );
        } else {
          channel.appendLine(
            `[aegis] Written: ${path.basename(outputPath)}`
          );
          vscode.window.showInformationMessage(
            `Aegis: compiled to ${path.basename(outputPath)}`
          );
        }
        resolve();
      }
    );
  });
}

// ═══════════════════════════════════════════════════════════════════════
//  aegisc dump — open compiled IR as JSON in a new editor
// ═══════════════════════════════════════════════════════════════════════

async function runDump(uri: vscode.Uri): Promise<void> {
  const compiler = compilerPath(uri);
  const filePath = uri.fsPath;

  return new Promise((resolve) => {
    cp.exec(
      `"${compiler}" dump "${filePath}"`,
      { cwd: path.dirname(filePath), maxBuffer: 10 * 1024 * 1024 },
      async (err, stdout, stderr) => {
        if (err || !stdout.trim()) {
          const msg = (stderr || "").trim() || "aegisc dump failed";
          vscode.window.showErrorMessage(`Aegis dump: ${msg}`);
          resolve();
          return;
        }

        // Pretty-print and open in a new untitled JSON editor
        let pretty = stdout.trim();
        try {
          pretty = JSON.stringify(JSON.parse(stdout), null, 2);
        } catch {
          // leave as-is if already formatted
        }

        const doc = await vscode.workspace.openTextDocument({
          language: "json",
          content: pretty,
        });
        await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
        resolve();
      }
    );
  });
}

// ═══════════════════════════════════════════════════════════════════════
//  Shared output channel
// ═══════════════════════════════════════════════════════════════════════

let _outputChannel: vscode.OutputChannel | undefined;
function getOutputChannel(): vscode.OutputChannel {
  if (!_outputChannel) {
    _outputChannel = vscode.window.createOutputChannel("Aegis");
  }
  return _outputChannel;
}

// ═══════════════════════════════════════════════════════════════════════
//  .aegisc custom readonly editor
//
//  The .aegisc format:
//    Bytes  0– 3  Magic: 0xAE 0x91 0x5C 0x01
//    Bytes  4– 5  Version: u16 LE (currently 1)
//    Bytes  6– 7  Flags:   u16 LE (reserved, currently 0)
//    Bytes  8–11  Payload length: u32 LE
//    Bytes 12–N   JSON-serialized CompiledPolicy
// ═══════════════════════════════════════════════════════════════════════

interface AegiscHeader {
  validMagic: boolean;
  version: number;
  flags: number;
  payloadLen: number;
  fileSize: number;
}

interface AegiscDocument extends vscode.CustomDocument {
  header: AegiscHeader;
  policy: Record<string, unknown> | null;
  parseError: string | null;
}

class AegiscEditorProvider
  implements vscode.CustomReadonlyEditorProvider<AegiscDocument>
{
  constructor(private readonly context: vscode.ExtensionContext) {}

  async openCustomDocument(
    uri: vscode.Uri,
    _openContext: vscode.CustomDocumentOpenContext,
    _token: vscode.CancellationToken
  ): Promise<AegiscDocument> {
    return readAegiscDocument(uri);
  }

  async resolveCustomEditor(
    document: AegiscDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken
  ): Promise<void> {
    webviewPanel.webview.options = { enableScripts: true };
    webviewPanel.webview.html = buildWebviewHtml(document, webviewPanel.webview, this.context);
  }
}

function readAegiscDocument(uri: vscode.Uri): AegiscDocument {
  const MAGIC = [0xae, 0x91, 0x5c, 0x01];
  const HEADER_SIZE = 12;

  let buf: Buffer;
  try {
    buf = fs.readFileSync(uri.fsPath);
  } catch (e) {
    return {
      uri,
      header: { validMagic: false, version: 0, flags: 0, payloadLen: 0, fileSize: 0 },
      policy: null,
      parseError: `Cannot read file: ${e}`,
      dispose: () => {},
    };
  }

  const fileSize = buf.length;

  if (buf.length < HEADER_SIZE) {
    return {
      uri,
      header: { validMagic: false, version: 0, flags: 0, payloadLen: 0, fileSize },
      policy: null,
      parseError: `File too small to be a valid .aegisc (${buf.length} bytes, need at least ${HEADER_SIZE})`,
      dispose: () => {},
    };
  }

  const validMagic = MAGIC.every((b, i) => buf[i] === b);
  const version = buf.readUInt16LE(4);
  const flags = buf.readUInt16LE(6);
  const payloadLen = buf.readUInt32LE(8);

  const header: AegiscHeader = { validMagic, version, flags, payloadLen, fileSize };

  if (!validMagic) {
    return {
      uri,
      header,
      policy: null,
      parseError: `Invalid magic bytes. Got [${[...buf.slice(0, 4)]
        .map((b) => `0x${b.toString(16).padStart(2, "0").toUpperCase()}`)
        .join(", ")}], expected [0xAE, 0x91, 0x5C, 0x01].`,
      dispose: () => {},
    };
  }

  const payloadEnd = HEADER_SIZE + payloadLen;
  if (buf.length < payloadEnd) {
    return {
      uri,
      header,
      policy: null,
      parseError: `Truncated file: header declares ${payloadLen} bytes of payload but only ${buf.length - HEADER_SIZE} bytes remain.`,
      dispose: () => {},
    };
  }

  const payloadStr = buf.slice(HEADER_SIZE, payloadEnd).toString("utf8");
  try {
    const policy = JSON.parse(payloadStr) as Record<string, unknown>;
    return { uri, header, policy, parseError: null, dispose: () => {} };
  } catch (e) {
    return {
      uri,
      header,
      policy: null,
      parseError: `JSON payload parse error: ${e}`,
      dispose: () => {},
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════
//  Webview HTML for .aegisc inspector
// ═══════════════════════════════════════════════════════════════════════

function buildWebviewHtml(
  doc: AegiscDocument,
  _webview: vscode.Webview,
  _context: vscode.ExtensionContext
): string {
  const { header, policy, parseError } = doc;

  const fileName = path.basename(doc.uri.fsPath);

  // Helper: escape HTML
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  // ── Error state ──────────────────────────────────────────────────────
  if (parseError) {
    return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-font-family); padding: 20px;
         color: var(--vscode-foreground); background: var(--vscode-editor-background); }
  .error { color: var(--vscode-errorForeground); background: var(--vscode-inputValidation-errorBackground);
           border: 1px solid var(--vscode-inputValidation-errorBorder);
           padding: 12px 16px; border-radius: 4px; margin-top: 16px; }
  h1 { font-size: 1.1em; margin-bottom: 4px; }
</style></head><body>
<h1>⚠ ${esc(fileName)}</h1>
<div class="error">${esc(parseError)}</div>
</body></html>`;
  }

  if (!policy) {
    return `<!DOCTYPE html><html><body>No policy data.</body></html>`;
  }

  // ── Build summary sections ───────────────────────────────────────────
  const name = String(policy["name"] ?? "(unnamed)");
  const severity = String(policy["severity"] ?? "-");
  const scopes = (policy["scopes"] as string[] | undefined ?? []).join(", ") || "-";

  const rules = policy["rules"] as Array<Record<string, unknown>> | undefined ?? [];
  const constraints = policy["constraints"] as Array<Record<string, unknown>> | undefined ?? [];
  const stateMachines = policy["state_machines"] as Array<Record<string, unknown>> | undefined ?? [];
  const metadata = policy["metadata"] as Record<string, unknown> | undefined ?? {};

  const compilerVersion = String(metadata["compiler_version"] ?? "-");
  const sourceHash = metadata["source_hash"] != null
    ? "0x" + Number(metadata["source_hash"]).toString(16).toUpperCase()
    : "-";

  const rulesHtml = rules.length === 0
    ? "<p class='empty'>No rules.</p>"
    : rules.map((r, i) => {
        const id = r["id"] ?? i;
        const events = (r["on_events"] as string[] | undefined ?? []).join(", ");
        const verdicts = (r["verdicts"] as Array<Record<string, unknown>> | undefined ?? [])
          .map((v) => String(v["verdict"] ?? "?"))
          .join(", ");
        const sev = r["severity"] ? ` <span class="badge-sev badge-${String(r["severity"]).toLowerCase()}">${String(r["severity"])}</span>` : "";
        return `<div class="rule-row">
          <span class="rule-id">#${id}</span>
          <span class="rule-events">on <strong>${esc(events)}</strong></span>
          <span class="rule-verdict">${esc(verdicts)}</span>${sev}
        </div>`;
      }).join("");


  const constraintsHtml = constraints.length === 0
    ? "<p class='empty'>No rate limits or quotas.</p>"
    : constraints.map((c) => {
        const kind = String(c["kind"] ?? "-");
        const target = String(c["target"] ?? "-");
        const limit = c["limit"];
        const windowMs = c["window_millis"];
        return `<div class="constraint-row">
          <span class="badge-kind">${esc(kind)}</span>
          <strong>${esc(target)}</strong>: ${limit} per ${windowMs}ms
        </div>`;
      }).join("");

  const jsonPayload = JSON.stringify(policy, null, 2);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(fileName)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }

  body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
    background: var(--vscode-editor-background);
    margin: 0;
    padding: 0 24px 40px;
  }

  h1 { font-size: 1.15em; font-weight: 600; margin: 20px 0 4px; }
  h2 { font-size: 1em; font-weight: 600; margin: 24px 0 8px;
       border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 4px; }

  .header-bar {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 0; border-bottom: 1px solid var(--vscode-panel-border);
    margin-bottom: 8px;
  }
  .header-bar .policy-name { font-size: 1.3em; font-weight: 700; }
  .header-bar .file-name { color: var(--vscode-descriptionForeground); font-size: 0.9em; }

  .meta-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 8px; margin: 12px 0;
  }
  .meta-cell { background: var(--vscode-sideBar-background);
               border: 1px solid var(--vscode-panel-border);
               border-radius: 4px; padding: 8px 12px; }
  .meta-cell .label { font-size: 0.78em; text-transform: uppercase;
                      letter-spacing: 0.05em; color: var(--vscode-descriptionForeground);
                      margin-bottom: 2px; }
  .meta-cell .value { font-weight: 600; font-size: 0.95em;
                      font-family: var(--vscode-editor-font-family, monospace); }

  .rule-row, .sm-row, .constraint-row {
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    padding: 5px 8px; border-radius: 3px; font-size: 0.9em;
    border-bottom: 1px solid var(--vscode-panel-border);
  }
  .rule-row:hover, .sm-row:hover { background: var(--vscode-list-hoverBackground); }

  .rule-id { font-family: monospace; color: var(--vscode-descriptionForeground);
             min-width: 32px; }
  .rule-verdict { font-family: monospace; font-weight: 600; }
  .sm-name { font-family: monospace; font-weight: 600; }
  .sm-stats { color: var(--vscode-descriptionForeground); font-size: 0.88em; }

  .badge-kind {
    font-size: 0.78em; font-family: monospace; padding: 1px 6px;
    border-radius: 10px; background: var(--vscode-badge-background);
    color: var(--vscode-badge-foreground); white-space: nowrap;
  }
  .badge-info {
    font-size: 0.78em; padding: 1px 6px; border-radius: 10px;
    background: var(--vscode-inputOption-activeBackground);
    color: var(--vscode-inputOption-activeForeground); white-space: nowrap;
  }
  .badge-sev { font-size: 0.78em; padding: 1px 6px; border-radius: 10px; white-space: nowrap; }
  .badge-critical { background: #7c0f0f; color: #ffd7d7; }
  .badge-high     { background: #6b3a00; color: #ffe0b3; }
  .badge-medium   { background: #4a3c00; color: #fff3b3; }
  .badge-low      { background: #1a3a1a; color: #c8e6c9; }
  .badge-info-s   { background: #0d2b4a; color: #b3d1ff; }

  .empty { color: var(--vscode-descriptionForeground); font-style: italic; margin: 4px 0; }

  details { margin-top: 24px; }
  summary {
    cursor: pointer; font-weight: 600; font-size: 1em;
    padding: 6px 0; border-bottom: 1px solid var(--vscode-panel-border);
    user-select: none;
  }
  summary:hover { color: var(--vscode-textLink-foreground); }

  pre.json-view {
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.85em;
    background: var(--vscode-textBlockQuote-background);
    border: 1px solid var(--vscode-panel-border);
    border-radius: 4px;
    padding: 16px;
    overflow: auto;
    max-height: 600px;
    margin: 12px 0 0;
    white-space: pre;
    tab-size: 2;
  }

  .valid-chip { display: inline-flex; align-items: center; gap: 4px;
                font-size: 0.8em; padding: 2px 8px; border-radius: 10px;
                background: #1a3a1a; color: #a5d6a7; }

  /* ── State machine graph ─────────────────────────────────────── */
  .sm-graph-wrapper {
    margin: 12px 0;
    border: 1px solid var(--vscode-panel-border);
    border-radius: 6px;
    overflow: hidden;
  }
  .sm-graph-title {
    padding: 6px 12px;
    font-size: 0.85em;
    font-weight: 600;
    background: var(--vscode-sideBar-background);
    display: flex; align-items: center; gap: 8px;
    cursor: pointer;
    user-select: none;
  }
  .sm-graph-title:hover { background: var(--vscode-list-hoverBackground); }
  .sm-graph-title.open { border-bottom: 1px solid var(--vscode-panel-border); }
  .sm-graph-chevron {
    flex-shrink: 0;
    color: var(--vscode-foreground);
    opacity: 0.7;
    transition: transform 0.12s ease;
    transform: rotate(0deg);
  }
  .sm-graph-title.open .sm-graph-chevron {
    transform: rotate(90deg);
  }
  .sm-graph-title .sm-graph-kind {
    font-size: 0.78em; font-family: monospace; padding: 1px 6px;
    border-radius: 10px; background: var(--vscode-badge-background);
    color: var(--vscode-badge-foreground);
  }
  .sm-graph-title .sm-graph-inv {
    color: var(--vscode-descriptionForeground); font-weight: 400;
  }
  .sm-graph-body { display: none; }
  .sm-graph-body.open { display: block; }
  .sm-graph-svg-wrap {
    overflow-x: auto;
    background: var(--vscode-editor-background);
  }
  .sm-graph-legend {
    display: flex; gap: 14px; flex-wrap: wrap;
    padding: 6px 12px;
    font-size: 0.78em;
    border-top: 1px solid var(--vscode-panel-border);
    background: var(--vscode-sideBar-background);
    color: var(--vscode-descriptionForeground);
  }
  .sm-graph-legend span { display: flex; align-items: center; gap: 5px; }
  .legend-dot {
    display: inline-block; width: 10px; height: 10px;
    border-radius: 50%; flex-shrink: 0;
  }
  .sm-zoom-controls {
    margin-left: auto; display: flex; align-items: center; gap: 3px; flex-shrink: 0;
  }
  .sm-zoom-btn {
    background: var(--vscode-button-secondaryBackground, #3c3c3c);
    color: var(--vscode-button-secondaryForeground, #ccc);
    border: 1px solid var(--vscode-contrastBorder, transparent);
    border-radius: 3px; padding: 1px 7px; font-size: 0.85em;
    cursor: pointer; line-height: 1.5; user-select: none;
  }
  .sm-zoom-btn:hover { background: var(--vscode-button-secondaryHoverBackground, #505050); }
  .sm-zoom-label {
    font-size: 0.78em; color: var(--vscode-descriptionForeground);
    min-width: 38px; text-align: center; font-family: monospace;
  }
  .sm-graph-svg-inner { display: inline-block; }
</style>
</head>
<body>

<div class="header-bar">
  <span class="policy-name">${esc(name)}</span>
  <span class="file-name">${esc(fileName)}</span>
  <span class="valid-chip">✓ valid .aegisc</span>
</div>

<div class="meta-grid">
  <div class="meta-cell"><div class="label">Severity</div><div class="value">${esc(severity)}</div></div>
  <div class="meta-cell"><div class="label">Scopes</div><div class="value">${esc(scopes)}</div></div>
  <div class="meta-cell"><div class="label">Rules</div><div class="value">${rules.length}</div></div>
  <div class="meta-cell"><div class="label">State Machines</div><div class="value">${stateMachines.length}</div></div>
  <div class="meta-cell"><div class="label">Constraints</div><div class="value">${constraints.length}</div></div>
  <div class="meta-cell"><div class="label">Format Version</div><div class="value">${header.version}</div></div>
  <div class="meta-cell"><div class="label">Payload</div><div class="value">${header.payloadLen.toLocaleString()} bytes</div></div>
  <div class="meta-cell"><div class="label">Compiler</div><div class="value">${esc(compilerVersion)}</div></div>
  <div class="meta-cell"><div class="label">Source Hash</div><div class="value">${esc(sourceHash)}</div></div>
</div>

<h2>Rules (${rules.length})</h2>
${rulesHtml}

<h2>State Machines — Temporal Invariants (${stateMachines.length})</h2>
${stateMachines.length === 0 ? "<p class='empty'>No state machines (no temporal invariants).</p>" : ""}
<div id="sm-graphs"></div>

<h2>Constraints (${constraints.length})</h2>
${constraintsHtml}

<details>
  <summary>Full JSON payload</summary>
  <pre class="json-view">${esc(jsonPayload)}</pre>
</details>

<script>
(function () {
  // ── Injected data ────────────────────────────────────────────────────
  const SM_DATA = ${JSON.stringify(stateMachines)};

  // ── Edge colour palette (bright, works on dark backgrounds) ─────────
  const EDGE_COLORS = [
    '#f59e0b',  // amber
    '#06b6d4',  // cyan
    '#a78bfa',  // violet
    '#fb7185',  // rose
    '#fbbf24',  // yellow
    '#60a5fa',  // sky blue
    '#f97316',  // orange
    '#e879f9',  // fuchsia
    '#34d399',  // emerald
    '#f43f5e',  // pink-red
  ];

  // ── Guard → short human-readable label ──────────────────────────────
  const OP_SYMBOLS = {
    And: '\u2227', Or: '\u2228', Eq: '=', Ne: '\u2260',
    Gt: '>', Lt: '<', Ge: '\u2265', Le: '\u2264',
    Add: '+', Sub: '\u2212', Mul: '\u00d7', Div: '\u00f7',
  };

  function summarizeExpr(e, depth) {
    if (!e || depth > 3) return '\u2026';
    const k = Object.keys(e)[0];
    if (!k) return '?';
    const v = e[k];
    if (k === 'Binary') {
      const l = summarizeExpr(v.left, depth + 1);
      const r = summarizeExpr(v.right, depth + 1);
      return l + ' ' + (OP_SYMBOLS[v.op] || v.op) + ' ' + r;
    }
    if (k === 'Unary') {
      if (v.op === 'Not') return '\u00ac' + summarizeExpr(v.operand, depth + 1);
      return v.op + '(' + summarizeExpr(v.operand, depth + 1) + ')';
    }
    if (k === 'Ref') {
      return [v.root.toLowerCase()].concat(v.fields || []).join('.');
    }
    if (k === 'Literal') {
      const lk = Object.keys(v)[0];
      return lk === 'String' ? '"' + v[lk] + '"' : String(v[lk]);
    }
    if (k === 'Count') {
      return 'count(' + summarizeExpr(v.collection, depth + 1) + ')';
    }
    if (k === 'FieldAccess') {
      return summarizeExpr(v.object, depth + 1) + '.' + v.field;
    }
    return k;
  }

  function summarizeGuard(guard) {
    if (!guard) return '';
    const k = Object.keys(guard)[0];
    if (!k) return '';
    if (k === 'Predicate') return summarizeExpr(guard[k], 0);
    if (k === 'NegatedPredicate') return '\u00ac(' + summarizeExpr(guard[k], 0) + ')';
    if (k === 'Always') return 'always(\u2026)';
    if (k === 'Timeout') return 'timeout';
    return k;
  }

  function trunc(s, n) {
    return s.length > n ? s.slice(0, n) + '\u2026' : s;
  }

  // ── State colours ────────────────────────────────────────────────────
  function stateColor(kind, isViolating, isAccepting) {
    if (isViolating || kind === 'Violated')  return { fill: '#7f1d1d', stroke: '#ef4444', text: '#fca5a5' };
    if (isAccepting || kind === 'Satisfied') return { fill: '#14532d', stroke: '#22c55e', text: '#86efac' };
    if (kind === 'Active' || kind === 'Initial') return { fill: '#1e1b4b', stroke: '#6366f1', text: '#a5b4fc' };
    return { fill: '#1c1917', stroke: '#78716c', text: '#a8a29e' };
  }

  // ── Layout ───────────────────────────────────────────────────────────
  // Returns {id: {x,y}} positions on a circle of radius R, initial state at left.
  function layoutStates(states, W, H, initialId, R) {
    const n = states.length;
    if (n === 0) return {};
    const cx = W / 2, cy = H / 2;
    const pos = {};
    if (n === 1) {
      pos[states[0].id] = { x: cx, y: cy };
      return pos;
    }
    const initIdx = states.findIndex(function (s) { return s.id === initialId; });
    states.forEach(function (s, i) {
      const offset = (i - (initIdx >= 0 ? initIdx : 0) + n) % n;
      const angle = Math.PI + (2 * Math.PI * offset / n); // initial at left (angle=π)
      pos[s.id] = { x: cx + R * Math.cos(angle), y: cy + R * Math.sin(angle) };
    });
    return pos;
  }

  // Push a point away from all node centres that are within clearance px.
  // Returns adjusted {x, y}.
  function avoidNodes(x, y, nodePositions, clearance) {
    let ox = x, oy = y;
    for (let iter = 0; iter < 6; iter++) {
      let moved = false;
      nodePositions.forEach(function (p) {
        const dx = ox - p.x, dy = oy - p.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        if (d < clearance) {
          const push = (clearance - d) / d;
          ox += dx * push;
          oy += dy * push;
          moved = true;
        }
      });
      if (!moved) break;
    }
    return { x: ox, y: oy };
  }

  // ── SVG helpers ──────────────────────────────────────────────────────
  const NS = 'http://www.w3.org/2000/svg';

  function svgEl(tag, attrs, children) {
    const node = document.createElementNS(NS, tag);
    Object.entries(attrs || {}).forEach(function (kv) { node.setAttribute(kv[0], String(kv[1])); });
    (children || []).forEach(function (c) { node.appendChild(c); });
    return node;
  }

  function svgText(content, attrs) {
    const t = svgEl('text', attrs);
    t.textContent = content;
    return t;
  }

  // ── Edge-label layout constants ──────────────────────────────────────
  const LABEL_CHAR_W = 5.8;
  const LABEL_PAD    = 10;
  const LABEL_H      = 16;

  function labelWidth(text) {
    return text.length * LABEL_CHAR_W + LABEL_PAD;
  }

  // Edge label: plain coloured text, no background — colour matches the edge.
  function svgEdgeLabel(content, x, y, color) {
    return svgText(content, {
      x: x, y: y + 4,
      'text-anchor': 'middle', 'font-size': '10',
      'font-family': 'monospace', fill: color || '#cbd5e1',
    });
  }

  // Iteratively push labels away from each other and from nodes.
  // Each label: { text, x, y, w }  (h = LABEL_H for all)
  function resolveLabels(labels, nodePositions, nodeR, maxIter) {
    const GAP = 5; // minimum pixel gap between label pills
    for (let iter = 0; iter < maxIter; iter++) {
      let moved = false;

      // Label-label separation
      for (let i = 0; i < labels.length; i++) {
        for (let j = i + 1; j < labels.length; j++) {
          const a = labels[i], b = labels[j];
          const dx = b.x - a.x, dy = b.y - a.y;
          const minSepX = (a.w + b.w) / 2 + GAP;
          const minSepY = LABEL_H + GAP;
          if (Math.abs(dx) < minSepX && Math.abs(dy) < minSepY) {
            // Push radially along the centre-to-centre vector
            const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
            const overlapX = minSepX - Math.abs(dx);
            const overlapY = minSepY - Math.abs(dy);
            const push = Math.min(overlapX, overlapY) / 2 + 1;
            const nx = dx / d, ny = dy / d;
            a.x -= nx * push;  a.y -= ny * push;
            b.x += nx * push;  b.y += ny * push;
            moved = true;
          }
        }
      }

      // Re-apply node avoidance after each label-push pass
      labels.forEach(function (lbl) {
        const safe = avoidNodes(lbl.x, lbl.y, nodePositions, nodeR + LABEL_H + GAP);
        lbl.x = safe.x;  lbl.y = safe.y;
      });

      if (!moved) break;
    }
  }

  // Point on the border of a circle of radius r at (cx,cy) toward (tx,ty)
  function edgePoint(cx, cy, tx, ty, r) {
    const dx = tx - cx, dy = ty - cy;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    return { x: cx + (dx / d) * r, y: cy + (dy / d) * r };
  }

  // Perpendicular unit vector
  function perp(dx, dy) {
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    return { x: -dy / d, y: dx / d };
  }

  // ── Draw one state machine ───────────────────────────────────────────
  function drawSM(sm, smIdx) {
    const states      = sm.states      || [];
    const transitions = sm.transitions || [];
    const initialId   = sm.initial_state;
    const accepting   = new Set(sm.accepting_states  || []);
    const violating   = new Set(sm.violating_states  || []);

    const NODE_R = 34;
    const n      = states.length;

    // Circle radius: guarantee adjacent nodes are NODE_R*5 apart (plenty of
    // room for edge labels between them).
    // chord = 2R·sin(π/n) ≥ MIN_CHORD  →  R ≥ MIN_CHORD / (2·sin(π/n))
    const MIN_CHORD = NODE_R * 5;
    const layoutR = n <= 1 ? 0
                  : n === 2 ? MIN_CHORD
                  : (MIN_CHORD / 2) / Math.sin(Math.PI / n);

    // Canvas: circle + node radius + generous margin for labels + entry arrow
    const MARGIN = NODE_R + 130;
    const dim    = Math.max(640, Math.ceil(2 * (layoutR + MARGIN)));
    const W      = dim;
    const H      = n <= 2 ? 240 : dim;

    const svg = svgEl('svg', {
      width: W, height: H,
      viewBox: '0 0 ' + W + ' ' + H,
      style: 'display:block;',
    });

    // One arrowhead marker per palette colour so each edge's arrow matches its line.
    const markerBase = 'arrow-' + smIdx + '-';
    const defs = svgEl('defs', {});
    EDGE_COLORS.forEach(function (color, ci) {
      defs.appendChild(svgEl('marker', {
        id: markerBase + ci, markerWidth: '10', markerHeight: '7',
        refX: '9', refY: '3.5', orient: 'auto',
      }, [svgEl('polygon', { points: '0 0, 10 3.5, 0 7', fill: color })]));
    });
    svg.appendChild(defs);

    // Node positions
    let pos;
    if (n === 2) {
      const cy    = H / 2;
      const initId = initialId !== undefined ? initialId : states[0].id;
      const other  = states.find(function (s) { return s.id !== initId; });
      pos = {};
      pos[initId] = { x: W * 0.25, y: cy };
      if (other) { pos[other.id] = { x: W * 0.75, y: cy }; }
    } else {
      pos = layoutStates(states, W, H, initialId, layoutR);
    }

    const nodeCentres = states.map(function (s) { return pos[s.id]; }).filter(Boolean);

    // ── Pass 1: compute edge paths + raw label positions ────────────────
    const edgeSet = new Set();
    transitions.forEach(function (t) { edgeSet.add(t.from + '-' + t.to); });

    const edgeAttrs  = [];  // { pathAttrs, color }
    const labelItems = [];  // { text, x, y, w, color }
    let   colorIdx   = 0;

    transitions.forEach(function (t) {
      const sp = pos[t.from], ep = pos[t.to];
      if (!sp || !ep) return;
      const color     = EDGE_COLORS[colorIdx % EDGE_COLORS.length];
      const arrowRef  = 'url(#' + markerBase + (colorIdx % EDGE_COLORS.length) + ')';
      colorIdx++;
      const labelText = trunc(summarizeGuard(t.guard), 30);
      const isBidi    = t.from !== t.to && edgeSet.has(t.to + '-' + t.from);

      if (t.from === t.to) {
        const loopW = NODE_R * 0.75;
        const loopH = NODE_R * 2.0;
        const lx = sp.x - loopW, rx = sp.x + loopW;
        const topY = sp.y - NODE_R - loopH;
        edgeAttrs.push({
          pathAttrs: {
            d: 'M ' + lx + ' ' + (sp.y - NODE_R) +
               ' C ' + lx + ' ' + topY + ', ' + rx + ' ' + topY +
               ', '  + rx + ' ' + (sp.y - NODE_R),
            fill: 'none', stroke: color, 'stroke-width': '1.5',
            'marker-end': arrowRef,
          },
        });
        if (labelText) {
          labelItems.push({ text: labelText, x: sp.x, y: topY - LABEL_H, w: labelWidth(labelText), color: color });
        }
      } else {
        const dx  = ep.x - sp.x, dy = ep.y - sp.y;
        const src = edgePoint(sp.x, sp.y, ep.x, ep.y, NODE_R);
        const dst = edgePoint(ep.x, ep.y, sp.x, sp.y, NODE_R + 10);
        const pv  = perp(dx, dy);
        const curve = isBidi ? 60 : 35;
        const sign  = (isBidi && t.from > t.to) ? -1 : 1;
        const qcx = (src.x + dst.x) / 2 + pv.x * curve * sign;
        const qcy = (src.y + dst.y) / 2 + pv.y * curve * sign;
        edgeAttrs.push({
          pathAttrs: {
            d: 'M ' + src.x + ' ' + src.y + ' Q ' + qcx + ' ' + qcy + ' ' + dst.x + ' ' + dst.y,
            fill: 'none', stroke: color, 'stroke-width': '1.5',
            'marker-end': arrowRef,
          },
        });
        if (labelText) {
          labelItems.push({
            text: labelText,
            x: 0.25 * src.x + 0.5 * qcx + 0.25 * dst.x,
            y: 0.25 * src.y + 0.5 * qcy + 0.25 * dst.y,
            w: labelWidth(labelText),
            color: color,
          });
        }
      }
    });

    // ── Pass 2: resolve label positions (node avoidance + label separation)
    labelItems.forEach(function (lbl) {
      const safe = avoidNodes(lbl.x, lbl.y, nodeCentres, NODE_R + LABEL_H + 8);
      lbl.x = safe.x;  lbl.y = safe.y;
    });
    resolveLabels(labelItems, nodeCentres, NODE_R, 40);

    // ── Render: entry arrow ─────────────────────────────────────────────
    const initPos = pos[initialId];
    if (initPos) {
      svg.appendChild(svgEl('line', {
        x1: initPos.x - NODE_R - 32, y1: initPos.y,
        x2: initPos.x - NODE_R - 2,  y2: initPos.y,
        stroke: '#64748b', 'stroke-width': '1.5',
        'marker-end': 'url(#' + markerBase + '0)',
      }));
    }

    // ── Render: edges ───────────────────────────────────────────────────
    edgeAttrs.forEach(function (e) {
      svg.appendChild(svgEl('path', e.pathAttrs));
    });

    // ── Render: edge labels ─────────────────────────────────────────────
    labelItems.forEach(function (lbl) {
      svg.appendChild(svgEdgeLabel(lbl.text, lbl.x, lbl.y, lbl.color));
    });

    // ── Render: nodes (on top of everything) ────────────────────────────
    states.forEach(function (s) {
      const p = pos[s.id];
      if (!p) return;
      const col = stateColor(s.kind, violating.has(s.id), accepting.has(s.id));

      if (accepting.has(s.id)) {
        svg.appendChild(svgEl('circle', {
          cx: p.x, cy: p.y, r: NODE_R + 7,
          fill: 'none', stroke: col.stroke, 'stroke-width': '1',
          'stroke-dasharray': '4,3', opacity: '0.5',
        }));
      }

      svg.appendChild(svgEl('circle', {
        cx: p.x, cy: p.y, r: NODE_R,
        fill: col.fill, stroke: col.stroke, 'stroke-width': '2',
      }));

      // State name: one line if short, two lines if long (split at underscore)
      const rawLabel = s.label || s.kind || String(s.id);
      if (rawLabel.length <= 9) {
        svg.appendChild(svgText(rawLabel, {
          x: p.x, y: p.y - 1,
          'text-anchor': 'middle', 'font-size': '11',
          'font-family': 'monospace', fill: col.text,
        }));
      } else {
        const mid   = rawLabel.indexOf('_', Math.floor(rawLabel.length / 3));
        const split = mid > 0 ? mid + 1 : Math.ceil(rawLabel.length / 2);
        svg.appendChild(svgText(rawLabel.slice(0, split), {
          x: p.x, y: p.y - 8,
          'text-anchor': 'middle', 'font-size': '10',
          'font-family': 'monospace', fill: col.text,
        }));
        svg.appendChild(svgText(rawLabel.slice(split), {
          x: p.x, y: p.y + 5,
          'text-anchor': 'middle', 'font-size': '10',
          'font-family': 'monospace', fill: col.text,
        }));
      }

      // State id — inside the node, below the name, same font
      svg.appendChild(svgText('s' + s.id, {
        x: p.x, y: p.y + NODE_R - 8,
        'text-anchor': 'middle', 'font-size': '11',
        'font-family': 'monospace', fill: col.text,
      }));
    });

    return svg;
  }

  // ── Mount all graphs ─────────────────────────────────────────────────
  const container = document.getElementById('sm-graphs');
  if (!container || SM_DATA.length === 0) return;

  SM_DATA.forEach(function (sm, smIdx) {
    const wrapper = document.createElement('div');
    wrapper.className = 'sm-graph-wrapper';

    // ── Title bar ────────────────────────────────────────────────────────
    const titleBar = document.createElement('div');
    titleBar.className = 'sm-graph-title';
    const deadline = sm.deadline_millis
      ? ' <span class="sm-graph-kind">deadline: ' + sm.deadline_millis + 'ms</span>'
      : '';

    // Zoom controls (right side of title bar — stopPropagation prevents collapse toggle)
    const zoomControls = document.createElement('span');
    zoomControls.className = 'sm-zoom-controls';
    zoomControls.innerHTML =
      '<button class="sm-zoom-btn" data-role="out" title="Zoom out">\u2212</button>' +
      '<span class="sm-zoom-label">100%</span>' +
      '<button class="sm-zoom-btn" data-role="in"  title="Zoom in">+</button>' +
      '<button class="sm-zoom-btn" data-role="rst" title="Reset zoom">\u27f3</button>';

    titleBar.innerHTML =
      '<svg class="sm-graph-chevron" viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 4l4 4-4 4"/></svg>' +
      '<strong>' + (sm.name || '(unnamed)') + '</strong>' +
      ' <span class="sm-graph-inv">invariant: ' + (sm.invariant_name || '-') + '</span>' +
      ' <span class="sm-graph-kind">' + (sm.kind || '-') + '</span>' +
      deadline;
    titleBar.appendChild(zoomControls);
    wrapper.appendChild(titleBar);

    // ── Collapsible body ─────────────────────────────────────────────────
    const body = document.createElement('div');
    body.className = 'sm-graph-body';

    // svgWrap scrolls; svgInner is sized to the scaled content area
    const svgWrap = document.createElement('div');
    svgWrap.className = 'sm-graph-svg-wrap';
    svgWrap.style.overflow = 'auto';

    const svgInner = document.createElement('div');
    svgInner.className = 'sm-graph-svg-inner';

    const svgEl = drawSM(sm, smIdx);
    const origW = parseInt(svgEl.getAttribute('width')  || '640');
    const origH = parseInt(svgEl.getAttribute('height') || '360');
    svgEl.style.transformOrigin = '0 0';
    svgEl.style.display = 'block';

    svgInner.appendChild(svgEl);
    svgWrap.appendChild(svgInner);
    body.appendChild(svgWrap);

    const legend = document.createElement('div');
    legend.className = 'sm-graph-legend';
    legend.innerHTML =
      '<span><span class="legend-dot" style="background:#1e1b4b;border:1.5px solid #6366f1"></span>active</span>' +
      '<span><span class="legend-dot" style="background:#14532d;border:1.5px solid #22c55e"></span>satisfied</span>' +
      '<span><span class="legend-dot" style="background:#7f1d1d;border:1.5px solid #ef4444"></span>violated</span>' +
      '<span><span class="legend-dot" style="background:none;border:1.5px dashed #22c55e"></span>accepting</span>' +
      '<span>\u2192 initial</span>';
    body.appendChild(legend);

    wrapper.appendChild(body);

    // ── Zoom logic ───────────────────────────────────────────────────────
    const ZOOM_MIN = 0.25, ZOOM_MAX = 4.0, ZOOM_STEP = 0.25;
    let zoom = 1.0;
    const zoomLabel = zoomControls.querySelector('.sm-zoom-label');

    function applyZoom(level) {
      zoom = Math.round(Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, level)) * 20) / 20;
      svgEl.style.transform = 'scale(' + zoom + ')';
      svgInner.style.width  = Math.ceil(origW * zoom) + 'px';
      svgInner.style.height = Math.ceil(origH * zoom) + 'px';
      if (zoomLabel) { zoomLabel.textContent = Math.round(zoom * 100) + '%'; }
    }

    zoomControls.addEventListener('click', function (e) {
      e.stopPropagation(); // don't trigger collapse toggle
      const btn = /** @type {HTMLElement} */ (e.target);
      const role = btn && btn.dataset ? btn.dataset.role : null;
      if (role === 'in')  { applyZoom(zoom + ZOOM_STEP); }
      if (role === 'out') { applyZoom(zoom - ZOOM_STEP); }
      if (role === 'rst') { applyZoom(1.0); }
    });

    svgWrap.addEventListener('wheel', function (e) {
      if (!e.ctrlKey && !e.metaKey) { return; } // Ctrl/Cmd + scroll to zoom
      e.preventDefault();
      applyZoom(zoom * (e.deltaY < 0 ? 1.1 : 0.9));
    }, { passive: false });

    // ── Collapse toggle ──────────────────────────────────────────────────
    titleBar.addEventListener('click', function () {
      const isOpen = body.classList.contains('open');
      body.classList.toggle('open', !isOpen);
      titleBar.classList.toggle('open', !isOpen);
    });

    container.appendChild(wrapper);
  });
})();
</script>

</body>
</html>`;
}
