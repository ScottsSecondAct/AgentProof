"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
// ═══════════════════════════════════════════════════════════════════════
//  Extension entry point
// ═══════════════════════════════════════════════════════════════════════
function activate(context) {
    const diagnostics = vscode.languages.createDiagnosticCollection("aegis");
    context.subscriptions.push(diagnostics);
    // Offer to activate Aegis file icons on first install, but only if the
    // user hasn't already seen the prompt and the current icon theme isn't ours.
    const iconPromptKey = "aegis.iconPromptShown";
    const alreadyPrompted = context.globalState.get(iconPromptKey, false);
    if (!alreadyPrompted) {
        context.globalState.update(iconPromptKey, true);
        const currentTheme = vscode.workspace
            .getConfiguration("workbench")
            .get("iconTheme");
        if (currentTheme !== "aegis-icons") {
            vscode.window
                .showInformationMessage("Aegis: Enable Aegis file icons for .aegis and .aegisc files?", "Enable", "Not now")
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
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument((doc) => {
        if (doc.languageId !== "aegis") {
            return;
        }
        const cfg = vscode.workspace.getConfiguration("aegis", doc.uri);
        if (cfg.get("checkOnSave", true)) {
            runCheck(doc.uri, diagnostics);
        }
    }));
    // Clear diagnostics when a .aegis file is closed
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument((doc) => {
        if (doc.languageId === "aegis") {
            diagnostics.delete(doc.uri);
        }
    }));
    // Register commands
    context.subscriptions.push(vscode.commands.registerCommand("aegis.check", async () => {
        const uri = activeAegisUri();
        if (!uri) {
            return;
        }
        await runCheck(uri, diagnostics, true);
    }), vscode.commands.registerCommand("aegis.compile", async () => {
        const uri = activeAegisUri();
        if (!uri) {
            return;
        }
        await runCompile(uri);
    }), vscode.commands.registerCommand("aegis.dump", async () => {
        const uri = activeAegisUri();
        if (!uri) {
            return;
        }
        await runDump(uri);
    }));
    // Register the .aegisc custom readonly editor
    context.subscriptions.push(vscode.window.registerCustomEditorProvider("aegis.aegiscInspector", new AegiscEditorProvider(context), {
        supportsMultipleEditorsPerDocument: false,
        webviewOptions: { retainContextWhenHidden: true },
    }));
    console.log("Aegis Policy Language extension activated");
}
function deactivate() { }
// ═══════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════
function activeAegisUri() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage("No active editor.");
        return undefined;
    }
    if (editor.document.languageId !== "aegis" &&
        !editor.document.fileName.endsWith(".aegis")) {
        vscode.window.showErrorMessage("Active file is not an .aegis policy.");
        return undefined;
    }
    return editor.document.uri;
}
function compilerPath(uri) {
    const cfg = vscode.workspace.getConfiguration("aegis", uri);
    const configured = cfg.get("compilerPath", "aegisc");
    // If the user explicitly set a non-default path, honour it as-is.
    if (configured !== "aegisc") {
        return configured;
    }
    // Auto-discover: prefer release build, fall back to debug build, then PATH.
    const workspaceFolders = vscode.workspace.workspaceFolders;
    const roots = workspaceFolders
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
async function runCheck(uri, diagnosticCollection, showFeedback = false) {
    const compiler = compilerPath(uri);
    const filePath = uri.fsPath;
    const fileName = path.basename(filePath);
    const statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusItem.text = `$(sync~spin) aegisc: checking ${fileName}…`;
    statusItem.show();
    return new Promise((resolve) => {
        cp.exec(`"${compiler}" check "${filePath}"`, { cwd: path.dirname(filePath) }, (err, _stdout, stderr) => {
            statusItem.dispose();
            // Compiler not found: ENOENT means the binary doesn't exist
            if (err && err.code === "ENOENT") {
                vscode.window.showErrorMessage(`Aegis: compiler not found at "${compiler}". ` +
                    `Set aegis.compilerPath in settings or build the compiler with ` +
                    `"cargo build -p aegis-compiler".`);
                resolve();
                return;
            }
            const output = stderr || "";
            const parsed = parseDiagnostics(output, uri);
            diagnosticCollection.set(uri, parsed);
            if (showFeedback) {
                if (parsed.length === 0) {
                    vscode.window.setStatusBarMessage(`$(check) aegisc: ${fileName} — no errors`, 4000);
                }
                else {
                    const errors = parsed.filter((d) => d.severity === vscode.DiagnosticSeverity.Error).length;
                    const warnings = parsed.filter((d) => d.severity === vscode.DiagnosticSeverity.Warning).length;
                    const parts = [];
                    if (errors > 0) {
                        parts.push(`${errors} error${errors !== 1 ? "s" : ""}`);
                    }
                    if (warnings > 0) {
                        parts.push(`${warnings} warning${warnings !== 1 ? "s" : ""}`);
                    }
                    vscode.window.setStatusBarMessage(`$(error) aegisc: ${parts.join(", ")}`, 6000);
                }
            }
            resolve();
        });
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
function parseDiagnostics(output, fileUri) {
    const results = [];
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
        const severity = severityStr === "error"
            ? vscode.DiagnosticSeverity.Error
            : vscode.DiagnosticSeverity.Warning;
        // Scan forward for the location line
        let location;
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
            const targetUri = diagnosticUri.fsPath === fileUri.fsPath ? fileUri : diagnosticUri;
            // VS Code uses 0-based line/column; aegisc uses 1-based
            const range = new vscode.Range(location.line - 1, Math.max(0, location.col - 1), location.line - 1, Math.max(0, location.col - 1) + 80 // extend to end of likely token
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
    const maxDiags = cfg.get("maxDiagnostics", 100);
    return results.slice(0, maxDiags);
}
// ═══════════════════════════════════════════════════════════════════════
//  aegisc compile
// ═══════════════════════════════════════════════════════════════════════
async function runCompile(uri) {
    const compiler = compilerPath(uri);
    const filePath = uri.fsPath;
    const outputPath = filePath.replace(/\.aegis$/, ".aegisc");
    const channel = getOutputChannel();
    channel.show(true);
    channel.appendLine(`\n[aegis] Compiling ${path.basename(filePath)}...`);
    return new Promise((resolve) => {
        cp.exec(`"${compiler}" compile "${filePath}" -o "${outputPath}"`, { cwd: path.dirname(filePath) }, (err, _stdout, stderr) => {
            const output = (stderr || "").trim();
            if (output) {
                channel.appendLine(output);
            }
            if (err) {
                channel.appendLine(`[aegis] Compilation failed (exit ${err.code})`);
                vscode.window.showErrorMessage(`Aegis: compilation failed — see Output panel for details.`);
            }
            else {
                channel.appendLine(`[aegis] Written: ${path.basename(outputPath)}`);
                vscode.window.showInformationMessage(`Aegis: compiled to ${path.basename(outputPath)}`);
            }
            resolve();
        });
    });
}
// ═══════════════════════════════════════════════════════════════════════
//  aegisc dump — open compiled IR as JSON in a new editor
// ═══════════════════════════════════════════════════════════════════════
async function runDump(uri) {
    const compiler = compilerPath(uri);
    const filePath = uri.fsPath;
    return new Promise((resolve) => {
        cp.exec(`"${compiler}" dump "${filePath}"`, { cwd: path.dirname(filePath), maxBuffer: 10 * 1024 * 1024 }, async (err, stdout, stderr) => {
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
            }
            catch {
                // leave as-is if already formatted
            }
            const doc = await vscode.workspace.openTextDocument({
                language: "json",
                content: pretty,
            });
            await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
            resolve();
        });
    });
}
// ═══════════════════════════════════════════════════════════════════════
//  Shared output channel
// ═══════════════════════════════════════════════════════════════════════
let _outputChannel;
function getOutputChannel() {
    if (!_outputChannel) {
        _outputChannel = vscode.window.createOutputChannel("Aegis");
    }
    return _outputChannel;
}
class AegiscEditorProvider {
    constructor(context) {
        this.context = context;
    }
    async openCustomDocument(uri, _openContext, _token) {
        return readAegiscDocument(uri);
    }
    async resolveCustomEditor(document, webviewPanel, _token) {
        webviewPanel.webview.options = { enableScripts: true };
        webviewPanel.webview.html = buildWebviewHtml(document, webviewPanel.webview, this.context);
    }
}
function readAegiscDocument(uri) {
    const MAGIC = [0xae, 0x91, 0x5c, 0x01];
    const HEADER_SIZE = 12;
    let buf;
    try {
        buf = fs.readFileSync(uri.fsPath);
    }
    catch (e) {
        return {
            uri,
            header: { validMagic: false, version: 0, flags: 0, payloadLen: 0, fileSize: 0 },
            policy: null,
            parseError: `Cannot read file: ${e}`,
            dispose: () => { },
        };
    }
    const fileSize = buf.length;
    if (buf.length < HEADER_SIZE) {
        return {
            uri,
            header: { validMagic: false, version: 0, flags: 0, payloadLen: 0, fileSize },
            policy: null,
            parseError: `File too small to be a valid .aegisc (${buf.length} bytes, need at least ${HEADER_SIZE})`,
            dispose: () => { },
        };
    }
    const validMagic = MAGIC.every((b, i) => buf[i] === b);
    const version = buf.readUInt16LE(4);
    const flags = buf.readUInt16LE(6);
    const payloadLen = buf.readUInt32LE(8);
    const header = { validMagic, version, flags, payloadLen, fileSize };
    if (!validMagic) {
        return {
            uri,
            header,
            policy: null,
            parseError: `Invalid magic bytes. Got [${[...buf.slice(0, 4)]
                .map((b) => `0x${b.toString(16).padStart(2, "0").toUpperCase()}`)
                .join(", ")}], expected [0xAE, 0x91, 0x5C, 0x01].`,
            dispose: () => { },
        };
    }
    const payloadEnd = HEADER_SIZE + payloadLen;
    if (buf.length < payloadEnd) {
        return {
            uri,
            header,
            policy: null,
            parseError: `Truncated file: header declares ${payloadLen} bytes of payload but only ${buf.length - HEADER_SIZE} bytes remain.`,
            dispose: () => { },
        };
    }
    const payloadStr = buf.slice(HEADER_SIZE, payloadEnd).toString("utf8");
    try {
        const policy = JSON.parse(payloadStr);
        return { uri, header, policy, parseError: null, dispose: () => { } };
    }
    catch (e) {
        return {
            uri,
            header,
            policy: null,
            parseError: `JSON payload parse error: ${e}`,
            dispose: () => { },
        };
    }
}
// ═══════════════════════════════════════════════════════════════════════
//  Webview HTML for .aegisc inspector
// ═══════════════════════════════════════════════════════════════════════
function buildWebviewHtml(doc, _webview, _context) {
    const { header, policy, parseError } = doc;
    const fileName = path.basename(doc.uri.fsPath);
    // Helper: escape HTML
    const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
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
    const scopes = (policy["scopes"] ?? []).join(", ") || "-";
    const rules = policy["rules"] ?? [];
    const constraints = policy["constraints"] ?? [];
    const stateMachines = policy["state_machines"] ?? [];
    const metadata = policy["metadata"] ?? {};
    const compilerVersion = String(metadata["compiler_version"] ?? "-");
    const sourceHash = metadata["source_hash"] != null
        ? "0x" + Number(metadata["source_hash"]).toString(16).toUpperCase()
        : "-";
    const rulesHtml = rules.length === 0
        ? "<p class='empty'>No rules.</p>"
        : rules.map((r, i) => {
            const id = r["id"] ?? i;
            const events = (r["on_events"] ?? []).join(", ");
            const verdicts = (r["verdicts"] ?? [])
                .map((v) => String(v["verdict"] ?? "?"))
                .join(", ");
            const sev = r["severity"] ? ` <span class="badge-sev badge-${String(r["severity"]).toLowerCase()}">${String(r["severity"])}</span>` : "";
            return `<div class="rule-row">
          <span class="rule-id">#${id}</span>
          <span class="rule-events">on <strong>${esc(events)}</strong></span>
          <span class="rule-verdict">${esc(verdicts)}</span>${sev}
        </div>`;
        }).join("");
    const smHtml = stateMachines.length === 0
        ? "<p class='empty'>No state machines (no temporal invariants).</p>"
        : stateMachines.map((sm) => {
            const smName = String(sm["name"] ?? "-");
            const invName = String(sm["invariant_name"] ?? "-");
            const kind = String(sm["kind"] ?? "-");
            const states = (sm["states"] ?? []).length;
            const transitions = (sm["transitions"] ?? []).length;
            const deadline = sm["deadline_millis"] != null
                ? ` <span class="badge-info">deadline: ${sm["deadline_millis"]}ms</span>` : "";
            return `<div class="sm-row">
          <span class="sm-name">${esc(smName)}</span>
          <span class="sm-inv">invariant: <em>${esc(invName)}</em></span>
          <span class="sm-kind badge-kind">${esc(kind)}</span>
          <span class="sm-stats">${states} states · ${transitions} transitions</span>${deadline}
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
${smHtml}

<h2>Constraints (${constraints.length})</h2>
${constraintsHtml}

<details>
  <summary>Full JSON payload</summary>
  <pre class="json-view">${esc(jsonPayload)}</pre>
</details>

</body>
</html>`;
}
//# sourceMappingURL=extension.js.map