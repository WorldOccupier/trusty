const vscode = require('vscode');
const { exec } = require('child_process');

function activate(context) {
    const diagCollection = vscode.languages.createDiagnosticCollection('trusty');
    context.subscriptions.push(diagCollection);

    function getCliPath() {
        return vscode.workspace.getConfiguration('trusty').get('cliPath', 'trusty');
    }

    function scanFile(uri) {
        const config = vscode.workspace.getConfiguration('trusty');
        const cliPath = config.get('cliPath', 'trusty');
        const rootPath = vscode.workspace.rootPath;
        if (!rootPath) return;

        exec(`${cliPath} scan --diff-file /dev/null --format json --min-score 0`, {
            cwd: rootPath,
            env: Object.assign({}, process.env, { CI: 'true' })
        }, (err, stdout) => {
            try {
                const result = JSON.parse(stdout);
                const diagnostics = [];
                if (result.files) {
                    for (const file of result.files) {
                        const filePath = uri ? uri.fsPath : '';
                        if (!filePath || file.path === filePath || file.path.endsWith('/' + filePath)) {
                            for (const finding of file.findings) {
                                const line = Math.max(0, (finding.line || 1) - 1);
                                const diag = new vscode.Diagnostic(
                                    new vscode.Range(line, 0, line, 200),
                                    `[${finding.rule}] ${finding.message}`,
                                    finding.severity >= 3 ? vscode.DiagnosticSeverity.Error :
                                    finding.severity >= 2 ? vscode.DiagnosticSeverity.Warning :
                                    vscode.DiagnosticSeverity.Information
                                );
                                diagnostics.push(diag);
                            }
                        }
                    }
                }
                if (uri) {
                    diagCollection.set(uri, diagnostics);
                }
            } catch (e) {
                // scan results not available yet
            }
        });
    }

    let scanCmd = vscode.commands.registerCommand('trusty.scan', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;
        const doc = editor.document;

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: 'Trusty: Scanning file...'
        }, () => {
            return new Promise((resolve) => {
                scanFile(doc.uri);
                resolve();
            });
        });
    });

    let scanAllCmd = vscode.commands.registerCommand('trusty.scanAll', () => {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: 'Trusty: Scanning all files...'
        }, () => {
            return new Promise((resolve) => {
                const cliPath = getCliPath();
                const rootPath = vscode.workspace.rootPath;
                if (!rootPath) { resolve(); return; }

                exec(`${cliPath} scan --format json --min-score 0`, {
                    cwd: rootPath,
                    env: Object.assign({}, process.env, { CI: 'true' })
                }, (err, stdout) => {
                    try {
                        const result = JSON.parse(stdout);
                        if (result.files) {
                            for (const file of result.files) {
                                const uri = vscode.Uri.file(file.path);
                                const diagnostics = file.findings.map(f => {
                                    const line = Math.max(0, (f.line || 1) - 1);
                                    return new vscode.Diagnostic(
                                        new vscode.Range(line, 0, line, 200),
                                        `[${f.rule}] ${f.message}`,
                                        f.severity >= 3 ? vscode.DiagnosticSeverity.Error :
                                        f.severity >= 2 ? vscode.DiagnosticSeverity.Warning :
                                        vscode.DiagnosticSeverity.Information
                                    );
                                });
                                diagCollection.set(uri, diagnostics);
                            }
                        }
                    } catch (e) {
                        vscode.window.showErrorMessage(`Trusty: ${e.message}`);
                    }
                    resolve();
                });
            });
        });
    });

    let onSave = vscode.workspace.onDidSaveTextDocument((doc) => {
        const config = vscode.workspace.getConfiguration('trusty');
        if (config.get('scanOnSave', true)) {
            scanFile(doc.uri);
        }
    });

    context.subscriptions.push(scanCmd);
    context.subscriptions.push(scanAllCmd);
    context.subscriptions.push(onSave);
}

function deactivate() {}

module.exports = { activate, deactivate };
