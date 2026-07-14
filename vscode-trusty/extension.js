const vscode = require('vscode');
const { exec } = require('child_process');

function activate(context) {
    let scanCmd = vscode.commands.registerCommand('trusty.scan', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;

        const doc = editor.document;
        const filePath = doc.uri.fsPath;
        const config = vscode.workspace.getConfiguration('trusty');
        const cliPath = config.get('cliPath', 'trusty');

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: 'Trusty: Scanning file...'
        }, () => {
            return new Promise((resolve) => {
                exec(`${cliPath} scan --diff-file /dev/null --format json --min-score 0`, {
                    cwd: vscode.workspace.rootPath,
                    env: Object.assign({}, process.env, { CI: 'true' })
                }, (err, stdout) => {
                    try {
                        const result = JSON.parse(stdout);
                        const diagnostics = [];
                        if (result.files) {
                            for (const file of result.files) {
                                if (file.path === filePath || file.path.endsWith('/' + filePath)) {
                                    for (const finding of file.findings) {
                                        const diag = new vscode.Diagnostic(
                                            new vscode.Range(0, 0, 0, 0),
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

                        const diagCollection = vscode.languages.createDiagnosticCollection('trusty');
                        diagCollection.set(editor.document.uri, diagnostics);
                    } catch (e) {
                        vscode.window.showErrorMessage(`Trusty: Failed to parse scan results: ${e.message}`);
                    }
                    resolve();
                });
            });
        });
    });

    context.subscriptions.push(scanCmd);
}

function deactivate() {}

module.exports = { activate, deactivate };
