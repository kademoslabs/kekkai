/**
 * Quick Fix Code Action Provider for Kekkai findings.
 *
 * Provides code actions to fix security issues using the kekkai fix command.
 * Security: Requires explicit user action, previews changes before applying.
 */

import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { Finding } from './types';
import { sanitizeError } from './sanitize';

const execFileAsync = promisify(execFile);

const KEKKAI_FIX_COMMAND = 'kekkai.applyFix';
const MAX_FIX_TIMEOUT_MS = 60000;

export interface FixContext {
    finding: Finding;
    filePath: string;
    workspacePath: string;
}

export class KekkaiCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
    ];

    private diagnosticToFinding: Map<string, Finding> = new Map();

    public setFindingForDiagnostic(diagnostic: vscode.Diagnostic, finding: Finding): void {
        const key = this.diagnosticKey(diagnostic);
        this.diagnosticToFinding.set(key, finding);
    }

    public clearFindings(): void {
        this.diagnosticToFinding.clear();
    }

    private diagnosticKey(diagnostic: vscode.Diagnostic): string {
        return `${diagnostic.range.start.line}:${diagnostic.range.start.character}:${diagnostic.message.substring(0, 50)}`;
    }

    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'kekkai') {
                continue;
            }

            const finding = this.diagnosticToFinding.get(this.diagnosticKey(diagnostic));
            if (!finding || finding.scanner !== 'semgrep') {
                continue;
            }

            const fixAction = this.createFixAction(document, diagnostic, finding);
            if (fixAction) {
                actions.push(fixAction);
            }
        }

        return actions;
    }

    private createFixAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        finding: Finding,
    ): vscode.CodeAction | null {
        const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
        if (!workspaceFolder) {
            return null;
        }

        const action = new vscode.CodeAction(
            `Fix: ${finding.title.substring(0, 50)}...`,
            vscode.CodeActionKind.QuickFix,
        );

        action.diagnostics = [diagnostic];
        action.isPreferred = true;

        action.command = {
            command: KEKKAI_FIX_COMMAND,
            title: 'Apply Kekkai Fix',
            arguments: [{
                finding,
                filePath: document.uri.fsPath,
                workspacePath: workspaceFolder.uri.fsPath,
            } as FixContext],
        };

        return action;
    }
}

export async function applyFix(
    context: FixContext,
    cliPath: string,
): Promise<{ success: boolean; message: string }> {
    const { finding, filePath, workspacePath } = context;

    if (!finding.rule_id) {
        return { success: false, message: 'No rule ID available for fix' };
    }

    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
    statusBar.text = '$(sync~spin) Kekkai: Generating fix...';
    statusBar.show();

    try {
        const { stdout } = await execFileAsync(cliPath, [
            'fix',
            '--repo', workspacePath,
            '--file', filePath,
            '--line', String(finding.line || 1),
            '--rule', finding.rule_id,
            '--dry-run',
            '--output', '-',
        ], {
            timeout: MAX_FIX_TIMEOUT_MS,
            maxBuffer: 5 * 1024 * 1024,
        });

        const fixResult = JSON.parse(stdout) as {
            success: boolean;
            suggestions?: Array<{
                preview: string;
                diff?: { original: string; fixed: string };
            }>;
            error?: string;
        };

        if (!fixResult.success || !fixResult.suggestions?.length) {
            return {
                success: false,
                message: fixResult.error || 'No fix suggestion available',
            };
        }

        const suggestion = fixResult.suggestions[0];

        const choice = await vscode.window.showInformationMessage(
            'Apply suggested fix?',
            { modal: true, detail: suggestion.preview },
            'Apply',
            'Cancel',
        );

        if (choice !== 'Apply') {
            return { success: false, message: 'Fix cancelled by user' };
        }

        await execFileAsync(cliPath, [
            'fix',
            '--repo', workspacePath,
            '--file', filePath,
            '--line', String(finding.line || 1),
            '--rule', finding.rule_id,
            '--apply',
        ], {
            timeout: MAX_FIX_TIMEOUT_MS,
        });

        const document = await vscode.workspace.openTextDocument(filePath);
        await vscode.window.showTextDocument(document);

        return { success: true, message: 'Fix applied successfully' };

    } catch (error) {
        const safeError = sanitizeError(error);
        return { success: false, message: `Fix failed: ${safeError}` };
    } finally {
        statusBar.dispose();
    }
}

export function registerFixCommand(
    context: vscode.ExtensionContext,
    cliPath: string,
): void {
    const command = vscode.commands.registerCommand(
        KEKKAI_FIX_COMMAND,
        async (fixContext: FixContext) => {
            const result = await applyFix(fixContext, cliPath);
            if (result.success) {
                vscode.window.showInformationMessage(result.message);
            } else {
                vscode.window.showWarningMessage(result.message);
            }
        },
    );
    context.subscriptions.push(command);
}
