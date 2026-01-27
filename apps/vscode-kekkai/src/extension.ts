/**
 * Kekkai VS Code Extension
 *
 * Integrates kekkai security scanning into VS Code with:
 * - Rate limiting to prevent resource exhaustion
 * - Workspace trust checks for untrusted folders
 * - Sanitized output to prevent injection attacks
 */

import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { ExtensionConfig, Finding, RateLimitState } from './types';
import { updateDiagnostics, extractFindings } from './diagnostics';
import { sanitizeError } from './sanitize';

const execFileAsync = promisify(execFile);

const DEFAULT_DEBOUNCE_MS = 30000;
const DEFAULT_TIMEOUT_MS = 300000;
const MAX_OUTPUT_BUFFER = 10 * 1024 * 1024;

let rateLimitState: RateLimitState = {
    lastScanTime: 0,
    debounceMs: DEFAULT_DEBOUNCE_MS,
};

function getConfig(): ExtensionConfig {
    const config = vscode.workspace.getConfiguration('kekkai');
    return {
        scanDebounceMs: config.get<number>('scanDebounceMs', DEFAULT_DEBOUNCE_MS),
        autoScanOnSave: config.get<boolean>('autoScanOnSave', false),
        cliPath: config.get<string>('cliPath', 'kekkai'),
        scanTimeoutMs: config.get<number>('scanTimeoutMs', DEFAULT_TIMEOUT_MS),
    };
}

function checkRateLimit(config: ExtensionConfig): { allowed: boolean; waitSeconds: number } {
    const now = Date.now();
    const elapsed = now - rateLimitState.lastScanTime;

    if (elapsed < config.scanDebounceMs) {
        const waitSeconds = Math.ceil((config.scanDebounceMs - elapsed) / 1000);
        return { allowed: false, waitSeconds };
    }

    return { allowed: true, waitSeconds: 0 };
}

async function checkWorkspaceTrust(): Promise<boolean> {
    if (vscode.workspace.isTrusted) {
        return true;
    }

    const choice = await vscode.window.showWarningMessage(
        'This workspace is not trusted. Running kekkai scan may execute code. Continue?',
        'Scan',
        'Cancel'
    );

    return choice === 'Scan';
}

async function runScan(
    workspacePath: string,
    diagnostics: vscode.DiagnosticCollection,
    config: ExtensionConfig
): Promise<void> {
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
    statusBar.text = '$(sync~spin) Kekkai: Scanning...';
    statusBar.show();

    try {
        const { stdout } = await execFileAsync(config.cliPath, [
            'scan',
            '--repo', workspacePath,
            '--output', '-',
        ], {
            timeout: config.scanTimeoutMs,
            maxBuffer: MAX_OUTPUT_BUFFER,
        });

        const scanOutput = JSON.parse(stdout) as { results?: Array<{ findings?: Finding[] }> };
        const findings = extractFindings(scanOutput);
        updateDiagnostics(findings, diagnostics, workspacePath);

        const count = findings.length;
        vscode.window.showInformationMessage(`Kekkai: Found ${count} issue(s)`);

    } catch (error) {
        const safeError = sanitizeError(error);
        vscode.window.showErrorMessage(`Kekkai scan failed: ${safeError}`);
    } finally {
        statusBar.dispose();
    }
}

export function activate(context: vscode.ExtensionContext): void {
    const diagnostics = vscode.languages.createDiagnosticCollection('kekkai');
    context.subscriptions.push(diagnostics);

    const scanCommand = vscode.commands.registerCommand('kekkai.scan', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const config = getConfig();

        const rateCheck = checkRateLimit(config);
        if (!rateCheck.allowed) {
            vscode.window.showWarningMessage(
                `Please wait ${rateCheck.waitSeconds}s before scanning again`
            );
            return;
        }

        const trusted = await checkWorkspaceTrust();
        if (!trusted) {
            return;
        }

        rateLimitState.lastScanTime = Date.now();
        await runScan(workspaceFolder.uri.fsPath, diagnostics, config);
    });

    const clearCommand = vscode.commands.registerCommand('kekkai.clearDiagnostics', () => {
        diagnostics.clear();
        vscode.window.showInformationMessage('Kekkai: Diagnostics cleared');
    });

    context.subscriptions.push(scanCommand, clearCommand);

    const config = getConfig();
    if (config.autoScanOnSave) {
        const saveWatcher = vscode.workspace.onDidSaveTextDocument(async () => {
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
            if (!workspaceFolder) {
                return;
            }

            const currentConfig = getConfig();
            const rateCheck = checkRateLimit(currentConfig);
            if (!rateCheck.allowed) {
                return;
            }

            if (!vscode.workspace.isTrusted) {
                return;
            }

            rateLimitState.lastScanTime = Date.now();
            await runScan(workspaceFolder.uri.fsPath, diagnostics, currentConfig);
        });
        context.subscriptions.push(saveWatcher);
    }
}

export function deactivate(): void {
    rateLimitState = { lastScanTime: 0, debounceMs: DEFAULT_DEBOUNCE_MS };
}

export function _testExports() {
    return {
        checkRateLimit,
        getConfig,
        rateLimitState,
        resetRateLimitState: () => {
            rateLimitState = { lastScanTime: 0, debounceMs: DEFAULT_DEBOUNCE_MS };
        },
    };
}
