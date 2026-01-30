/**
 * Kekkai VS Code Extension
 *
 * Integrates kekkai security scanning into VS Code with:
 * - Rate limiting to prevent resource exhaustion
 * - Workspace trust checks for untrusted folders
 * - Sanitized output to prevent injection attacks
 * - Hover details for security findings
 * - Quick fix actions for remediating issues
 */

import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { ExtensionConfig, Finding, RateLimitState } from './types';
import { updateDiagnostics, extractFindings, findingToDiagnostic } from './diagnostics';
import { sanitizeError } from './sanitize';
import { KekkaiCodeActionProvider, registerFixCommand } from './quickfix';
import { KekkaiHoverProvider } from './hover';
import { getSettings, buildScanArgs, SettingsManager } from './settings';

const execFileAsync = promisify(execFile);

const DEFAULT_DEBOUNCE_MS = 30000;
const DEFAULT_TIMEOUT_MS = 300000;
const MAX_OUTPUT_BUFFER = 10 * 1024 * 1024;

let rateLimitState: RateLimitState = {
    lastScanTime: 0,
    debounceMs: DEFAULT_DEBOUNCE_MS,
};

let statusBarItem: vscode.StatusBarItem | undefined;
let codeActionProvider: KekkaiCodeActionProvider | undefined;
let hoverProvider: KekkaiHoverProvider | undefined;

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

function updateStatusBar(scanning: boolean, findingsCount?: number): void {
    if (!statusBarItem) {
        return;
    }

    if (scanning) {
        statusBarItem.text = '$(sync~spin) Kekkai: Scanning...';
        statusBarItem.tooltip = 'Security scan in progress';
    } else if (findingsCount !== undefined) {
        const icon = findingsCount > 0 ? '$(warning)' : '$(check)';
        statusBarItem.text = `${icon} Kekkai: ${findingsCount} issue(s)`;
        statusBarItem.tooltip = `Click to run security scan\nLast scan: ${findingsCount} findings`;
    } else {
        statusBarItem.text = '$(shield) Kekkai';
        statusBarItem.tooltip = 'Click to run security scan';
    }
}

async function runScan(
    workspacePath: string,
    diagnostics: vscode.DiagnosticCollection,
    config: ExtensionConfig
): Promise<Finding[]> {
    updateStatusBar(true);

    try {
        const settings = getSettings();
        const args = buildScanArgs(settings, workspacePath);

        const { stdout } = await execFileAsync(config.cliPath, args, {
            timeout: config.scanTimeoutMs,
            maxBuffer: MAX_OUTPUT_BUFFER,
        });

        const scanOutput = JSON.parse(stdout) as { results?: Array<{ findings?: Finding[] }> };
        const findings = extractFindings(scanOutput);

        codeActionProvider?.clearFindings();
        hoverProvider?.clearFindings();

        updateDiagnostics(findings, diagnostics, workspacePath);

        for (const finding of findings) {
            if (finding.file_path) {
                const diagnostic = findingToDiagnostic(finding);
                codeActionProvider?.setFindingForDiagnostic(diagnostic, finding);
                hoverProvider?.setFindingForDiagnostic(diagnostic, finding);
            }
        }

        const count = findings.length;
        updateStatusBar(false, count);
        vscode.window.showInformationMessage(`Kekkai: Found ${count} issue(s)`);

        return findings;

    } catch (error) {
        const safeError = sanitizeError(error);
        updateStatusBar(false);
        vscode.window.showErrorMessage(`Kekkai scan failed: ${safeError}`);
        return [];
    }
}

export function activate(context: vscode.ExtensionContext): void {
    const diagnostics = vscode.languages.createDiagnosticCollection('kekkai');
    context.subscriptions.push(diagnostics);

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'kekkai.scan';
    updateStatusBar(false);
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    const settingsManager = new SettingsManager();
    context.subscriptions.push(settingsManager);

    const config = getConfig();
    registerFixCommand(context, config.cliPath);

    codeActionProvider = new KekkaiCodeActionProvider();
    const codeActionDisposable = vscode.languages.registerCodeActionsProvider(
        { scheme: 'file' },
        codeActionProvider,
        { providedCodeActionKinds: KekkaiCodeActionProvider.providedCodeActionKinds }
    );
    context.subscriptions.push(codeActionDisposable);

    hoverProvider = new KekkaiHoverProvider();
    const hoverDisposable = vscode.languages.registerHoverProvider(
        { scheme: 'file' },
        hoverProvider
    );
    context.subscriptions.push(hoverDisposable);

    const scanCommand = vscode.commands.registerCommand('kekkai.scan', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const currentConfig = getConfig();

        const rateCheck = checkRateLimit(currentConfig);
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
        await runScan(workspaceFolder.uri.fsPath, diagnostics, currentConfig);
    });

    const clearCommand = vscode.commands.registerCommand('kekkai.clearDiagnostics', () => {
        diagnostics.clear();
        codeActionProvider?.clearFindings();
        hoverProvider?.clearFindings();
        updateStatusBar(false);
        vscode.window.showInformationMessage('Kekkai: Diagnostics cleared');
    });

    context.subscriptions.push(scanCommand, clearCommand);

    const saveWatcher = vscode.workspace.onDidSaveTextDocument(async () => {
        const settings = getSettings();
        if (!settings.autoScanOnSave) {
            return;
        }

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

    settingsManager.onDidChangeSettings(() => {
        const newConfig = getConfig();
        rateLimitState.debounceMs = newConfig.scanDebounceMs;
    });
}

export function deactivate(): void {
    rateLimitState = { lastScanTime: 0, debounceMs: DEFAULT_DEBOUNCE_MS };
    statusBarItem = undefined;
    codeActionProvider = undefined;
    hoverProvider = undefined;
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
