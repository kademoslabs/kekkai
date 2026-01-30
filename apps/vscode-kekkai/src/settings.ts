/**
 * Settings management for Kekkai VS Code extension.
 *
 * Provides typed access to extension configuration with validation.
 */

import * as vscode from 'vscode';

export interface ScannerSettings {
    trivy: boolean;
    semgrep: boolean;
    gitleaks: boolean;
}

export interface KekkaiSettings {
    scanDebounceMs: number;
    autoScanOnSave: boolean;
    cliPath: string;
    scanTimeoutMs: number;
    enabledScanners: ScannerSettings;
    nativeMode: boolean;
    showHoverDetails: boolean;
    enableQuickFix: boolean;
}

const DEFAULT_SETTINGS: KekkaiSettings = {
    scanDebounceMs: 30000,
    autoScanOnSave: false,
    cliPath: 'kekkai',
    scanTimeoutMs: 300000,
    enabledScanners: {
        trivy: true,
        semgrep: true,
        gitleaks: true,
    },
    nativeMode: false,
    showHoverDetails: true,
    enableQuickFix: true,
};

export function getSettings(): KekkaiSettings {
    const config = vscode.workspace.getConfiguration('kekkai');

    const scanners = config.get<ScannerSettings>('enabledScanners', DEFAULT_SETTINGS.enabledScanners);
    const validatedScanners: ScannerSettings = {
        trivy: typeof scanners?.trivy === 'boolean' ? scanners.trivy : true,
        semgrep: typeof scanners?.semgrep === 'boolean' ? scanners.semgrep : true,
        gitleaks: typeof scanners?.gitleaks === 'boolean' ? scanners.gitleaks : true,
    };

    return {
        scanDebounceMs: validateNumber(config.get<number>('scanDebounceMs'), DEFAULT_SETTINGS.scanDebounceMs, 1000, 600000),
        autoScanOnSave: config.get<boolean>('autoScanOnSave', DEFAULT_SETTINGS.autoScanOnSave),
        cliPath: config.get<string>('cliPath', DEFAULT_SETTINGS.cliPath) || DEFAULT_SETTINGS.cliPath,
        scanTimeoutMs: validateNumber(config.get<number>('scanTimeoutMs'), DEFAULT_SETTINGS.scanTimeoutMs, 10000, 1800000),
        enabledScanners: validatedScanners,
        nativeMode: config.get<boolean>('nativeMode', DEFAULT_SETTINGS.nativeMode),
        showHoverDetails: config.get<boolean>('showHoverDetails', DEFAULT_SETTINGS.showHoverDetails),
        enableQuickFix: config.get<boolean>('enableQuickFix', DEFAULT_SETTINGS.enableQuickFix),
    };
}

function validateNumber(value: number | undefined, defaultVal: number, min: number, max: number): number {
    if (typeof value !== 'number' || isNaN(value)) {
        return defaultVal;
    }
    return Math.min(Math.max(value, min), max);
}

export function buildScanArgs(settings: KekkaiSettings, workspacePath: string): string[] {
    const args: string[] = ['scan', '--repo', workspacePath, '--output', '-'];

    if (settings.nativeMode) {
        args.push('--native');
    }

    const disabledScanners: string[] = [];
    if (!settings.enabledScanners.trivy) {
        disabledScanners.push('trivy');
    }
    if (!settings.enabledScanners.semgrep) {
        disabledScanners.push('semgrep');
    }
    if (!settings.enabledScanners.gitleaks) {
        disabledScanners.push('gitleaks');
    }

    if (disabledScanners.length > 0 && disabledScanners.length < 3) {
        for (const scanner of disabledScanners) {
            args.push('--skip', scanner);
        }
    }

    return args;
}

export function onSettingsChanged(callback: () => void): vscode.Disposable {
    return vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration('kekkai')) {
            callback();
        }
    });
}

export class SettingsManager {
    private _settings: KekkaiSettings;
    private _disposables: vscode.Disposable[] = [];
    private _onDidChangeSettings = new vscode.EventEmitter<KekkaiSettings>();

    public readonly onDidChangeSettings = this._onDidChangeSettings.event;

    constructor() {
        this._settings = getSettings();

        this._disposables.push(
            vscode.workspace.onDidChangeConfiguration((e) => {
                if (e.affectsConfiguration('kekkai')) {
                    this._settings = getSettings();
                    this._onDidChangeSettings.fire(this._settings);
                }
            }),
        );
    }

    public get settings(): KekkaiSettings {
        return this._settings;
    }

    public dispose(): void {
        this._onDidChangeSettings.dispose();
        for (const d of this._disposables) {
            d.dispose();
        }
    }
}

export function createSettingsManager(): SettingsManager {
    return new SettingsManager();
}
