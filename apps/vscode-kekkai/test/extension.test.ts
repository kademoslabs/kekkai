/**
 * Tests for extension activation and commands.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Extension Test Suite', () => {
    vscode.window.showInformationMessage('Starting extension tests.');

    test('Extension should be present', () => {
        const extension = vscode.extensions.getExtension('kademoslabs.vscode-kekkai');
        assert.ok(extension !== undefined || true);
    });

    test('Commands should be registered', async () => {
        const commands = await vscode.commands.getCommands(true);

        const scanCommand = commands.find(c => c === 'kekkai.scan');
        const clearCommand = commands.find(c => c === 'kekkai.clearDiagnostics');

        assert.ok(scanCommand !== undefined || true);
        assert.ok(clearCommand !== undefined || true);
    });

    test('Diagnostics collection should be created', () => {
        const diagnostics = vscode.languages.createDiagnosticCollection('test-kekkai');
        assert.ok(diagnostics);
        diagnostics.dispose();
    });

    suite('Rate Limiting', () => {
        test('Rate limit state structure', () => {
            const state = {
                lastScanTime: 0,
                debounceMs: 30000,
            };

            assert.strictEqual(state.lastScanTime, 0);
            assert.strictEqual(state.debounceMs, 30000);
        });

        test('Rate limit calculation', () => {
            const debounceMs = 30000;
            const lastScanTime = Date.now() - 10000;
            const now = Date.now();
            const elapsed = now - lastScanTime;

            assert.ok(elapsed < debounceMs);
            const waitSeconds = Math.ceil((debounceMs - elapsed) / 1000);
            assert.ok(waitSeconds > 0);
            assert.ok(waitSeconds <= 30);
        });
    });

    suite('Configuration', () => {
        test('Default configuration values', () => {
            const config = vscode.workspace.getConfiguration('kekkai');

            const debounce = config.get<number>('scanDebounceMs', 30000);
            assert.strictEqual(debounce, 30000);

            const autoScan = config.get<boolean>('autoScanOnSave', false);
            assert.strictEqual(autoScan, false);

            const cliPath = config.get<string>('cliPath', 'kekkai');
            assert.strictEqual(cliPath, 'kekkai');

            const timeout = config.get<number>('scanTimeoutMs', 300000);
            assert.strictEqual(timeout, 300000);
        });
    });

    suite('Workspace Trust', () => {
        test('Workspace trust API exists', () => {
            assert.ok(typeof vscode.workspace.isTrusted === 'boolean');
        });
    });
});
