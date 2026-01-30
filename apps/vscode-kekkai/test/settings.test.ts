/**
 * Tests for settings management.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import {
    getSettings,
    buildScanArgs,
    KekkaiSettings,
    ScannerSettings,
} from '../src/settings';

suite('Settings Test Suite', () => {
    suite('getSettings', () => {
        test('returns default values', () => {
            const settings = getSettings();

            assert.strictEqual(typeof settings.scanDebounceMs, 'number');
            assert.strictEqual(typeof settings.autoScanOnSave, 'boolean');
            assert.strictEqual(typeof settings.cliPath, 'string');
            assert.strictEqual(typeof settings.scanTimeoutMs, 'number');
            assert.strictEqual(typeof settings.nativeMode, 'boolean');
            assert.strictEqual(typeof settings.showHoverDetails, 'boolean');
            assert.strictEqual(typeof settings.enableQuickFix, 'boolean');
        });

        test('default scanDebounceMs is 30000', () => {
            const settings = getSettings();
            assert.strictEqual(settings.scanDebounceMs, 30000);
        });

        test('default autoScanOnSave is false', () => {
            const settings = getSettings();
            assert.strictEqual(settings.autoScanOnSave, false);
        });

        test('default cliPath is kekkai', () => {
            const settings = getSettings();
            assert.strictEqual(settings.cliPath, 'kekkai');
        });

        test('default scanTimeoutMs is 300000', () => {
            const settings = getSettings();
            assert.strictEqual(settings.scanTimeoutMs, 300000);
        });

        test('default nativeMode is false', () => {
            const settings = getSettings();
            assert.strictEqual(settings.nativeMode, false);
        });

        test('default showHoverDetails is true', () => {
            const settings = getSettings();
            assert.strictEqual(settings.showHoverDetails, true);
        });

        test('default enableQuickFix is true', () => {
            const settings = getSettings();
            assert.strictEqual(settings.enableQuickFix, true);
        });

        test('default enabledScanners has all scanners enabled', () => {
            const settings = getSettings();

            assert.strictEqual(settings.enabledScanners.trivy, true);
            assert.strictEqual(settings.enabledScanners.semgrep, true);
            assert.strictEqual(settings.enabledScanners.gitleaks, true);
        });
    });

    suite('buildScanArgs', () => {
        test('includes basic args', () => {
            const settings: KekkaiSettings = {
                scanDebounceMs: 30000,
                autoScanOnSave: false,
                cliPath: 'kekkai',
                scanTimeoutMs: 300000,
                enabledScanners: { trivy: true, semgrep: true, gitleaks: true },
                nativeMode: false,
                showHoverDetails: true,
                enableQuickFix: true,
            };

            const args = buildScanArgs(settings, '/workspace');

            assert.ok(args.includes('scan'));
            assert.ok(args.includes('--repo'));
            assert.ok(args.includes('/workspace'));
            assert.ok(args.includes('--output'));
            assert.ok(args.includes('-'));
        });

        test('adds native flag when nativeMode is true', () => {
            const settings: KekkaiSettings = {
                scanDebounceMs: 30000,
                autoScanOnSave: false,
                cliPath: 'kekkai',
                scanTimeoutMs: 300000,
                enabledScanners: { trivy: true, semgrep: true, gitleaks: true },
                nativeMode: true,
                showHoverDetails: true,
                enableQuickFix: true,
            };

            const args = buildScanArgs(settings, '/workspace');

            assert.ok(args.includes('--native'));
        });

        test('does not add native flag when nativeMode is false', () => {
            const settings: KekkaiSettings = {
                scanDebounceMs: 30000,
                autoScanOnSave: false,
                cliPath: 'kekkai',
                scanTimeoutMs: 300000,
                enabledScanners: { trivy: true, semgrep: true, gitleaks: true },
                nativeMode: false,
                showHoverDetails: true,
                enableQuickFix: true,
            };

            const args = buildScanArgs(settings, '/workspace');

            assert.ok(!args.includes('--native'));
        });

        test('adds skip flag for disabled scanners', () => {
            const settings: KekkaiSettings = {
                scanDebounceMs: 30000,
                autoScanOnSave: false,
                cliPath: 'kekkai',
                scanTimeoutMs: 300000,
                enabledScanners: { trivy: false, semgrep: true, gitleaks: true },
                nativeMode: false,
                showHoverDetails: true,
                enableQuickFix: true,
            };

            const args = buildScanArgs(settings, '/workspace');

            const skipIndex = args.indexOf('--skip');
            assert.ok(skipIndex >= 0);
            assert.strictEqual(args[skipIndex + 1], 'trivy');
        });

        test('adds multiple skip flags for multiple disabled scanners', () => {
            const settings: KekkaiSettings = {
                scanDebounceMs: 30000,
                autoScanOnSave: false,
                cliPath: 'kekkai',
                scanTimeoutMs: 300000,
                enabledScanners: { trivy: false, semgrep: true, gitleaks: false },
                nativeMode: false,
                showHoverDetails: true,
                enableQuickFix: true,
            };

            const args = buildScanArgs(settings, '/workspace');

            const skipCount = args.filter(a => a === '--skip').length;
            assert.strictEqual(skipCount, 2);
        });

        test('does not add skip flags when all scanners disabled', () => {
            const settings: KekkaiSettings = {
                scanDebounceMs: 30000,
                autoScanOnSave: false,
                cliPath: 'kekkai',
                scanTimeoutMs: 300000,
                enabledScanners: { trivy: false, semgrep: false, gitleaks: false },
                nativeMode: false,
                showHoverDetails: true,
                enableQuickFix: true,
            };

            const args = buildScanArgs(settings, '/workspace');

            assert.ok(!args.includes('--skip'));
        });
    });

    suite('ScannerSettings', () => {
        test('scanner settings structure', () => {
            const scanners: ScannerSettings = {
                trivy: true,
                semgrep: false,
                gitleaks: true,
            };

            assert.strictEqual(scanners.trivy, true);
            assert.strictEqual(scanners.semgrep, false);
            assert.strictEqual(scanners.gitleaks, true);
        });
    });

    suite('Settings Validation', () => {
        test('scanDebounceMs minimum is enforced', () => {
            const settings = getSettings();
            assert.ok(settings.scanDebounceMs >= 1000);
        });

        test('scanDebounceMs maximum is enforced', () => {
            const settings = getSettings();
            assert.ok(settings.scanDebounceMs <= 600000);
        });

        test('scanTimeoutMs minimum is enforced', () => {
            const settings = getSettings();
            assert.ok(settings.scanTimeoutMs >= 10000);
        });

        test('scanTimeoutMs maximum is enforced', () => {
            const settings = getSettings();
            assert.ok(settings.scanTimeoutMs <= 1800000);
        });
    });

    suite('Configuration Change Detection', () => {
        test('workspace configuration exists', () => {
            const config = vscode.workspace.getConfiguration('kekkai');
            assert.ok(config);
        });
    });
});
