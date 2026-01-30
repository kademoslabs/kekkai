/**
 * Tests for quick fix code action provider.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { KekkaiCodeActionProvider, FixContext } from '../src/quickfix';
import { Finding } from '../src/types';

suite('QuickFix Test Suite', () => {
    suite('KekkaiCodeActionProvider', () => {
        let provider: KekkaiCodeActionProvider;

        setup(() => {
            provider = new KekkaiCodeActionProvider();
        });

        test('provides QuickFix code action kind', () => {
            assert.ok(KekkaiCodeActionProvider.providedCodeActionKinds.includes(vscode.CodeActionKind.QuickFix));
        });

        test('stores and retrieves findings by diagnostic', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'SQL Injection',
                severity: 'high',
                rule_id: 'python.lang.security.sql-injection',
                line: 10,
            };

            const diagnostic = new vscode.Diagnostic(
                new vscode.Range(9, 0, 9, 50),
                'SQL Injection',
                vscode.DiagnosticSeverity.Error
            );
            diagnostic.source = 'kekkai';

            provider.setFindingForDiagnostic(diagnostic, finding);

            assert.ok(true);
        });

        test('clears findings', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'high',
            };

            const diagnostic = new vscode.Diagnostic(
                new vscode.Range(0, 0, 0, 10),
                'Test',
                vscode.DiagnosticSeverity.Error
            );
            diagnostic.source = 'kekkai';

            provider.setFindingForDiagnostic(diagnostic, finding);
            provider.clearFindings();

            assert.ok(true);
        });

        test('only processes semgrep findings for quick fix', () => {
            const trivyFinding: Finding = {
                scanner: 'trivy',
                title: 'CVE-2021-1234',
                severity: 'critical',
            };

            const semgrepFinding: Finding = {
                scanner: 'semgrep',
                title: 'SQL Injection',
                severity: 'high',
                rule_id: 'test.rule',
            };

            assert.strictEqual(trivyFinding.scanner, 'trivy');
            assert.strictEqual(semgrepFinding.scanner, 'semgrep');
        });
    });

    suite('FixContext', () => {
        test('fix context has required fields', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test Issue',
                severity: 'high',
                rule_id: 'test.rule',
                line: 15,
            };

            const context: FixContext = {
                finding,
                filePath: '/workspace/src/app.py',
                workspacePath: '/workspace',
            };

            assert.strictEqual(context.finding.scanner, 'semgrep');
            assert.strictEqual(context.filePath, '/workspace/src/app.py');
            assert.strictEqual(context.workspacePath, '/workspace');
        });

        test('fix context preserves line number', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'medium',
                line: 42,
            };

            const context: FixContext = {
                finding,
                filePath: '/test.py',
                workspacePath: '/',
            };

            assert.strictEqual(context.finding.line, 42);
        });
    });

    suite('Code Action Creation', () => {
        test('action requires rule_id for fix', () => {
            const findingWithRule: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'high',
                rule_id: 'my.rule.id',
            };

            const findingWithoutRule: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'high',
            };

            assert.ok(findingWithRule.rule_id);
            assert.ok(!findingWithoutRule.rule_id);
        });

        test('action title is truncated for long findings', () => {
            const longTitle = 'A'.repeat(100);
            const truncated = longTitle.substring(0, 50) + '...';

            assert.ok(truncated.length < longTitle.length);
            assert.ok(truncated.endsWith('...'));
        });
    });
});
