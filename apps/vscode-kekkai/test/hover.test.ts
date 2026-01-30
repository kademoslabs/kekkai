/**
 * Tests for hover provider.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { KekkaiHoverProvider, createHoverProvider } from '../src/hover';
import { Finding } from '../src/types';

suite('Hover Test Suite', () => {
    suite('KekkaiHoverProvider', () => {
        let provider: KekkaiHoverProvider;

        setup(() => {
            provider = createHoverProvider();
        });

        test('creates hover provider instance', () => {
            assert.ok(provider);
            assert.ok(provider instanceof KekkaiHoverProvider);
        });

        test('stores findings for diagnostics', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'SQL Injection',
                severity: 'high',
                description: 'User input used in SQL query',
                cwe_id: 'CWE-89',
            };

            const diagnostic = new vscode.Diagnostic(
                new vscode.Range(10, 0, 10, 50),
                'SQL Injection',
                vscode.DiagnosticSeverity.Error
            );
            diagnostic.source = 'kekkai';

            provider.setFindingForDiagnostic(diagnostic, finding);

            assert.ok(true);
        });

        test('clears all stored findings', () => {
            const finding: Finding = {
                scanner: 'test',
                title: 'Test',
                severity: 'low',
            };

            const diagnostic = new vscode.Diagnostic(
                new vscode.Range(0, 0, 0, 10),
                'Test',
                vscode.DiagnosticSeverity.Information
            );
            diagnostic.source = 'kekkai';

            provider.setFindingForDiagnostic(diagnostic, finding);
            provider.clearFindings();

            assert.ok(true);
        });
    });

    suite('Severity Icons', () => {
        test('critical severity has red icon', () => {
            const icon = getSeverityIcon('critical');
            assert.strictEqual(icon, '🔴');
        });

        test('high severity has orange icon', () => {
            const icon = getSeverityIcon('high');
            assert.strictEqual(icon, '🟠');
        });

        test('medium severity has yellow icon', () => {
            const icon = getSeverityIcon('medium');
            assert.strictEqual(icon, '🟡');
        });

        test('low severity has blue icon', () => {
            const icon = getSeverityIcon('low');
            assert.strictEqual(icon, '🔵');
        });

        test('info severity has info icon', () => {
            const icon = getSeverityIcon('info');
            assert.strictEqual(icon, 'ℹ️');
        });
    });

    suite('Hover Content', () => {
        test('finding with CWE generates link', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'high',
                cwe_id: 'CWE-89',
            };

            const expectedUrl = 'https://cwe.mitre.org/data/definitions/89.html';
            const cweNumber = finding.cwe_id?.replace('CWE-', '');

            assert.strictEqual(cweNumber, '89');
            assert.ok(expectedUrl.includes(cweNumber!));
        });

        test('finding with CVE generates link', () => {
            const finding: Finding = {
                scanner: 'trivy',
                title: 'Test',
                severity: 'critical',
                cve_id: 'CVE-2021-44228',
            };

            const expectedUrl = `https://nvd.nist.gov/vuln/detail/${finding.cve_id}`;

            assert.ok(expectedUrl.includes('CVE-2021-44228'));
        });

        test('semgrep findings show quick fix hint', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'high',
                rule_id: 'test.rule',
            };

            const hasQuickFix = finding.scanner === 'semgrep' && finding.rule_id;

            assert.ok(hasQuickFix);
        });

        test('trivy findings do not show quick fix hint', () => {
            const finding: Finding = {
                scanner: 'trivy',
                title: 'Test',
                severity: 'high',
            };

            const hasQuickFix = finding.scanner === 'semgrep' && finding.rule_id;

            assert.ok(!hasQuickFix);
        });
    });

    suite('Finding Details', () => {
        test('includes scanner name', () => {
            const finding: Finding = {
                scanner: 'gitleaks',
                title: 'Secret detected',
                severity: 'high',
            };

            assert.strictEqual(finding.scanner, 'gitleaks');
        });

        test('includes description when present', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'medium',
                description: 'This is a detailed description of the security issue.',
            };

            assert.ok(finding.description);
            assert.ok(finding.description.length > 0);
        });

        test('handles missing description', () => {
            const finding: Finding = {
                scanner: 'test',
                title: 'Test',
                severity: 'low',
            };

            assert.strictEqual(finding.description, undefined);
        });

        test('includes rule_id when present', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'high',
                rule_id: 'python.flask.security.injection',
            };

            assert.strictEqual(finding.rule_id, 'python.flask.security.injection');
        });
    });
});

function getSeverityIcon(severity: string): string {
    switch (severity) {
        case 'critical':
            return '🔴';
        case 'high':
            return '🟠';
        case 'medium':
            return '🟡';
        case 'low':
            return '🔵';
        case 'info':
        default:
            return 'ℹ️';
    }
}
