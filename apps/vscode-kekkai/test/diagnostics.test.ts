/**
 * Tests for diagnostics module.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import {
    severityToVscode,
    findingToDiagnostic,
    groupFindingsByFile,
    extractFindings,
} from '../src/diagnostics';
import { Finding, Severity } from '../src/types';

suite('Diagnostics Test Suite', () => {
    suite('severityToVscode', () => {
        test('maps critical to Error', () => {
            assert.strictEqual(severityToVscode('critical'), vscode.DiagnosticSeverity.Error);
        });

        test('maps high to Error', () => {
            assert.strictEqual(severityToVscode('high'), vscode.DiagnosticSeverity.Error);
        });

        test('maps medium to Warning', () => {
            assert.strictEqual(severityToVscode('medium'), vscode.DiagnosticSeverity.Warning);
        });

        test('maps low to Information', () => {
            assert.strictEqual(severityToVscode('low'), vscode.DiagnosticSeverity.Information);
        });

        test('maps info to Hint', () => {
            assert.strictEqual(severityToVscode('info'), vscode.DiagnosticSeverity.Hint);
        });
    });

    suite('findingToDiagnostic', () => {
        test('creates diagnostic with correct range', () => {
            const finding: Finding = {
                scanner: 'test',
                title: 'Test Issue',
                severity: 'high',
                line: 10,
                column: 5,
            };

            const diagnostic = findingToDiagnostic(finding);

            assert.strictEqual(diagnostic.range.start.line, 9);
            assert.strictEqual(diagnostic.range.start.character, 4);
            assert.strictEqual(diagnostic.source, 'kekkai');
        });

        test('handles missing line/column', () => {
            const finding: Finding = {
                scanner: 'test',
                title: 'Test Issue',
                severity: 'medium',
            };

            const diagnostic = findingToDiagnostic(finding);

            assert.strictEqual(diagnostic.range.start.line, 0);
            assert.strictEqual(diagnostic.range.start.character, 0);
        });

        test('includes rule_id as code', () => {
            const finding: Finding = {
                scanner: 'semgrep',
                title: 'Test',
                severity: 'low',
                rule_id: 'semgrep.rule.test',
            };

            const diagnostic = findingToDiagnostic(finding);
            assert.strictEqual(diagnostic.code, 'semgrep.rule.test');
        });

        test('sanitizes title in message', () => {
            const finding: Finding = {
                scanner: 'test',
                title: '<script>alert(1)</script>',
                severity: 'high',
            };

            const diagnostic = findingToDiagnostic(finding);
            assert.ok(!diagnostic.message.includes('<script>'));
        });

        test('includes description when present', () => {
            const finding: Finding = {
                scanner: 'test',
                title: 'Title',
                description: 'Description text',
                severity: 'medium',
            };

            const diagnostic = findingToDiagnostic(finding);
            assert.ok(diagnostic.message.includes('Description text'));
        });
    });

    suite('groupFindingsByFile', () => {
        test('groups findings by file path', () => {
            const findings: Finding[] = [
                { scanner: 'a', title: 't1', severity: 'high', file_path: 'src/a.ts' },
                { scanner: 'b', title: 't2', severity: 'high', file_path: 'src/b.ts' },
                { scanner: 'c', title: 't3', severity: 'high', file_path: 'src/a.ts' },
            ];

            const grouped = groupFindingsByFile(findings, '/workspace');

            assert.strictEqual(grouped.size, 2);
            assert.strictEqual(grouped.get('/workspace/src/a.ts')?.length, 2);
            assert.strictEqual(grouped.get('/workspace/src/b.ts')?.length, 1);
        });

        test('handles absolute paths', () => {
            const findings: Finding[] = [
                { scanner: 'a', title: 't1', severity: 'high', file_path: '/abs/path/file.ts' },
            ];

            const grouped = groupFindingsByFile(findings, '/workspace');

            assert.ok(grouped.has('/abs/path/file.ts'));
        });

        test('skips findings without file_path', () => {
            const findings: Finding[] = [
                { scanner: 'a', title: 't1', severity: 'high' },
                { scanner: 'b', title: 't2', severity: 'high', file_path: 'src/a.ts' },
            ];

            const grouped = groupFindingsByFile(findings, '/workspace');

            assert.strictEqual(grouped.size, 1);
        });
    });

    suite('extractFindings', () => {
        test('extracts findings from multiple results', () => {
            const scanOutput = {
                results: [
                    { findings: [{ scanner: 'a', title: 't1', severity: 'high' as Severity }] },
                    { findings: [{ scanner: 'b', title: 't2', severity: 'low' as Severity }] },
                ],
            };

            const findings = extractFindings(scanOutput);

            assert.strictEqual(findings.length, 2);
        });

        test('handles empty results', () => {
            const findings = extractFindings({ results: [] });
            assert.strictEqual(findings.length, 0);
        });

        test('handles missing results', () => {
            const findings = extractFindings({});
            assert.strictEqual(findings.length, 0);
        });

        test('handles results without findings', () => {
            const scanOutput = {
                results: [{ findings: undefined }],
            };

            const findings = extractFindings(scanOutput);
            assert.strictEqual(findings.length, 0);
        });
    });
});
