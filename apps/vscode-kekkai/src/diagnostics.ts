/**
 * Diagnostic management for mapping Kekkai findings to VS Code Problems panel.
 */

import * as vscode from 'vscode';
import { Finding, Severity } from './types';
import { sanitizeForDisplay } from './sanitize';

/**
 * Convert Kekkai severity to VS Code DiagnosticSeverity.
 */
export function severityToVscode(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
            return vscode.DiagnosticSeverity.Information;
        case 'info':
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

/**
 * Create a VS Code Diagnostic from a Kekkai Finding.
 */
export function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
    const line = Math.max((finding.line || 1) - 1, 0);
    const column = Math.max((finding.column || 1) - 1, 0);
    const endLine = finding.end_line ? Math.max(finding.end_line - 1, line) : line;
    const endColumn = finding.end_column || 1000;

    const range = new vscode.Range(line, column, endLine, endColumn);

    const safeTitle = sanitizeForDisplay(finding.title);
    const message = finding.description
        ? `${safeTitle}\n\n${sanitizeForDisplay(finding.description)}`
        : safeTitle;

    const diagnostic = new vscode.Diagnostic(
        range,
        message,
        severityToVscode(finding.severity)
    );

    diagnostic.source = 'kekkai';
    diagnostic.code = finding.rule_id || finding.cve_id || finding.cwe_id;

    return diagnostic;
}

/**
 * Group findings by file path.
 */
export function groupFindingsByFile(
    findings: Finding[],
    workspacePath: string
): Map<string, Finding[]> {
    const fileMap = new Map<string, Finding[]>();

    for (const finding of findings) {
        if (!finding.file_path) {
            continue;
        }

        const absolutePath = finding.file_path.startsWith('/')
            ? finding.file_path
            : `${workspacePath}/${finding.file_path}`;

        const existing = fileMap.get(absolutePath) || [];
        existing.push(finding);
        fileMap.set(absolutePath, existing);
    }

    return fileMap;
}

/**
 * Update VS Code diagnostics collection with findings.
 */
export function updateDiagnostics(
    findings: Finding[],
    diagnostics: vscode.DiagnosticCollection,
    workspacePath: string
): void {
    diagnostics.clear();

    const fileMap = groupFindingsByFile(findings, workspacePath);

    for (const [filePath, fileFindings] of fileMap) {
        const uri = vscode.Uri.file(filePath);
        const fileDiagnostics = fileFindings.map(findingToDiagnostic);
        diagnostics.set(uri, fileDiagnostics);
    }
}

/**
 * Extract all findings from scan output.
 */
export function extractFindings(scanOutput: { results?: Array<{ findings?: Finding[] }> }): Finding[] {
    const allFindings: Finding[] = [];

    if (!scanOutput.results) {
        return allFindings;
    }

    for (const result of scanOutput.results) {
        if (result.findings) {
            allFindings.push(...result.findings);
        }
    }

    return allFindings;
}
