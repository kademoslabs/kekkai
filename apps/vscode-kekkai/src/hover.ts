/**
 * Hover Provider for Kekkai findings.
 *
 * Shows detailed finding information when hovering over diagnostics.
 * Includes severity, CWE, rule ID, and description.
 */

import * as vscode from 'vscode';
import { Finding, Severity } from './types';
import { sanitizeForDisplay } from './sanitize';

export class KekkaiHoverProvider implements vscode.HoverProvider {
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

    public provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
    ): vscode.Hover | null {
        const diagnostics = vscode.languages.getDiagnostics(document.uri);

        for (const diagnostic of diagnostics) {
            if (diagnostic.source !== 'kekkai') {
                continue;
            }

            if (!diagnostic.range.contains(position)) {
                continue;
            }

            const finding = this.diagnosticToFinding.get(this.diagnosticKey(diagnostic));
            if (finding) {
                return this.createHover(finding, diagnostic);
            }

            return this.createBasicHover(diagnostic);
        }

        return null;
    }

    private createHover(finding: Finding, diagnostic: vscode.Diagnostic): vscode.Hover {
        const markdown = new vscode.MarkdownString();
        markdown.isTrusted = true;
        markdown.supportHtml = false;

        markdown.appendMarkdown(`### ${this.getSeverityIcon(finding.severity)} ${sanitizeForDisplay(finding.title)}\n\n`);

        markdown.appendMarkdown(`**Scanner:** ${sanitizeForDisplay(finding.scanner)}\n\n`);
        markdown.appendMarkdown(`**Severity:** ${this.formatSeverity(finding.severity)}\n\n`);

        if (finding.rule_id) {
            markdown.appendMarkdown(`**Rule:** \`${sanitizeForDisplay(finding.rule_id)}\`\n\n`);
        }

        if (finding.cwe_id) {
            markdown.appendMarkdown(`**CWE:** [${sanitizeForDisplay(finding.cwe_id)}](https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html)\n\n`);
        }

        if (finding.cve_id) {
            markdown.appendMarkdown(`**CVE:** [${sanitizeForDisplay(finding.cve_id)}](https://nvd.nist.gov/vuln/detail/${finding.cve_id})\n\n`);
        }

        if (finding.description) {
            markdown.appendMarkdown(`---\n\n${sanitizeForDisplay(finding.description)}\n\n`);
        }

        if (finding.scanner === 'semgrep' && finding.rule_id) {
            markdown.appendMarkdown(`---\n\n💡 *Quick Fix available via Code Actions (Ctrl+.)*\n`);
        }

        return new vscode.Hover(markdown, diagnostic.range);
    }

    private createBasicHover(diagnostic: vscode.Diagnostic): vscode.Hover {
        const markdown = new vscode.MarkdownString();
        markdown.isTrusted = true;

        markdown.appendMarkdown(`### Kekkai Security Finding\n\n`);
        markdown.appendMarkdown(`${sanitizeForDisplay(diagnostic.message)}\n\n`);

        if (diagnostic.code) {
            markdown.appendMarkdown(`**Code:** \`${String(diagnostic.code)}\`\n`);
        }

        return new vscode.Hover(markdown, diagnostic.range);
    }

    private getSeverityIcon(severity: Severity): string {
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

    private formatSeverity(severity: Severity): string {
        const icons: Record<Severity, string> = {
            critical: '🔴 Critical',
            high: '🟠 High',
            medium: '🟡 Medium',
            low: '🔵 Low',
            info: 'ℹ️ Info',
        };
        return icons[severity] || severity;
    }
}

export function createHoverProvider(): KekkaiHoverProvider {
    return new KekkaiHoverProvider();
}
