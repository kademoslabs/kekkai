/**
 * Type definitions for Kekkai VS Code extension.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
    scanner: string;
    rule_id?: string;
    title: string;
    description?: string;
    severity: Severity;
    file_path?: string;
    line?: number;
    column?: number;
    end_line?: number;
    end_column?: number;
    cwe_id?: string;
    cve_id?: string;
}

export interface ScanResult {
    scanner: string;
    success: boolean;
    findings: Finding[];
    error?: string;
    duration_ms?: number;
}

export interface ScanOutput {
    results: ScanResult[];
    run_id?: string;
    timestamp?: string;
}

export interface RateLimitState {
    lastScanTime: number;
    debounceMs: number;
}

export interface ExtensionConfig {
    scanDebounceMs: number;
    autoScanOnSave: boolean;
    cliPath: string;
    scanTimeoutMs: number;
}
