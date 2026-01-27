/**
 * Sanitization utilities for secure display of untrusted content.
 * Prevents XSS and information disclosure through careful encoding.
 */

const MAX_DISPLAY_LENGTH = 500;
const PATH_PATTERN = /\/[^\s]+/g;

/**
 * Sanitize text for safe display in VS Code UI.
 * Removes potential HTML/script injection and truncates long strings.
 */
export function sanitizeForDisplay(text: string): string {
    if (!text) {
        return '';
    }

    let sanitized = text
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');

    if (sanitized.length > MAX_DISPLAY_LENGTH) {
        sanitized = sanitized.substring(0, MAX_DISPLAY_LENGTH) + '...';
    }

    return sanitized;
}

/**
 * Sanitize error messages to prevent path/sensitive info disclosure.
 * Redacts file paths and limits length.
 */
export function sanitizeError(error: unknown): string {
    let message: string;

    if (error instanceof Error) {
        message = error.message;
    } else if (typeof error === 'string') {
        message = error;
    } else {
        message = 'Unknown error';
    }

    const redacted = message
        .substring(0, 200)
        .replace(PATH_PATTERN, '[path]');

    return redacted;
}

/**
 * Validate that a string is a safe severity value.
 */
export function isValidSeverity(value: string): value is 'critical' | 'high' | 'medium' | 'low' | 'info' {
    return ['critical', 'high', 'medium', 'low', 'info'].includes(value);
}

/**
 * Sanitize a finding object for safe display.
 */
export function sanitizeFinding(finding: {
    title?: string;
    description?: string;
    severity?: string;
}): { title: string; description: string; severity: string } {
    const sev = finding.severity || '';
    return {
        title: sanitizeForDisplay(finding.title || 'Unknown'),
        description: sanitizeForDisplay(finding.description || ''),
        severity: isValidSeverity(sev) ? sev : 'info',
    };
}
