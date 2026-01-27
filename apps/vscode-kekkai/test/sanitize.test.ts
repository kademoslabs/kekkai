/**
 * Tests for sanitization utilities.
 */

import * as assert from 'assert';
import { sanitizeForDisplay, sanitizeError, isValidSeverity, sanitizeFinding } from '../src/sanitize';

suite('Sanitize Test Suite', () => {
    suite('sanitizeForDisplay', () => {
        test('escapes HTML special characters', () => {
            const input = '<script>alert("xss")</script>';
            const result = sanitizeForDisplay(input);

            assert.ok(!result.includes('<script>'));
            assert.ok(result.includes('&lt;script&gt;'));
        });

        test('escapes quotes', () => {
            const input = 'Test "quoted" and \'single\'';
            const result = sanitizeForDisplay(input);

            assert.ok(!result.includes('"'));
            assert.ok(result.includes('&quot;'));
            assert.ok(result.includes('&#x27;'));
        });

        test('truncates long strings', () => {
            const input = 'A'.repeat(1000);
            const result = sanitizeForDisplay(input);

            assert.ok(result.length <= 503);
            assert.ok(result.endsWith('...'));
        });

        test('handles empty string', () => {
            assert.strictEqual(sanitizeForDisplay(''), '');
        });

        test('handles normal text', () => {
            const input = 'Normal text without special chars';
            assert.strictEqual(sanitizeForDisplay(input), input);
        });

        test('prevents markdown link injection', () => {
            const input = '[Click here](http://evil.com) for details';
            const result = sanitizeForDisplay(input);
            assert.ok(!result.includes('<'));
            assert.ok(!result.includes('>'));
        });
    });

    suite('sanitizeError', () => {
        test('redacts file paths', () => {
            const error = new Error('File not found: /home/user/secret/file.txt');
            const result = sanitizeError(error);

            assert.ok(!result.includes('/home/user'));
            assert.ok(result.includes('[path]'));
        });

        test('truncates long messages', () => {
            const error = new Error('E'.repeat(500));
            const result = sanitizeError(error);

            assert.ok(result.length <= 200);
        });

        test('handles string errors', () => {
            const result = sanitizeError('Simple error message');
            assert.strictEqual(result, 'Simple error message');
        });

        test('handles unknown error types', () => {
            const result = sanitizeError({ code: 123 });
            assert.strictEqual(result, 'Unknown error');
        });

        test('handles null/undefined', () => {
            assert.strictEqual(sanitizeError(null), 'Unknown error');
            assert.strictEqual(sanitizeError(undefined), 'Unknown error');
        });
    });

    suite('isValidSeverity', () => {
        test('accepts valid severities', () => {
            assert.ok(isValidSeverity('critical'));
            assert.ok(isValidSeverity('high'));
            assert.ok(isValidSeverity('medium'));
            assert.ok(isValidSeverity('low'));
            assert.ok(isValidSeverity('info'));
        });

        test('rejects invalid severities', () => {
            assert.ok(!isValidSeverity('unknown'));
            assert.ok(!isValidSeverity(''));
            assert.ok(!isValidSeverity('CRITICAL'));
        });
    });

    suite('sanitizeFinding', () => {
        test('sanitizes finding fields', () => {
            const finding = {
                title: '<script>bad</script>',
                description: 'Test description',
                severity: 'high',
            };
            const result = sanitizeFinding(finding);

            assert.ok(!result.title.includes('<script>'));
            assert.strictEqual(result.severity, 'high');
        });

        test('handles missing fields', () => {
            const result = sanitizeFinding({});

            assert.strictEqual(result.title, 'Unknown');
            assert.strictEqual(result.description, '');
            assert.strictEqual(result.severity, 'info');
        });

        test('defaults invalid severity to info', () => {
            const result = sanitizeFinding({ severity: 'bad' });
            assert.strictEqual(result.severity, 'info');
        });
    });
});
