/**
 * Regular Expression Denial of Service (ReDoS) Vulnerabilities
 * WARNING: This code is intentionally vulnerable for testing purposes.
 * DO NOT USE IN PRODUCTION.
 */

// VULNERABLE: Catastrophic backtracking
function validateEmail(email) {
    // VULNERABLE: Can cause ReDoS with crafted input
    const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
    return regex.test(email);
}

// VULNERABLE: Nested quantifiers
function validateUsername(username) {
    // VULNERABLE: (a+)+ pattern causes exponential backtracking
    const regex = /^(a+)+$/;
    return regex.test(username);
}

// VULNERABLE: Overlapping alternation
function validateURL(url) {
    // VULNERABLE: Can cause severe performance degradation
    const regex = /(.*,)*(.*)$/;
    return regex.test(url);
}

// VULNERABLE: Nested repetition
function validateInput(input) {
    // VULNERABLE: Multiple nested quantifiers
    const regex = /^(a*)*b$/;
    return regex.test(input);
}

// VULNERABLE: Complex pattern with backtracking
function validateHTML(html) {
    // VULNERABLE: Can hang on malicious input
    const regex = /^(<([a-z]+)([^>]*)>.*<\/\2>)+$/i;
    return regex.test(html);
}

// VULNERABLE: Alternation with overlapping patterns
function sanitizeInput(input) {
    // VULNERABLE: (a|a)* causes ReDoS
    const regex = /(a|a)*c/;
    return input.replace(regex, '');
}

module.exports = {
    validateEmail,
    validateUsername,
    validateURL,
    validateInput,
    validateHTML,
    sanitizeInput
};
