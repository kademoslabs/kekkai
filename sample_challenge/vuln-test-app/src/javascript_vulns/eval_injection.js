/**
 * Code Injection Vulnerabilities (eval, Function constructor)
 * WARNING: This code is intentionally vulnerable for testing purposes.
 * DO NOT USE IN PRODUCTION.
 */

// VULNERABLE: Direct eval of user input
function calculateExpression(expression) {
    // VULNERABLE: eval allows arbitrary code execution
    return eval(expression);
}

// VULNERABLE: Function constructor with user input
function createDynamicFunction(functionBody) {
    // VULNERABLE: Similar to eval
    const fn = new Function('x', functionBody);
    return fn;
}

// VULNERABLE: setTimeout with string
function scheduleTask(code, delay) {
    // VULNERABLE: setTimeout with string evaluates code
    setTimeout(code, delay);
}

// VULNERABLE: setInterval with string
function repeatTask(code, interval) {
    // VULNERABLE: setInterval with string evaluates code
    return setInterval(code, interval);
}

// VULNERABLE: Indirect eval
function processUserCode(userCode) {
    // VULNERABLE: window.eval or globalThis.eval
    const result = window.eval(userCode);
    return result;
}

// VULNERABLE: Script tag injection
function loadScript(scriptContent) {
    // VULNERABLE: Creating script element with user content
    const script = document.createElement('script');
    script.innerHTML = scriptContent;
    document.body.appendChild(script);
}

// VULNERABLE: Dynamic property access
function getObjectProperty(obj, propertyPath) {
    // VULNERABLE: Using eval for property access
    return eval(`obj.${propertyPath}`);
}

// VULNERABLE: JSON parsing with eval
function parseJSON(jsonString) {
    // VULNERABLE: Using eval instead of JSON.parse
    return eval('(' + jsonString + ')');
}

module.exports = {
    calculateExpression,
    createDynamicFunction,
    scheduleTask,
    repeatTask,
    processUserCode,
    loadScript,
    getObjectProperty,
    parseJSON
};
