/**
 * Prototype Pollution Vulnerabilities
 * WARNING: This code is intentionally vulnerable for testing purposes.
 * DO NOT USE IN PRODUCTION.
 */

// VULNERABLE: Unsafe object merge
function unsafeMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) {
                target[key] = {};
            }
            unsafeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABLE: Deep clone without protection
function deepClone(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    
    let clone = Array.isArray(obj) ? [] : {};
    
    for (let key in obj) {
        clone[key] = deepClone(obj[key]);
    }
    
    return clone;
}

// VULNERABLE: Extend function
function extend(target, ...sources) {
    sources.forEach(source => {
        for (let key in source) {
            target[key] = source[key];
        }
    });
    return target;
}

// VULNERABLE: Assignment from user input
function setUserPreferences(userInput) {
    const preferences = {};
    
    // VULNERABLE: Can pollute Object.prototype
    for (let key in userInput) {
        preferences[key] = userInput[key];
    }
    
    return preferences;
}

// VULNERABLE: Recursive property assignment
function setNestedProperty(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    
    for (let i = 0; i < keys.length - 1; i++) {
        if (!current[keys[i]]) {
            current[keys[i]] = {};
        }
        current = current[keys[i]];
    }
    
    current[keys[keys.length - 1]] = value;
}

module.exports = {
    unsafeMerge,
    deepClone,
    extend,
    setUserPreferences,
    setNestedProperty
};
