
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const unicornPath = path.join(__dirname, '../docs/unicorn-x86.min.js');
const unicornCode = fs.readFileSync(unicornPath, 'utf8');

// Mock window and document
global.window = {};
global.document = { currentScript: { src: '' } };

const context = vm.createContext({
    window: global.window,
    document: global.document,
    console: console,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    setInterval: setInterval,
    clearInterval: clearInterval,
});

// Run the unicorn code in the context
vm.runInContext(unicornCode, context);

if (context.uc) {
    global.window.uc = context.uc;
    global.uc = context.uc; // Backup
} else if (context.window.uc) {
    global.window.uc = context.window.uc;
} else {
    throw new Error('Failed to find "uc" object in context');
}

async function loadUnicorn() {
    // Check if Unicorn is ready or needs initialization
    // Based on previous log, MUnicorn had a 'ready' promise.
    // If 'uc' is the wrapper, it might just be ready.
    // But let's check if 'uc.Unicorn' exists.
    const uc = global.window.uc;
    if (!uc.Unicorn) {
        throw new Error('uc.Unicorn is not defined');
    }
    return Promise.resolve(uc);
}

module.exports = { loadUnicorn };
