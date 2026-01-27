
const fs = require('fs');
const path = require('path');

async function explore() {
    const v86Path = path.join(__dirname, '../node_modules/v86/build/libv86.js');
    const v86Module = require(v86Path);
    console.log('Exports:', Object.keys(v86Module));

    const V86Starter = v86Module.V86Starter;
    console.log('V86Starter:', V86Starter);

    const wasmPath = path.join(__dirname, '../node_modules/v86/build/v86.wasm');

    // Mock browser
    global.window = {
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => {},
    };
    global.document = {
        createElement: () => ({
            getContext: () => ({}),
            style: {},
        }),
        getElementById: () => null,
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => {},
    };
    global.screen = {};
    global.navigator = { userAgent: 'Node' };
    global.self = global.window;

    try {
        // Try passing buffer directly if supported?
        // Or just path.
        const emulator = new V86Starter({
            wasm_path: wasmPath,
            memory_size: 32 * 1024 * 1024,
            vga_memory_size: 2 * 1024 * 1024,
            bios: { buffer: new Uint8Array(0) },
            vga_bios: { buffer: new Uint8Array(0) },
            autostart: false,
        });

        emulator.add_listener('emulator-ready', () => {
            console.log('Emulator ready!');
        });

    } catch (e) {
        console.error('Error instantiating v86:', e);
    }
}

explore();
