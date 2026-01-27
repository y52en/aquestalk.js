
const fs = require('fs');
const path = require('path');

// Try to load v86
async function explore() {
    // Use patched library
    const v86Path = path.join(__dirname, 'libv86_patched.mjs');

    // Use dynamic import
    const v86Module = await import('file://' + v86Path);
    console.log('Exports:', Object.keys(v86Module));

    const V86Starter = v86Module.default || v86Module.V86;
    console.log('V86Starter:', V86Starter);

    // Instantiate simple starter to check properties
    // V86Starter expects options. wasm_path is needed.
    const wasmPath = path.join(__dirname, '../node_modules/v86/build/v86.wasm');

    // We need to mock browser environment because v86 checks for window, document etc.
    // Or maybe it supports Node.js? v86 is browser focused.

    // Mocking
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
    global.self = global.window; // v86 uses self sometimes

    // Mock XMLHttpRequest
    global.XMLHttpRequest = class XMLHttpRequest {
        constructor() {
            this.onload = null;
            this.onerror = null;
            this.status = 0;
            this.response = null;
            this.responseType = '';
            this._url = '';
        }
        open(method, url) {
            this._url = url;
        }
        send() {
            // Mock fetching file
            const fs = require('fs');
            // Assuming url is a file path
            try {
                if (this._url.endsWith('.wasm')) {
                    const buffer = fs.readFileSync(this._url);
                    this.status = 200;
                    this.response = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
                    if (this.onload) this.onload();
                } else {
                    console.log('XHR request for:', this._url);
                    // For other files, return empty?
                    this.status = 404;
                    if (this.onerror) this.onerror();
                }
            } catch (e) {
                console.error('XHR Error:', e);
                this.status = 500;
                if (this.onerror) this.onerror();
            }
        }
    };

    console.log('CPU Class:', v86Module.CPU);

    try {
        const emulator = new V86Starter({
            wasm_path: wasmPath,
            memory_size: 32 * 1024 * 1024, // 32MB
            vga_memory_size: 2 * 1024 * 1024,
            bios: { buffer: new Uint8Array(0) }, // Mock bios
            vga_bios: { buffer: new Uint8Array(0) }, // Mock vga bios
            autostart: false,
        });

        console.log('Emulator keys:', Object.keys(emulator));

        emulator.add_listener('emulator-ready', () => {
            console.log('Emulator ready!');
            console.log('v86 keys:', Object.keys(emulator.v86));
            if (emulator.v86.cpu) {
                console.log('cpu keys:', Object.keys(emulator.v86.cpu));
                // Try to read register
                // console.log('EAX:', emulator.v86.cpu.reg32[0]); // EAX is usually index 0
            } else {
                console.log('cpu is undefined in v86 object');
            }
        });

        setTimeout(() => {
            console.log('Timeout reached. Checking emulator state...');
            if (emulator.v86) {
                console.log('v86 keys:', Object.keys(emulator.v86));
                if (emulator.v86.cpu) {
                    console.log('cpu keys:', Object.keys(emulator.v86.cpu));
                }
            } else {
                console.log('emulator.v86 is undefined');
            }
        }, 5000);

    } catch (e) {
        console.error('Error instantiating v86:', e);
    }
}

explore();
