
const path = require('path');

async function explore() {
    const v86Path = path.join(__dirname, 'libv86_debug.mjs');
    const v86Module = await import('file://' + v86Path);
    const V86Starter = v86Module.default || v86Module.V86;

    // We don't mock window/document heavily, let v86 detect Node.js
    // But v86 might need minimal mocks even in Node mode if it's not fully supported?
    // Based on source, it checks for process.versions.node.

    global.window = {
        addEventListener: () => {},
        removeEventListener: () => {},
        document: {
            addEventListener: () => {},
            removeEventListener: () => {},
        }
    };
    global.document = global.window.document;
    global.self = global.window;

    try {
        const wasmPath = path.join(__dirname, '../node_modules/v86/build/v86.wasm');

        console.log('Initializing v86 with wasm_path:', wasmPath);

        const biosPath = path.join(__dirname, 'bios.bin');
        const vgaBiosPath = path.join(__dirname, 'vga_bios.bin');

        const emulator = new V86Starter({
            wasm_path: wasmPath,
            memory_size: 32 * 1024 * 1024,
            bios: { url: biosPath },
            vga_bios: { url: vgaBiosPath },
            autostart: false,
        });

        console.log('Emulator created');

        emulator.add_listener('emulator-ready', () => {
            console.log('Emulator ready!');
            console.log('v86 keys:', Object.keys(emulator.v86));
            if (emulator.v86.cpu) {
                console.log('cpu keys:', Object.keys(emulator.v86.cpu));
            } else {
                console.log('cpu is undefined');
            }
        });

    } catch (e) {
        console.error('Error:', e);
    }
}

explore();
