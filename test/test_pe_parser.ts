import * as fs from 'fs';
import * as path from 'path';
import { PEParser } from '../src/pe_parser.ts';

async function main() {
    console.log("Starting PE Parser Test");

    const dllPath = path.join(process.cwd(), 'f1/AquesTalk.dll');
    if (!fs.existsSync(dllPath)) {
        console.warn("AquesTalk.dll not found, skipping PE test");
        return;
    }

    const buffer = fs.readFileSync(dllPath);
    const parser = new PEParser(buffer.buffer); // Pass ArrayBuffer

    // Test finding an import
    // AquesTalk.dll likely imports malloc/free from MSVCRT or similar?
    // Or maybe kernel32.dll functions.
    // Let's look for a common function. 'ExitProcess' from 'KERNEL32.dll'.

    // Note: PEParser uses exact string match for DLL name.

    const importsToCheck = [
        { dll: 'KERNEL32.dll', func: 'ExitProcess' },
        { dll: 'KERNEL32.dll', func: 'VirtualAlloc' },
        { dll: 'msvcrt.dll', func: 'malloc' } // Might differ depending on compiler
    ];

    for (const imp of importsToCheck) {
        try {
            const addr = parser.getImportAddress(imp.dll, imp.func);
            console.log(`Import ${imp.dll}:${imp.func} -> ${addr ? '0x' + addr.toString(16) : 'Not Found'}`);
        } catch (e) {
            console.error(`Error checking ${imp.dll}:${imp.func}:`, e);
        }
    }

    console.log("PE Parser Test Finished");
}

main().catch(e => {
    console.error(e);
    process.exit(1);
});
