import * as path from 'path';
import * as fs from 'fs';
import { PEParser } from '../src/pe_parser.ts';
import { Downloader } from '../src/downloader.ts';
import { pathToFileURL } from 'url';

async function main() {
    console.log("Starting PE Parser Test");

    const zipPath = path.join(process.cwd(), 'test/fixtures/f1.zip');
    const zipUrl = pathToFileURL(zipPath).href;

    // Mock fetch for file:// URLs
    const originalFetch = global.fetch;
    global.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const urlStr = input.toString();
        if (urlStr.startsWith('file://')) {
            const filePath = urlStr.replace('file://', '');
            // Simple replacement, might need decodeURIComponent for complex paths
            try {
                const buffer = fs.readFileSync(filePath);
                return new Response(buffer);
            } catch (e) {
                return new Response(null, { status: 404, statusText: 'Not Found' });
            }
        }
        return originalFetch(input, init);
    };

    console.log(`Downloading from ${zipUrl}`);

    const downloader = new Downloader();
    let buffer: ArrayBuffer;
    try {
        buffer = await downloader.downloadAndExtract(zipUrl, 'AquesTalk.dll');
        console.log(`Extracted AquesTalk.dll, size: ${buffer.byteLength}`);
    } catch (e) {
        console.error("Download/Extract failed:", e);
        process.exit(1);
    }

    const parser = new PEParser(buffer);

    const importsToCheck = [
        { dll: 'KERNEL32.dll', func: 'ExitProcess' },
        { dll: 'KERNEL32.dll', func: 'VirtualAlloc' },
        { dll: 'msvcrt.dll', func: 'malloc' }
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
