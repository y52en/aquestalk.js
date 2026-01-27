import JSZip from 'jszip';

export class Downloader {
    constructor() {}

    async downloadAndExtract(url: string, dllName: string): Promise<ArrayBuffer> {
        // If url starts with 'file://', handle local file (for testing)
        // Note: fetch can handle file:// in Node 20+, but we might need manual handling if not.
        // For testing we will rely on fetch working or mocking it.
        // But for real usage it will be http(s).

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to download: ${response.statusText}`);
        }
        const buffer = await response.arrayBuffer();

        const zip = new JSZip();
        const zipContent = await zip.loadAsync(buffer);

        // Find the DLL. It might be in a subdir.
        // We look for 'dllName' (e.g. AquesTalk.dll)
        let dllFile = zipContent.file(dllName);

        if (!dllFile) {
            // Search recursively
            const foundPath = Object.keys(zipContent.files).find(path => path.endsWith(dllName) || path.endsWith(dllName.replace(/\\/g, '/')));
            if (foundPath) {
                dllFile = zipContent.file(foundPath);
            }
        }

        if (!dllFile) {
            throw new Error(`DLL ${dllName} not found in zip`);
        }

        return await dllFile.async("arraybuffer");
    }
}
