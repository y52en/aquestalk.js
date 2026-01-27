export class PEParser {
    private buffer: ArrayBuffer;
    private view: DataView;

    constructor(buffer: ArrayBuffer) {
        this.buffer = buffer;
        this.view = new DataView(buffer);
    }

    getImportAddress(dllName: string, funcName: string): number | null {
        const dosHeader = 0;
        if (this.view.getUint16(dosHeader, true) !== 0x5A4D) { // MZ
            throw new Error("Invalid DOS header");
        }

        const peHeader = this.view.getUint32(dosHeader + 0x3C, true);
        if (this.view.getUint32(peHeader, true) !== 0x00004550) { // PE\0\0
            throw new Error("Invalid PE header");
        }

        const optionalHeader = peHeader + 24;
        const magic = this.view.getUint16(optionalHeader, true);
        const is64Bit = magic === 0x20b;

        // Data Directories
        const dataDirectoriesOffset = optionalHeader + (is64Bit ? 112 : 96);
        const importTableRVA = this.view.getUint32(dataDirectoriesOffset + 1 * 8, true);

        if (importTableRVA === 0) return null;

        const importTableOffset = this.rvaToOffset(importTableRVA);
        let currentDescriptor = importTableOffset;

        while (true) {
            const originalFirstThunk = this.view.getUint32(currentDescriptor, true);
            const timeDateStamp = this.view.getUint32(currentDescriptor + 4, true);
            const forwarderChain = this.view.getUint32(currentDescriptor + 8, true);
            const nameRVA = this.view.getUint32(currentDescriptor + 12, true);
            const firstThunk = this.view.getUint32(currentDescriptor + 16, true);

            if (originalFirstThunk === 0 && nameRVA === 0) break;

            const name = this.readString(this.rvaToOffset(nameRVA));

            if (name.toLowerCase() === dllName.toLowerCase()) {
                let thunkOffset = this.rvaToOffset(originalFirstThunk !== 0 ? originalFirstThunk : firstThunk);
                let iatOffset = this.rvaToOffset(firstThunk);

                while (true) {
                    const thunkData = this.view.getUint32(thunkOffset, true);
                    if (thunkData === 0) break;

                    if ((thunkData & 0x80000000) === 0) { // Import by name
                        const nameOffset = this.rvaToOffset(thunkData);
                        // Hint is 2 bytes
                        const importedFuncName = this.readString(nameOffset + 2);
                        if (importedFuncName === funcName) {
                            // The address in the IAT that will be patched by the loader
                            // We return the RVA of the IAT entry
                            return firstThunk + (thunkOffset - this.rvaToOffset(originalFirstThunk));
                        }
                    }
                    thunkOffset += 4;
                    iatOffset += 4;
                }
            }

            currentDescriptor += 20;
        }

        return null;
    }

    private rvaToOffset(rva: number): number {
        const dosHeader = 0;
        const peHeader = this.view.getUint32(dosHeader + 0x3C, true);
        const numberOfSections = this.view.getUint16(peHeader + 6, true);
        const sizeOfOptionalHeader = this.view.getUint16(peHeader + 20, true);

        let sectionHeader = peHeader + 24 + sizeOfOptionalHeader;

        for (let i = 0; i < numberOfSections; i++) {
            const virtualAddress = this.view.getUint32(sectionHeader + 12, true);
            const sizeOfRawData = this.view.getUint32(sectionHeader + 16, true);
            const pointerToRawData = this.view.getUint32(sectionHeader + 20, true);

            if (rva >= virtualAddress && rva < virtualAddress + sizeOfRawData) {
                return pointerToRawData + (rva - virtualAddress);
            }

            sectionHeader += 40;
        }

        // If not found in sections, it might be header?
        return rva;
    }

    private readString(offset: number): string {
        let str = "";
        let charCode;
        while ((charCode = this.view.getUint8(offset++)) !== 0) {
            str += String.fromCharCode(charCode);
        }
        return str;
    }
}
