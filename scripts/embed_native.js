import fs from "fs";
import { execSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const nativeDir = path.join(__dirname, "../src/native");
const outputTs = path.join(__dirname, "../src/native_code.ts");

console.log("Building native code...");
execSync("make clean && make", { cwd: nativeDir, stdio: "inherit" });

console.log("Extracting symbols...");
// Use nm on an ELF version to get symbols, but we current build binary directly.
// Let's change Makefile to also produce an ELF for symbol extraction.
const elfFile = path.join(nativeDir, "clib.elf");
const linkerLd = path.join(nativeDir, "linker.ld");
const objectFiles = path.join(nativeDir, "*.o");
execSync(`clang -target i386-pc-none-elf -march=i386 -ffreestanding -nostdlib -fuse-ld=lld -Wl,-T,${linkerLd} -o ${elfFile} ${objectFiles}`, { stdio: "inherit" });

const nmOutput = execSync(`nm ${elfFile}`).toString();
const symbols = {};
nmOutput.split("\n").forEach(line => {
    const match = line.match(/([0-9a-f]+) [Tt] (\w+)/);
    if (match) {
        symbols[match[2]] = parseInt(match[1], 16);
    }
});

const binFile = path.join(nativeDir, "clib.bin");
const binData = fs.readFileSync(binFile);
const hexData = binData.toString("hex").match(/.{1,2}/g).map(h => `0x${h}`).join(", ");

const tsContent = `/**
 * This file is auto-generated from C source code in src/native/
 * Do not edit manually.
 */

export const NATIVE_CLIB_BIN = new Uint8Array([
  ${hexData}
]);

export const NATIVE_CLIB_SYMBOLS = ${JSON.stringify(symbols, null, 2)};
`;

fs.writeFileSync(outputTs, tsContent);
console.log(`Generated ${outputTs}`);
