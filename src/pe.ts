export interface PEResult {
  baseAddress: number;
  imageSize: number;
  aquesTalkSyntheRVA: number;
  iatHooks: { [key: string]: { rva: number; target: number } };
  adjustFdivRVA: number;
  adjustFdivTarget: number;
  writableSections: {
    virtualAddress: number;
    virtualSize: number;
    pointerToRawData: number;
    rawSize: number;
  }[];
  baseRelocationOffsets: number[];
}

const HOOKED_IMPORTS = new Set([
  "malloc",
  "free",
  "strncmp",
  "strncpy",
  "strtok",
  "strchr",
  "stricmp",
  "_stricmp",
  "_initterm",
  "initterm",
  "__CxxFrameHandler",
  "DisableThreadLibraryCalls",
]);

export function parsePE(buffer: ArrayBuffer): PEResult {
  const view = new DataView(buffer);
  const uint8 = new Uint8Array(buffer);

  function requireRange(offset: number, size: number, description: string) {
    if (
      !Number.isSafeInteger(offset) ||
      !Number.isSafeInteger(size) ||
      offset < 0 ||
      size < 0 ||
      offset + size > buffer.byteLength
    ) {
      throw new Error(`Invalid PE ${description}`);
    }
  }

  function readNullTerminatedString(offset: number, description: string) {
    requireRange(offset, 1, description);
    let value = "";
    for (let index = offset; index < uint8.length; index += 1) {
      if (uint8[index] === 0) return value;
      value += String.fromCharCode(uint8[index]);
    }
    throw new Error(`Invalid PE ${description}`);
  }

  requireRange(0, 0x40, "DOS header");

  // DOS Header: "MZ" at 0x0
  if (view.getUint16(0, true) !== 0x5a4d) {
    throw new Error("Not a PE file (MZ header missing)");
  }

  // PE Header offset at 0x3c
  const peOffset = view.getUint32(0x3c, true);
  requireRange(peOffset, 24, "header");
  // PE Signature: "PE\0\0"
  if (view.getUint32(peOffset, true) !== 0x00004550) {
    throw new Error("Not a PE file (PE signature missing)");
  }

  const machine = view.getUint16(peOffset + 4, true);
  if (machine !== 0x014c) {
    // IMAGE_FILE_MACHINE_I386
    throw new Error("Only x86-32 PE files are supported");
  }

  const numberOfSections = view.getUint16(peOffset + 6, true);
  const sizeOfOptionalHeader = view.getUint16(peOffset + 20, true);
  const optionalHeaderOffset = peOffset + 24;
  requireRange(optionalHeaderOffset, sizeOfOptionalHeader, "optional header");
  if (sizeOfOptionalHeader < 0x90) {
    throw new Error("Invalid PE optional header");
  }

  const magic = view.getUint16(optionalHeaderOffset, true);
  if (magic !== 0x010b) {
    // PE32
    throw new Error("Only PE32 (32-bit) is supported");
  }

  const imageBase = view.getUint32(optionalHeaderOffset + 28, true);
  const imageSize = view.getUint32(optionalHeaderOffset + 56, true);

  // Data Directories
  const dataDirectoryOffset = optionalHeaderOffset + 96;
  const exportDirRVA = view.getUint32(dataDirectoryOffset, true);
  const importDirRVA = view.getUint32(dataDirectoryOffset + 8, true);
  const baseRelocationDirRVA = view.getUint32(
    dataDirectoryOffset + 5 * 8,
    true
  );
  const baseRelocationDirSize = view.getUint32(
    dataDirectoryOffset + 5 * 8 + 4,
    true
  );

  // Section Headers
  const sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  requireRange(sectionHeadersOffset, numberOfSections * 40, "section headers");
  const sections: {
    virtualAddress: number;
    virtualSize: number;
    pointerToRawData: number;
    rawSize: number;
    characteristics: number;
  }[] = [];

  for (let i = 0; i < numberOfSections; i++) {
    const offset = sectionHeadersOffset + i * 40;
    sections.push({
      virtualAddress: view.getUint32(offset + 12, true),
      virtualSize: view.getUint32(offset + 8, true),
      pointerToRawData: view.getUint32(offset + 20, true),
      rawSize: view.getUint32(offset + 16, true),
      characteristics: view.getUint32(offset + 36, true),
    });
    const rawSize = view.getUint32(offset + 16, true);
    if (rawSize > 0) {
      requireRange(
        view.getUint32(offset + 20, true),
        rawSize,
        "section data"
      );
    }
  }

  function rvaToOffset(rva: number): number {
    for (const section of sections) {
      if (
        rva >= section.virtualAddress &&
        rva <
          section.virtualAddress +
            Math.max(section.virtualSize, section.rawSize)
      ) {
        return section.pointerToRawData + (rva - section.virtualAddress);
      }
    }
    return rva; // Fallback if no section matches, though unlikely for valid RVA
  }

  // Find AquesTalk_Synthe in Export Table
  let aquesTalkSyntheRVA = 0;
  if (exportDirRVA !== 0) {
    const exportOffset = rvaToOffset(exportDirRVA);
    requireRange(exportOffset, 40, "export directory");
    const numNames = view.getUint32(exportOffset + 24, true);
    const addressOfFunctions = view.getUint32(exportOffset + 28, true);
    const addressOfNames = view.getUint32(exportOffset + 32, true);
    const addressOfNameOrdinals = view.getUint32(exportOffset + 36, true);

    const namesOffset = rvaToOffset(addressOfNames);
    const ordinalsOffset = rvaToOffset(addressOfNameOrdinals);
    const functionsOffset = rvaToOffset(addressOfFunctions);
    requireRange(namesOffset, numNames * 4, "export names");
    requireRange(ordinalsOffset, numNames * 2, "export ordinals");

    for (let i = 0; i < numNames; i++) {
      const nameRVA = view.getUint32(namesOffset + i * 4, true);
      const nameOffset = rvaToOffset(nameRVA);
      const name = readNullTerminatedString(nameOffset, "export name");

      if (name === "AquesTalk_Synthe") {
        const ordinal = view.getUint16(ordinalsOffset + i * 2, true);
        requireRange(functionsOffset + ordinal * 4, 4, "export function");
        aquesTalkSyntheRVA = view.getUint32(functionsOffset + ordinal * 4, true);
        break;
      }
    }
  }

  // Find IAT hooks and _adjust_fdiv
  const iatHooks: { [key: string]: { rva: number; target: number } } = {};
  let adjustFdivRVA = 0;
  let adjustFdivTarget = 0;

  if (importDirRVA !== 0) {
    let importOffset = rvaToOffset(importDirRVA);
    while (true) {
      requireRange(importOffset, 20, "import descriptor");
      const nameRVA = view.getUint32(importOffset + 12, true);
      if (nameRVA === 0) break;

      const firstThunkRVA = view.getUint32(importOffset + 16, true);
      const originalFirstThunkRVA =
        view.getUint32(importOffset, true) || firstThunkRVA;

      if (firstThunkRVA === 0) break;

      const thunkOffset = rvaToOffset(originalFirstThunkRVA);
      const iatOffset = rvaToOffset(firstThunkRVA);
      let entryIndex = 0;

      while (entryIndex < 1000) {
        // Safety limit
        requireRange(thunkOffset + entryIndex * 4, 4, "import thunk");
        requireRange(iatOffset + entryIndex * 4, 4, "IAT entry");
        const thunkValue = view.getUint32(thunkOffset + entryIndex * 4, true);
        if (thunkValue === 0) break;

        const currentIATRVA = firstThunkRVA + entryIndex * 4;
        const currentTargetRVA = view.getUint32(iatOffset + entryIndex * 4, true);

        if ((thunkValue & 0x80000000) === 0) {
          // Import by name
          const nameDataOffset = rvaToOffset(thunkValue);
          requireRange(nameDataOffset, 3, "import name");
          const funcName = readNullTerminatedString(
            nameDataOffset + 2,
            "import name"
          );

          if (HOOKED_IMPORTS.has(funcName) || funcName === "_adjust_fdiv") {
            iatHooks[funcName] = { rva: currentIATRVA, target: currentTargetRVA };
          }
          if (funcName === "_adjust_fdiv") {
            adjustFdivRVA = currentIATRVA;
            adjustFdivTarget = currentTargetRVA;
          }
        }
        entryIndex++;
      }
      importOffset += 20;
    }
  }

  const baseRelocationOffsets: number[] = [];
  if (baseRelocationDirRVA !== 0 && baseRelocationDirSize !== 0) {
    const relocationOffset = rvaToOffset(baseRelocationDirRVA);
    requireRange(
      relocationOffset,
      baseRelocationDirSize,
      "base relocation directory"
    );
    let consumed = 0;
    while (consumed < baseRelocationDirSize) {
      if (consumed + 8 > baseRelocationDirSize) {
        throw new Error("Invalid PE base relocation block");
      }
      const pageRVA = view.getUint32(relocationOffset + consumed, true);
      const blockSize = view.getUint32(relocationOffset + consumed + 4, true);
      if (
        blockSize < 8 ||
        (blockSize - 8) % 2 !== 0 ||
        consumed + blockSize > baseRelocationDirSize
      ) {
        throw new Error("Invalid PE base relocation block");
      }

      for (let entryOffset = 8; entryOffset + 1 < blockSize; entryOffset += 2) {
        const entry = view.getUint16(
          relocationOffset + consumed + entryOffset,
          true
        );
        const type = entry >>> 12;
        if (type === 0) continue; // IMAGE_REL_BASED_ABSOLUTE padding
        if (type !== 3) {
          throw new Error(`Unsupported PE base relocation type: ${type}`);
        }
        const rva = pageRVA + (entry & 0x0fff);
        const fileOffset = rvaToOffset(rva);
        requireRange(fileOffset, 4, "base relocation target");
        baseRelocationOffsets.push(fileOffset);
      }
      consumed += blockSize;
    }
  }

  return {
    baseAddress: imageBase,
    imageSize,
    aquesTalkSyntheRVA,
    iatHooks,
    adjustFdivRVA,
    adjustFdivTarget,
    writableSections: sections
      .filter(section => (section.characteristics & 0x80000000) !== 0)
      .map(({ virtualAddress, virtualSize, pointerToRawData, rawSize }) => ({
        virtualAddress,
        virtualSize,
        pointerToRawData,
        rawSize,
      })),
    baseRelocationOffsets,
  };
}
