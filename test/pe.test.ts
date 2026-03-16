import { describe, it, expect } from "vitest";
import { parsePE } from "../src/pe";

describe("parsePE", () => {
  it("should throw when MZ header is missing", () => {
    const buffer = new ArrayBuffer(1024);
    expect(() => parsePE(buffer)).toThrow("Not a PE file (MZ header missing)");
  });

  it("should throw when PE signature is missing", () => {
    const buffer = new ArrayBuffer(1024);
    const view = new DataView(buffer);

    // Set MZ header
    view.setUint16(0, 0x5a4d, true); // "MZ"
    // Set PE header offset
    view.setUint32(0x3c, 0x40, true);

    expect(() => parsePE(buffer)).toThrow("Not a PE file (PE signature missing)");
  });

  it("should throw when machine is not x86-32", () => {
    const buffer = new ArrayBuffer(1024);
    const view = new DataView(buffer);

    // Set MZ header
    view.setUint16(0, 0x5a4d, true); // "MZ"
    // Set PE header offset
    const peOffset = 0x40;
    view.setUint32(0x3c, peOffset, true);

    // Set PE signature "PE\0\0"
    view.setUint32(peOffset, 0x00004550, true);

    // Set invalid machine type (e.g., AMD64 = 0x8664)
    view.setUint16(peOffset + 4, 0x8664, true);

    expect(() => parsePE(buffer)).toThrow("Only x86-32 PE files are supported");
  });

  it("should throw when optional header magic is not PE32", () => {
    const buffer = new ArrayBuffer(1024);
    const view = new DataView(buffer);

    // Set MZ header
    view.setUint16(0, 0x5a4d, true); // "MZ"
    // Set PE header offset
    const peOffset = 0x40;
    view.setUint32(0x3c, peOffset, true);

    // Set PE signature "PE\0\0"
    view.setUint32(peOffset, 0x00004550, true);

    // Set machine type to x86-32
    view.setUint16(peOffset + 4, 0x014c, true);

    // Set sizeOfOptionalHeader
    view.setUint16(peOffset + 20, 0xe0, true);

    const optionalHeaderOffset = peOffset + 24;
    // Set invalid magic (e.g., PE32+ = 0x020b)
    view.setUint16(optionalHeaderOffset, 0x020b, true);

    expect(() => parsePE(buffer)).toThrow("Only PE32 (32-bit) is supported");
  });

  it("should parse minimal successful PE header", () => {
    const buffer = new ArrayBuffer(1024);
    const view = new DataView(buffer);

    // Setup MZ header
    view.setUint16(0, 0x5a4d, true); // "MZ"

    // Setup PE header offset
    const peOffset = 0x40;
    view.setUint32(0x3c, peOffset, true);

    // Setup PE signature "PE\0\0"
    view.setUint32(peOffset, 0x00004550, true);

    // Machine = x86-32
    view.setUint16(peOffset + 4, 0x014c, true);

    // Number of Sections = 0
    view.setUint16(peOffset + 6, 0, true);

    // SizeOfOptionalHeader = 0xe0 (standard for PE32)
    view.setUint16(peOffset + 20, 0xe0, true);

    const optionalHeaderOffset = peOffset + 24;
    // Optional Header Magic = PE32
    view.setUint16(optionalHeaderOffset, 0x010b, true);

    // ImageBase = 0x10000000
    const imageBase = 0x10000000;
    view.setUint32(optionalHeaderOffset + 28, imageBase, true);

    // Data Directories - zeroed out naturally by ArrayBuffer

    const result = parsePE(buffer);

    expect(result).toEqual({
      baseAddress: imageBase,
      aquesTalkSyntheRVA: 0,
      iatHooks: {},
      adjustFdivRVA: 0,
      adjustFdivTarget: 0,
    });
  });
});
