import { V86UnicornAdapter, UC_X86_REG_EAX, UC_X86_REG_ESP } from '../src/v86_unicorn_adapter.ts';

async function main() {
    console.log("Starting Adapter Test");

    const adapter = new V86UnicornAdapter();
    console.log("Adapter created, initializing...");
    await adapter.initialize();
    console.log("Adapter initialized");

    // Test Registers
    adapter.reg_write(UC_X86_REG_EAX, 0x12345678);
    const eax = adapter.reg_read(UC_X86_REG_EAX);
    console.log(`EAX: 0x${eax.toString(16)} (Expected: 0x12345678)`);
    if (eax !== 0x12345678) throw new Error("Register Read/Write Failed");

    // Test Memory
    const addr = 0x10000;
    const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    adapter.mem_write(addr, data);
    const readBack = adapter.mem_read(addr, 4);
    console.log(`Memory Read: ${Buffer.from(readBack).toString('hex')} (Expected: deadbeef)`);
    if (readBack[0] !== 0xDE || readBack[1] !== 0xAD) throw new Error("Memory Read/Write Failed");

    console.log("Adapter Test Passed");
}

main().catch(e => {
    console.error(e);
    process.exit(1);
});
