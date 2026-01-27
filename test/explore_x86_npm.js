
const x86 = require('x86');
console.log(x86);

// x86 package usage seems to be:
// var cpu = new x86.CPU();
// cpu.memory.write(...)
// cpu.run();

try {
    const cpu = new x86.CPU();
    console.log('CPU created');

    // Simple test: MOV EAX, 123
    // B8 7B 00 00 00
    const code = [0xB8, 0x7B, 0x00, 0x00, 0x00];

    // Write code to memory at 0x100
    for (let i = 0; i < code.length; i++) {
        cpu.memory.write8(0x100 + i, code[i]);
    }

    cpu.eip = 0x100;

    console.log('Running...');
    cpu.run_instruction(); // Run one instruction

    console.log('EAX:', cpu.reg32[x86.reg.eax]);
} catch (e) {
    console.error(e);
}
