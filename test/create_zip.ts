import JSZip from 'jszip';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
    const f1Dir = path.join(process.cwd(), 'f1');
    const outputZip = path.join(process.cwd(), 'test/fixtures/f1.zip');

    if (!fs.existsSync(f1Dir)) {
        console.error("f1 directory not found");
        process.exit(1);
    }

    const zip = new JSZip();
    const files = fs.readdirSync(f1Dir);

    for (const file of files) {
        const filePath = path.join(f1Dir, file);
        const content = fs.readFileSync(filePath);
        zip.file('f1/' + file, content); // Add inside f1/ folder as typical structure
    }

    const content = await zip.generateAsync({ type: "nodebuffer" });
    fs.writeFileSync(outputZip, content);
    console.log(`Zip created at ${outputZip}`);
}

main().catch(e => console.error(e));
