
const fs = require('fs');
const path = require('path');

const libPath = path.join(__dirname, '../node_modules/v86/build/libv86.mjs');
let content = fs.readFileSync(libPath, 'utf8');

// Patch process check to force browser mode
// Pattern found by grep: "undefined"!==typeof process&&process.versions&&process.versions.node
// Note: whitespace might vary if minified differently, but grep showed it compact.
const pattern = /"undefined"!==typeof process&&process\.versions&&process\.versions\.node/g;

if (pattern.test(content)) {
    console.log('Pattern found, patching...');
    content = content.replace(pattern, 'false');
    const newPath = path.join(__dirname, 'libv86_patched.mjs');
    fs.writeFileSync(newPath, content);
    console.log('Patched library saved to', newPath);
} else {
    console.error('Pattern not found in libv86.mjs');
    // Try a looser pattern or just replace "process.versions.node"
    const pattern2 = /process\.versions\.node/g;
    if (pattern2.test(content)) {
        console.log('Alternative pattern found, patching...');
        content = content.replace(pattern2, 'false');
        const newPath = path.join(__dirname, 'libv86_patched.mjs');
        fs.writeFileSync(newPath, content);
        console.log('Patched library saved to', newPath);
    } else {
        console.error('No suitable pattern found.');
    }
}
