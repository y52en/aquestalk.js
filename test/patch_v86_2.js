
const fs = require('fs');
const path = require('path');

const libPath = path.join(__dirname, 'libv86_patched.mjs');
let content = fs.readFileSync(libPath, 'utf8');

// Patch XMLHttpRequest check to force browser mode
// "undefined"===typeof XMLHttpRequest
const pattern = /"undefined"===typeof XMLHttpRequest/g;

if (pattern.test(content)) {
    console.log('XHR check pattern found, patching...');
    content = content.replace(pattern, 'false');
    fs.writeFileSync(libPath, content);
    console.log('Patched library saved to', libPath);
} else {
    console.error('XHR check pattern not found.');
}
