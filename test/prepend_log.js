
const fs = require('fs');
const path = require('path');

const libPath = path.join(__dirname, 'libv86_patched.mjs');
let content = fs.readFileSync(libPath, 'utf8');

content = ';console.log("XHR type:", typeof XMLHttpRequest);' + content;
fs.writeFileSync(libPath, content);
console.log('Prepended log to', libPath);
