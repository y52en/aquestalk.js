
const fs = require('fs');
const path = require('path');

const srcPath = path.join(__dirname, '../node_modules/v86/build/libv86.mjs');
const destPath = path.join(__dirname, 'libv86_debug.mjs');

let content = fs.readFileSync(srcPath, 'utf8');

// Inject log into Node.js file loader
// Pattern: oa=async function(b,c){a||
const pattern = /oa=async function\(b,c\)\{/g;

if (pattern.test(content)) {
    console.log('Node loader found, injecting log...');
    // Inject guard for undefined path
    content = content.replace(pattern, 'oa=async function(b,c){console.log("v86 loading:", b); if(!b) { if(c.done) c.done(new ArrayBuffer(0)); return; }');
    fs.writeFileSync(destPath, content);
    console.log('Debug library saved to', destPath);
} else {
    console.error('Node loader pattern not found.');
    // Try without "async" just in case
    const pattern2 = /oa=function\(b,c\)\{/g;
    if (pattern2.test(content)) {
        content = content.replace(pattern2, 'oa=function(b,c){console.log("v86 loading:", b); if(!b) { if(c.done) c.done(new ArrayBuffer(0)); return; }');
        fs.writeFileSync(destPath, content);
    }
}
