'use strict';
// Unpacks the bundled library sources into the build directory.
const path = require('path');
const [archive, outDir] = process.argv.slice(2);
console.log(`unpack ${path.basename(archive)} -> ${outDir}`);
