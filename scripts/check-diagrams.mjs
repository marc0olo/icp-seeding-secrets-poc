#!/usr/bin/env node
/**
 * Validates that every ```mermaid block in the docs actually parses.
 *
 * GitHub renders mermaid, but a block with a syntax error renders as an error
 * box rather than a diagram — so this is silently user-visible. It caught a real
 * one: mermaid treats `;` as a statement separator, so a semicolon inside message
 * text terminates the line and the rest fails to parse.
 *
 *   node scripts/check-diagrams.mjs README.md FOLLOW-UPS.md
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error("usage: check-diagrams.mjs <file.md>...");
  process.exit(2);
}

// mermaid lives in seed/node_modules; this script sits in scripts/, so resolve
// it explicitly rather than relying on directory-walking from here.
let mermaid;
try {
  const require = createRequire(new URL("../seed/package.json", import.meta.url));
  ({ default: mermaid } = await import(pathToFileURL(require.resolve("mermaid")).href));
} catch (e) {
  console.error(`mermaid is not installed; run \`npm ci\` in seed/ (${e.message})`);
  process.exit(2);
}

let checked = 0;
let failed = 0;

for (const file of files) {
  const blocks = [...readFileSync(file, "utf8").matchAll(/```mermaid\n([\s\S]*?)```/g)];
  for (const [i, match] of blocks.entries()) {
    checked++;
    try {
      await mermaid.parse(match[1]);
    } catch (e) {
      failed++;
      console.error(`\n${file}: mermaid block ${i + 1} does not parse\n${e.message}`);
    }
  }
}

if (failed > 0) {
  console.error(`\n${failed} of ${checked} mermaid block(s) failed to parse`);
  process.exit(1);
}
console.log(`ok — ${checked} mermaid block(s) parse`);
