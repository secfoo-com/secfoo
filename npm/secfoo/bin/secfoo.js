#!/usr/bin/env node
"use strict";

/**
 * Resolves and execs the platform-specific secfoo binary installed as an
 * optionalDependency of this package. Uses require.resolve() rather than
 * hand-computing a node_modules path so this works correctly regardless
 * of npm/yarn/pnpm's hoisting behavior.
 */

const { spawnSync } = require("child_process");

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@rakfortltd/secfoo-darwin-arm64",
  "darwin-x64": "@rakfortltd/secfoo-darwin-x64",
  "linux-x64": "@rakfortltd/secfoo-linux-x64",
  "linux-arm64": "@rakfortltd/secfoo-linux-arm64",
  "win32-x64": "@rakfortltd/secfoo-win32-x64",
};

const key = `${process.platform}-${process.arch}`;
const pkgName = PLATFORM_PACKAGES[key];

if (!pkgName) {
  console.error(
    `secfoo: no prebuilt binary is published for platform "${key}". ` +
      `Supported: ${Object.keys(PLATFORM_PACKAGES).join(", ")}. ` +
      "Install via pip instead: pip install secfoo"
  );
  process.exit(1);
}

let binPath;
try {
  const binName = process.platform === "win32" ? "secfoo.exe" : "secfoo";
  binPath = require.resolve(`${pkgName}/bin/${binName}`);
} catch (err) {
  console.error(
    `secfoo: the platform package "${pkgName}" is not installed. This ` +
      "usually means it failed to install as an optional dependency " +
      "(check your npm install logs), or you installed with " +
      "--no-optional / --omit=optional. Try reinstalling, or use " +
      "pip install secfoo instead."
  );
  process.exit(1);
}

const result = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  console.error(`secfoo: failed to launch binary at ${binPath}: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
