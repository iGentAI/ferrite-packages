// Verify the actual files installed by a released CLI in clean application directories.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const root = fileURLToPath(new URL("../", import.meta.url));
const { values } = parseArgs({ options: { cli: { type: "string" }, registry: { type: "string" } } });
const cli = values.cli ? path.resolve(values.cli) : "ferrite";
const source = values.registry ? ["--registry", values.registry] : ["--path", root];
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "package-notices-"));
const pkgs = JSON.parse(fs.readFileSync(path.join(root, "packages/registry.json"))).packages;
if (!pkgs.length) throw new Error("empty public registry");
function match(actual, expected) {
  if (!fs.readFileSync(actual).equals(fs.readFileSync(expected))) throw new Error("installed notice differs: " + actual);
}

try {
  for (const { name } of pkgs) {
    execFileSync(cli, ["new", "webapp", name], { cwd: scratch });
    const app = path.join(scratch, name);
    execFileSync(cli, ["add", name, ...source], { cwd: app });
    const mount = JSON.parse(fs.readFileSync(path.join(app, "ferrite-packages.json"))).packages[name].mount;
    const installed = path.join(app, "src", mount);
    match(path.join(installed, "licenses/LICENSE"), path.join(root, "LICENSE"));
    match(path.join(installed, "licenses/NOTICE"), path.join(root, "NOTICE"));
    const pkg = path.join(root, "packages", name);
    // Every standalone component licence distributed alongside a package must reach its application.
    for (const file of fs.readdirSync(pkg).filter(file => file.startsWith("LICENSE-"))) {
      match(path.join(installed, "licenses", file), path.join(pkg, file));
    }
    if (name === "image-codec") {
      for (const file of fs.readdirSync(path.join(pkg, "src/codec-notices"))) {
        match(path.join(installed, "codec-notices", file), path.join(pkg, "src/codec-notices", file));
      }
    }
    console.log(name + ": installed licence and notices match");
  }
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
