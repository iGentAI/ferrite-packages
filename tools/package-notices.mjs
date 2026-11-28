// ferrite add copies src/ verbatim for non-Rust files. Stage the notices in that tree.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const write = process.argv[2] === "--write";
if (process.argv.length !== 3 || (!write && process.argv[2] !== "--check")) {
  throw new Error("usage: node tools/package-notices.mjs --check|--write");
}
for (const entry of fs.readdirSync(path.join(root, "packages"), { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const pkg = path.join(root, "packages", entry.name);
  if (!fs.existsSync(path.join(pkg, "ferrite-package.json"))) continue;
  const sources = [path.join(root, "LICENSE"), path.join(root, "NOTICE"), ...fs.readdirSync(pkg).filter(name => name.startsWith("LICENSE-")).map(name => path.join(pkg, name))];
  for (const source of sources) {
    const dest = path.join(pkg, "src/licenses", path.basename(source));
    const bytes = fs.readFileSync(source);
    if (write) {
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, bytes);
    } else if (!fs.existsSync(dest) || !fs.readFileSync(dest).equals(bytes)) {
      throw new Error("installable licence differs or is missing: " + path.relative(root, dest));
    }
  }
}
