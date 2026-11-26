import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const TOOL = join(dirname(fileURLToPath(import.meta.url)), "registry-sign.mjs");
const INDEX = '{\n  "serial": 3,\n  "packages": []\n}\n';

function run(...args) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [TOOL, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (error) {
    return { code: error.status, out: `${error.stdout}${error.stderr}` };
  }
}

function scratch(t) {
  const dir = mkdtempSync(join(tmpdir(), "registry-sign-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function keyFile(dir, name, type = "ed25519") {
  const { privateKey } = generateKeyPairSync(type, type === "ec" ? { namedCurve: "P-256" } : {});
  const path = join(dir, name);
  writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  return path;
}

function signed(t) {
  const dir = scratch(t);
  const registry = join(dir, "registry.json");
  writeFileSync(registry, INDEX);
  const key = keyFile(dir, "registry.pem");
  const result = run("sign", "--key", key, registry);
  assert.equal(result.code, 0, result.out);
  const trust = result.out.match(/^FERRITE_REGISTRY_KEYS=(ed25519:\S+)$/m)[1];
  return { dir, registry, key, trust, out: result.out };
}

test("sign writes the document the CLI parses and it verifies under the printed key", (t) => {
  const { registry, trust, out } = signed(t);
  const document = JSON.parse(readFileSync(`${registry}.sig`, "utf8"));
  assert.deepEqual(Object.keys(document), ["alg", "key_id", "signature"]);
  assert.equal(document.alg, "ed25519");
  assert.match(document.key_id, /^[0-9a-f]{16}$/);
  assert.equal(Buffer.from(document.signature, "base64").length, 64);
  assert.match(out, new RegExp(`^key_id ${document.key_id}$`, "m"));
  assert.equal(Buffer.from(trust.slice("ed25519:".length), "base64").length, 32);
  const verified = run("verify", "--trust", trust, registry);
  assert.equal(verified.code, 0, verified.out);
  assert.match(verified.out, new RegExp(`signed by trusted key ${document.key_id}`));
});

test("one changed byte in the index after signing fails verification", (t) => {
  const { registry, trust } = signed(t);
  writeFileSync(registry, INDEX.replace('"serial": 3', '"serial": 4'));
  const result = run("verify", "--trust", trust, registry);
  assert.equal(result.code, 1);
  assert.match(result.out, /SIGNATURE CHECK FAILED/);
});

test("a document the CLI would refuse is refused: non-canonical base64, a non-string signature, a repeated field (finding_7d09d671bce6dd84)", async () => {
  const { signRegistry, verifyRegistry, parseTrust } = await import("./registry-sign.mjs");
  const { privateKey } = generateKeyPairSync("ed25519");
  const index = Buffer.from(INDEX);
  const signed = signRegistry(index, privateKey.export({ format: "pem", type: "pkcs8" }));
  const trusted = parseTrust(signed.trust);
  const doc = JSON.parse(signed.document);
  assert.equal(verifyRegistry(index, signed.document, trusted), signed.keyId);
  const variants = [
    { ...doc, signature: doc.signature.replace(/=+$/, "") },
    { ...doc, signature: `${doc.signature.slice(0, 10)}\n${doc.signature.slice(10)}` },
    { ...doc, signature: [doc.signature] },
  ];
  for (const variant of variants) assert.throws(() => verifyRegistry(index, Buffer.from(JSON.stringify(variant)), trusted));
  const repeated = `{"alg":"ed25519","key_id":"${doc.key_id}","signature":"AAAA","signature":"${doc.signature}"}`;
  assert.throws(() => verifyRegistry(index, Buffer.from(repeated), trusted), /repeats a field/);
});

test("a signature by a key that is not trusted is refused", (t) => {
  const { dir, registry } = signed(t);
  const copy = join(dir, "copy.json");
  writeFileSync(copy, INDEX);
  const otherTrust = run("sign", "--key", keyFile(dir, "other.pem"), copy).out.match(/FERRITE_REGISTRY_KEYS=(\S+)/)[1];
  const result = run("verify", "--trust", otherTrust, registry);
  assert.equal(result.code, 1);
  assert.match(result.out, /which is not trusted/);
});

test("a key that is not Ed25519 is refused and nothing is written", (t) => {
  const dir = scratch(t);
  const registry = join(dir, "registry.json");
  writeFileSync(registry, INDEX);
  const result = run("sign", "--key", keyFile(dir, "ec.pem", "ec"), registry);
  assert.equal(result.code, 1);
  assert.match(result.out, /the signing key is ec; the registry is signed with Ed25519 only/);
  assert.throws(() => readFileSync(`${registry}.sig`), { code: "ENOENT" });
});

test("a malformed trust value is an error, not an empty trust set", (t) => {
  const { registry } = signed(t);
  for (const bad of ["rsa:AAAA", "ed25519:AAAA", " , "]) {
    const result = run("verify", "--trust", bad, registry);
    assert.equal(result.code, 1, bad);
  }
});

test("the signer executes through a path alias with normal and preserved symlink resolution", (t) => {
  const dir = scratch(t);
  const alias = join(dir, "registry-sign-alias.mjs");
  symlinkSync(TOOL, alias);
  const key = keyFile(dir, "registry.pem");
  for (const flags of [[], ["--preserve-symlinks-main"]]) {
    const registry = join(dir, flags.length ? "preserved.json" : "normal.json");
    writeFileSync(registry, INDEX);
    const out = execFileSync(process.execPath, [...flags, alias, "sign", "--key", key, registry], { encoding: "utf8" });
    const trust = out.match(/^FERRITE_REGISTRY_KEYS=(ed25519:\S+)$/m)?.[1];
    assert.ok(trust, "a successful invocation must actually sign the registry");
    assert.equal(run("verify", "--trust", trust, registry).code, 0);
  }
});
