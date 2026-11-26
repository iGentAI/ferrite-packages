#!/usr/bin/env node
// registry-sign: sign and verify packages/registry.json the way `ferrite add`
// verifies a URL registry before installing from it.
//
//   node tools/ferrite-pkg/registry-sign.mjs sign --key <ed25519 private key PEM> <registry.json>
//   node tools/ferrite-pkg/registry-sign.mjs verify --trust ed25519:<base64>[,...] <registry.json> [<signature>]
//
// `sign` writes <registry.json>.sig, a JSON document
// {"alg":"ed25519","key_id":"<16 hex>","signature":"<base64>"}: Ed25519 over
// SIGNED_CONTEXT followed by the exact bytes of the index, key_id the first
// eight bytes of SHA-256 over the 32-byte public key. It verifies what it wrote
// before returning, and prints the FERRITE_REGISTRY_KEYS value for the key.
// The private key never leaves the PEM file it is read from.

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { existsSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const SIGNED_CONTEXT = Buffer.from("ferrite-registry-index-v1\n");
const MAX_SIGNATURE_BYTES = 4096;
// DER SubjectPublicKeyInfo prefix of every Ed25519 public key (RFC 8410).
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function keyId(raw) {
  return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

function rawPublicKey(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  if (der.length !== 44 || !der.subarray(0, 12).equals(SPKI_ED25519_PREFIX)) {
    throw new Error("not an Ed25519 public key");
  }
  return der.subarray(12);
}

export function trustValue(raw) {
  return `ed25519:${Buffer.from(raw).toString("base64")}`;
}

/** Parse FERRITE_REGISTRY_KEYS syntax into [{raw, keyId, publicKey}]. */
export function parseTrust(value) {
  const keys = [];
  for (const [index, entry] of value.split(",").map((s) => s.trim()).entries()) {
    if (!entry) continue;
    if (!entry.startsWith("ed25519:")) throw new Error(`trust entry ${index + 1}: expected ed25519:<base64 public key>`);
    const raw = Buffer.from(entry.slice("ed25519:".length), "base64");
    if (raw.length !== 32 || raw.toString("base64") !== entry.slice("ed25519:".length)) {
      throw new Error(`trust entry ${index + 1}: an Ed25519 public key is 32 bytes of standard base64`);
    }
    const publicKey = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
    keys.push({ raw, keyId: keyId(raw), publicKey });
  }
  if (keys.length === 0) throw new Error("no trusted key given");
  return keys;
}

/** The registry.json.sig document for `index` (exact bytes), signed with `privateKeyPem`. */
export function signRegistry(index, privateKeyPem) {
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error(`the signing key is ${privateKey.asymmetricKeyType}; the registry is signed with Ed25519 only`);
  }
  const raw = rawPublicKey(createPublicKey(privateKey));
  const signature = sign(null, Buffer.concat([SIGNED_CONTEXT, index]), privateKey);
  const document = Buffer.from(
    `${JSON.stringify({ alg: "ed25519", key_id: keyId(raw), signature: signature.toString("base64") })}\n`,
  );
  return { document, keyId: keyId(raw), trust: trustValue(raw) };
}

/** The key id that signed `index`, or an Error naming why the CLI would refuse it. */
export function verifyRegistry(index, document, trusted) {
  if (document.length > MAX_SIGNATURE_BYTES) throw new Error("the signature document is larger than the CLI reads");
  // The CLI reads it with serde_json: invalid UTF-8 and a repeated key are refused there, so here too.
  let parsed, text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(document);
    parsed = JSON.parse(text);
  } catch {
    throw new Error("the signature is not a registry signature document");
  }
  const keys = [...text.matchAll(/"((?:[^"\\]|\\.)*)"(\s*:)?/g)].filter((m) => m[2]).map((m) => JSON.parse(`"${m[1]}"`));
  if (new Set(keys).size !== keys.length) throw new Error("the signature document repeats a field");
  const fields = Object.keys(parsed ?? {}).sort().join(",");
  if (fields !== "alg,key_id,signature") throw new Error(`the signature document has fields [${fields}]; the CLI accepts exactly alg, key_id, signature`);
  if (parsed.alg !== "ed25519") throw new Error(`the signature uses algorithm ${JSON.stringify(parsed.alg)}; only ed25519 is accepted`);
  if (typeof parsed.key_id !== "string" || !/^[0-9a-fA-F]{16}$/.test(parsed.key_id)) throw new Error("key_id is not 16 hexadecimal characters");
  if (typeof parsed.signature !== "string") throw new Error("the signature is not a string");
  const signature = Buffer.from(parsed.signature, "base64");
  if (signature.length !== 64) throw new Error(`an Ed25519 signature is 64 bytes, this one is ${signature.length}`);
  // Node's decoder skips whitespace and accepts URL-safe or unpadded text; the CLI's STANDARD engine does not.
  if (signature.toString("base64") !== parsed.signature) throw new Error("the signature is not canonical standard base64");
  const anchor = trusted.find((key) => key.keyId === parsed.key_id.toLowerCase());
  if (!anchor) {
    throw new Error(`signed by key ${parsed.key_id}, which is not trusted (trusted: ${trusted.map((k) => k.keyId).join(", ")})`);
  }
  if (!verify(null, Buffer.concat([SIGNED_CONTEXT, index]), anchor.publicKey, signature)) {
    throw new Error(`SIGNATURE CHECK FAILED: the index does not match its signature by key ${anchor.keyId}`);
  }
  return anchor.keyId;
}

function parseArgs(argv) {
  const options = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--key" || argv[i] === "--trust") {
      if (argv[i + 1] === undefined) throw new Error(`${argv[i]} needs a value`);
      options[argv[i].slice(2)] = argv[i + 1];
      i += 1;
    } else if (argv[i].startsWith("--")) {
      throw new Error(`unknown option ${argv[i]}`);
    } else {
      positional.push(argv[i]);
    }
  }
  return { options, positional };
}

function main(argv) {
  const [command, ...rest] = argv;
  const { options, positional } = parseArgs(rest);
  if (command === "sign" && options.key && positional.length === 1) {
    const [registryPath] = positional;
    const index = readFileSync(registryPath);
    const { document, keyId: id, trust } = signRegistry(index, readFileSync(options.key));
    verifyRegistry(index, document, parseTrust(trust));
    const out = `${registryPath}.sig`;
    writeFileSync(`${out}.tmp`, document, { mode: 0o644 });
    renameSync(`${out}.tmp`, out);
    console.log(`signed ${registryPath} -> ${out}`);
    console.log(`key_id ${id}`);
    console.log(`FERRITE_REGISTRY_KEYS=${trust}`);
    return 0;
  }
  if (command === "verify" && options.trust && (positional.length === 1 || positional.length === 2)) {
    const [registryPath, signaturePath = `${registryPath}.sig`] = positional;
    const id = verifyRegistry(readFileSync(registryPath), readFileSync(signaturePath), parseTrust(options.trust));
    console.log(`verified ${registryPath}: signed by trusted key ${id}`);
    return 0;
  }
  console.error(
    "usage: registry-sign.mjs sign --key <ed25519 private key PEM> <registry.json>\n" +
      "       registry-sign.mjs verify --trust ed25519:<base64>[,...] <registry.json> [<signature>]",
  );
  return 2;
}

// Node normally resolves the module's path but leaves argv's path alone. Both
// macOS /var aliases and an explicit symlink must still execute the signer.
if (process.argv[1] && existsSync(process.argv[1]) &&
    realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(`registry-sign: ${error.message}`);
    process.exitCode = 1;
  }
}
