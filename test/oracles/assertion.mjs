// Independent Node/OpenSSL verification of output from Hellhound's public API.
// The EUnit producer uses a disposable key; only its public key is written.
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

const { token, key } = JSON.parse(
  await readFile("build/assertion-oracles/output.json", "utf8"),
);
const [protectedPart, payloadPart, signaturePart, extra] = token.split(".");
assert.equal(extra, undefined);
const header = JSON.parse(Buffer.from(protectedPart, "base64url").toString());
assert.deepEqual(header, { alg: "RS256", typ: "JWT" });
const publicKey = createPublicKey({ key, format: "jwk" });
const input = Buffer.from(`${protectedPart}.${payloadPart}`);
const signature = Buffer.from(signaturePart, "base64url");
assert(verify("RSA-SHA256", input, publicKey, signature));
const changed = Buffer.from(input);
changed[changed.length - 1] ^= 1;
assert(!verify("RSA-SHA256", changed, publicKey, signature));
assert.deepEqual(JSON.parse(Buffer.from(payloadPart, "base64url").toString()), {
  iss: "application-client",
  iat: 100,
  exp: 700,
  tenant: { roles: ["reader", "writer"], enabled: false },
});
console.log(
  `Node ${process.version} crypto assertion oracle: signature, claims and mutation passed`,
);
