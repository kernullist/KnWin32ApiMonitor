import assert from "node:assert/strict";
import { verifiedTypedProof } from "./proof.mjs";

const proof = verifiedTypedProof();
assert.equal(proof.status, "verified", JSON.stringify(proof));
console.log(`Typed ABI proof current: ${proof.apiKeys.length} APIs, x86/x64 ${proof.configuration}, Windows ${proof.windowsRelease}`);
