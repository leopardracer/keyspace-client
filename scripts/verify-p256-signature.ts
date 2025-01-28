import { ArgumentParser } from "argparse";
import { Hex, hexToBytes } from "viem";

const P256 = require("ecdsa-secp256r1");

/**
 * Verifies an ECDSA-secp256r1 signature given:
 *   - 64-byte uncompressed public key (x||y) in hex
 *   - Message bytes in hex
 *   - Signature (r||s) in hex
 *
 * Returns true if valid, false otherwise.
 */
function verifySignature(pubKeyHex: Hex, messageHex: Hex, signatureHex: Hex) {
  const publicKey = decodePublicKey(pubKeyHex);
  const messageBuffer = Buffer.from(messageHex.slice(2), 'hex');

  const signature = Buffer.from(signatureHex.slice(2), 'hex');
  console.log("r", signature.subarray(0, 32).toString('hex'));
  console.log("s", signature.subarray(32).toString('hex'));
  
  return publicKey.verify(messageBuffer, signatureHex.slice(2), 'hex');
}

function decodePublicKey(pubKeyHex: Hex) {
  const bytes = hexToBytes(pubKeyHex);
  const x = bytes.slice(0, 32);
  const y = bytes.slice(32, 64);
  return new P256({ x, y });
}

async function main() {
  const parser = new ArgumentParser({
    description: "Verify a P256 signature",
  });

  parser.add_argument("--public-key", {
    help: "The public key of the signer",
    required: true,
  });
  parser.add_argument("--signature", {
    help: "The P256 signature to verify",
    required: true,
  });
  parser.add_argument("--message", {
    help: "The message to verify",
    required: true,
  });

  const args = parser.parse_args();
  const result = verifySignature(args.public_key, args.message, args.signature);
  console.log(result);
}

if (import.meta.main) {
  main();
}
