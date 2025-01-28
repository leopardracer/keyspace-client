import { base64urlnopad } from "@scure/base";
import { Hex, bytesToBigInt, decodeAbiParameters, encodeAbiParameters, hexToBigInt, hexToBytes, stringToHex } from "viem";
import { wrapSignature } from "../../user-op";


export interface WebAuthnSignature {
  r: bigint;
  s: bigint;
  clientDataJSON: string;
  authenticatorData: string;
}

export const WebAuthnAuthStruct = {
  components: [
    {
      name: "authenticatorData",
      type: "bytes",
    },
    { name: "clientDataJSON", type: "bytes" },
    { name: "challengeIndex", type: "uint256" },
    { name: "typeIndex", type: "uint256" },
    {
      name: "r",
      type: "uint256",
    },
    {
      name: "s",
      type: "uint256",
    },
  ],
  name: "WebAuthnAuth",
  type: "tuple",
};

/**
 * Builds a dummy signature for estimating the gas cost of user operations.
 *
 * @returns {Uint8Array} The encoded dummy signature.
 */
export function buildDummySignature(): Hex {
  const challenge = new Uint8Array(32);
  return wrapSignature(0n, encodeWebAuthnAuth({
    r: 0n,
    s: 0n,
    clientDataJSON: `{"type":"webauthn.get","challenge":"${base64urlnopad.encode(challenge)}","origin":"https://keys.coinbase.com"}`,
    authenticatorData: "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000",
  }));
}

/**
 * Encodes a WebAuthn signature into the WebAuthnAuth struct expected by the Base Wallet contracts.
 *
 * @param signature - The signature to encode.
 * @returns The encoded signature.
 */
export function encodeWebAuthnAuth(
  { authenticatorData, clientDataJSON, r, s }: WebAuthnSignature
) {
  const challengeIndex = clientDataJSON.indexOf("\"challenge\":");
  const typeIndex = clientDataJSON.indexOf("\"type\":");

  return encodeAbiParameters(
    [WebAuthnAuthStruct],
    [
      {
        authenticatorData,
        clientDataJSON: stringToHex(clientDataJSON),
        challengeIndex,
        typeIndex,
        r,
        s,
      },
    ]
  );
}

/**
 * Ensures the signature is not malleable to pass the check in webauthn-sol.
 *
 * @returns The signature components.
 */
export function preventSignatureMalleability({r, s}: { r: bigint; s: bigint; }): { r: bigint; s: bigint; } {
  const n = hexToBigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  if (s > n / 2n) {
    s = n - s;
  }
  return { r, s };
}

/**
 * Decodes an ASN.1 sequence from a DER encoded signature.
 *
 * @param input - The DER encoded signature.
 * @returns The decoded sequence.
 */
export function decodeASN1Sequence(input: Uint8Array): Uint8Array[] {
  if (input[0] !== 0x30) {
    throw new Error("Invalid ASN.1 sequence");
  }
  const seqLength = input[1];
  const values = [];
  let bytes = input.slice(2, 2 + seqLength);
  while (bytes.length > 0) {
    const tag = bytes[0];
    if (tag !== 0x02) {
      throw new Error("Invalid ASN.1 integersequence");
    }
    const valueLength = bytes[1];
    const value = bytes.slice(2, 2 + valueLength);
    values.push(value);
    bytes = bytes.slice(2 + valueLength);
  }
  return values;
}

/**
 * Converts a DER encoded signature to the format expected by the Base Wallet contracts.
 *
 * @param signature - The DER encoded signature.
 * @returns The converted signature.
 */
export function convertDERSignature(signature: Hex): { r: bigint; s: bigint; } {
  const input = hexToBytes(signature);
  const values = decodeASN1Sequence(input);
  const r = bytesToBigInt(values[0]);
  const s = bytesToBigInt(values[1]);
  return preventSignatureMalleability({ r, s });
}
