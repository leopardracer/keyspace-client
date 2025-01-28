import { base64urlnopad } from "@scure/base";
import {
  decodeAbiParameters,
  encodePacked,
  hexToBytes,
  sha256,
  stringToBytes,
  type Hex
} from "viem";
import { wrapSignature } from "../../user-op";
import { encodeWebAuthnAuth, preventSignatureMalleability } from "./signatures";
import { getConfigDataForPrivateKey } from "./config-data";

export type P256PrivateKey = {
  x: Buffer;
  y: Buffer;
  sign: (message: string, format: string) => Buffer;
};

export const authenticatorData = "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000";

/**
 * Creates a WebAuthn-formatted payload and signs it with the provided P256 private key.
 * 
 * This is intended to simulate a WebAuthn signature from a browser, not for use by wallets.
 *
 * @param challenge - The challenge in hexadecimal format.
 * @param authenticatorData - The authenticator data in hexadecimal format.
 * @param p256PrivateKey - The P-256 private key used for signing.
 * @returns A WebAuthn-formatted signature.
 */
export function p256WebAuthnSign(
  { challenge, authenticatorData, p256PrivateKey }: { challenge: Hex; authenticatorData: Hex; p256PrivateKey: any; }
) {
  const challengeBase64 = base64urlnopad.encode(hexToBytes(challenge));
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${challengeBase64}","origin":"https://keys.coinbase.com"}`;
  const clientDataJSONHash = sha256(stringToBytes(clientDataJSON));
  const message = encodePacked(["bytes", "bytes32"], [authenticatorData, clientDataJSONHash]);
  const sig = p256PrivateKey.sign(Buffer.from(message.slice(2), "hex"), "hex");
  const [unsafeR, unsafeS] = decodeAbiParameters([{ type: "uint256" }, { type: "uint256" }], `0x${sig}` as Hex);
  const {r, s} = preventSignatureMalleability({r: unsafeR, s: unsafeS});
  return { r, s, clientDataJSON, authenticatorData };
}

export type SignAndWrapParameters = {
  hash: Hex;
  ownerIndex: bigint;
  privateKey: P256PrivateKey;
}

/**
 * Signs a hash with the provided private key and wraps the signature for use by the Base Wallet contracts.
 *
 * @param hash - The hash to be signed.
 * @param ownerIndex - The index of the owner in the Base Wallet.
 * @param privateKey - The P256 private key used for signing.
 * @returns A promise that resolves to the wrapped signature as a hex string.
 */
export async function signAndWrap({ hash, ownerIndex, privateKey }: SignAndWrapParameters): Promise<Hex> {
  const signature = await p256WebAuthnSign({
    challenge: hash,
    authenticatorData,
    p256PrivateKey: privateKey,
  });

  return wrapSignature(ownerIndex, encodeWebAuthnAuth(signature));
}
