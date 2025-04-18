import { defineConfig } from "@wagmi/cli";
import entrypointABI from "./abis/Entrypoint.json";
import smartWalletABI from "./abis/SmartWallet.json";
import smartWalletFactoryABI from "./abis/SmartWalletFactory.json";
import anchorStateRegistryABI from "./abis/AnchorStateRegistry.json";
import l1BlockABI from "./abis/L1Block.json";
import { baseSepolia, optimismSepolia } from "viem/chains";
import { Abi } from "viem";

export default defineConfig({
  out: "./generated.ts",
  contracts: [
    {
      abi: smartWalletFactoryABI as Abi,
      address: {
        [baseSepolia.id]: "0x775062650652749c86686f68971F23Bb3FFf2b92",
        // [optimismSepolia.id]: "0x4Ca895d26b7eb26a9D980565732049d4199f32C8",
      },
      name: "AccountFactory",
    },
    {
      abi: smartWalletABI as Abi,
      name: "Account",
    },
    {
      abi: entrypointABI as Abi,
      name: "EntryPoint",
      address: "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
    },
    {
      abi: anchorStateRegistryABI as Abi,
      name: "AnchorStateRegistry",
      address: "0x4C8BA32A5DAC2A720bb35CeDB51D6B067D104205",
    },
    {
      abi: l1BlockABI as Abi,
      name: "L1Block",
      address: "0x4200000000000000000000000000000000000015",
    }
  ],
});
