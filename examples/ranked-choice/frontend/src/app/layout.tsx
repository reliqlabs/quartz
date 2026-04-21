"use client";

import "./globals.css";
import { AbstraxionProvider } from "@burnt-labs/abstraxion";

const config = {
  chainId: process.env.NEXT_PUBLIC_CHAIN_ID || "xion-testnet-2",
  rpcUrl:
    process.env.NEXT_PUBLIC_RPC_URL ||
    "https://rpc.xion-testnet-2.burnt.com:443",
  restUrl:
    process.env.NEXT_PUBLIC_REST_URL ||
    "https://api.xion-testnet-2.burnt.com",
  treasury: process.env.NEXT_PUBLIC_TREASURY_ADDRESS,
  gasPrice: process.env.NEXT_PUBLIC_GAS_PRICE,
  authentication: {
    type: "auto" as const,
    authAppUrl: process.env.NEXT_PUBLIC_AUTH_APP_URL,
  },
  contracts: process.env.NEXT_PUBLIC_CONTRACT_ADDRESS
    ? [process.env.NEXT_PUBLIC_CONTRACT_ADDRESS]
    : undefined,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen bg-[#0a0a12] text-slate-200 antialiased">
        <AbstraxionProvider config={config}>{children}</AbstraxionProvider>
      </body>
    </html>
  );
}
