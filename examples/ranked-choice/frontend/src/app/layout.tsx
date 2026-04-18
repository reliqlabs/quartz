"use client";

import { AbstraxionProvider } from "@burnt-labs/abstraxion";

const CHAIN_ID = process.env.NEXT_PUBLIC_CHAIN_ID || "xion-testnet-2";
const RPC_URL =
  process.env.NEXT_PUBLIC_RPC_URL ||
  "https://rpc.xion-testnet-2.burnt.com:443";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", maxWidth: 640, margin: "0 auto", padding: 20 }}>
        <AbstraxionProvider
          config={{
            chainId: CHAIN_ID,
            rpcUrl: RPC_URL,
            authentication: { type: "auto" },
          }}
        >
          {children}
        </AbstraxionProvider>
      </body>
    </html>
  );
}
