import { toUtf8 } from "@cosmjs/encoding";

export const CONTRACT_ADDRESS =
  process.env.NEXT_PUBLIC_CONTRACT_ADDRESS || "";

// ── Types ──────────────────────────────────────────────────────────

export interface Config {
  admin: string;
  voting_duration: number;
}

export interface Election {
  election_id: number;
  phase: "setup" | "voting" | "tallying" | "complete";
  title: string;
  candidates: string[];
  voting_end: string; // nanosecond timestamp
  ballot_count: number;
}

export interface TallyRound {
  round: number;
  counts: [string, number][];
  eliminated: string | null;
}

export interface ElectionResult {
  election_id: number;
  winner: string;
  rounds: TallyRound[];
  total_ballots: number;
}

export interface SessionResponse {
  pub_key: string | null;
}

export interface Ballot {
  ranked_choices: string[];
}

// ── Queries ────────────────────────────────────────────────────────

export async function queryConfig(
  client: any,
  contractAddress: string
): Promise<Config> {
  return client.queryContractSmart(contractAddress, { config: {} });
}

export async function queryElection(
  client: any,
  contractAddress: string
): Promise<Election> {
  return client.queryContractSmart(contractAddress, { election: {} });
}

export async function querySession(
  client: any,
  contractAddress: string
): Promise<SessionResponse> {
  return client.queryContractSmart(contractAddress, { session: {} });
}

export async function queryResult(
  client: any,
  contractAddress: string,
  electionId: number
): Promise<ElectionResult> {
  return client.queryContractSmart(contractAddress, {
    result: { election_id: electionId },
  });
}

// ── Execute helpers ────────────────────────────────────────────────

function execMsg(sender: string, contract: string, msg: object) {
  return {
    typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
    value: {
      sender,
      contract,
      msg: toUtf8(JSON.stringify(msg)),
      funds: [],
    },
  };
}

export async function createElection(
  client: any,
  sender: string,
  contract: string,
  title: string,
  candidates: string[]
) {
  const msg = execMsg(sender, contract, {
    create_election: { title, candidates },
  });
  return client.signAndBroadcast(sender, [msg], "auto", "Create election");
}

export async function openVoting(
  client: any,
  sender: string,
  contract: string
) {
  const msg = execMsg(sender, contract, { open_voting: {} });
  return client.signAndBroadcast(sender, [msg], "auto", "Open voting");
}

export async function castBallot(
  client: any,
  sender: string,
  contract: string,
  ciphertext: string
) {
  const msg = execMsg(sender, contract, {
    cast_ballot: { ciphertext },
  });
  return client.signAndBroadcast(
    sender,
    [msg],
    "auto",
    "Cast ranked choice ballot"
  );
}
