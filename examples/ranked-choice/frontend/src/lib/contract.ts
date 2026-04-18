/// Contract interaction helpers for the ranked choice voting contract.

export const CONTRACT_ADDRESS = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS || "";

export interface Config {
  admin: string;
  voting_duration: number;
}

export interface Election {
  election_id: number;
  phase: "setup" | "voting" | "tallying" | "complete";
  title: string;
  candidates: string[];
  voting_end: string;
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

/// Query the current election state.
export async function queryElection(
  client: any,
  contractAddress: string
): Promise<Election> {
  return client.queryContractSmart(contractAddress, { election: {} });
}

/// Query the session public key (for encrypting ballots).
export async function querySession(
  client: any,
  contractAddress: string
): Promise<SessionResponse> {
  return client.queryContractSmart(contractAddress, { session: {} });
}

/// Query an election result.
export async function queryResult(
  client: any,
  contractAddress: string,
  electionId: number
): Promise<ElectionResult> {
  return client.queryContractSmart(contractAddress, {
    result: { election_id: electionId },
  });
}
