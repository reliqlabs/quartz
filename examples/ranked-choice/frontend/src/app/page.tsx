"use client";

import { useState, useEffect, useCallback } from "react";
import {
  useAbstraxionAccount,
  useAbstraxionSigningClient,
} from "@burnt-labs/abstraxion";
import { toUtf8 } from "@cosmjs/encoding";
import {
  CONTRACT_ADDRESS,
  queryElection,
  querySession,
  queryResult,
  type Election,
  type ElectionResult,
} from "@/lib/contract";
import { encryptBallot } from "@/lib/encrypt";

export default function RankedChoicePage() {
  const { data: account, isConnected, login, logout } = useAbstraxionAccount();
  const { client } = useAbstraxionSigningClient();

  const [election, setElection] = useState<Election | null>(null);
  const [sessionPubkey, setSessionPubkey] = useState<string | null>(null);
  const [result, setResult] = useState<ElectionResult | null>(null);
  const [rankings, setRankings] = useState<string[]>([]);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  // Fetch election state
  const refresh = useCallback(async () => {
    if (!client || !CONTRACT_ADDRESS) return;
    try {
      const el = await queryElection(client, CONTRACT_ADDRESS);
      setElection(el);

      const session = await querySession(client, CONTRACT_ADDRESS);
      setSessionPubkey(session.pub_key);

      if (el.phase === "complete") {
        try {
          const res = await queryResult(client, CONTRACT_ADDRESS, el.election_id);
          setResult(res);
        } catch {
          setResult(null);
        }
      }
    } catch (e: any) {
      setStatus(`Error: ${e.message}`);
    }
  }, [client]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Initialize rankings when election loads
  useEffect(() => {
    if (election?.candidates && rankings.length === 0) {
      setRankings([...election.candidates]);
    }
  }, [election, rankings.length]);

  // Move a candidate up in the ranking
  const moveUp = (index: number) => {
    if (index === 0) return;
    const next = [...rankings];
    [next[index - 1], next[index]] = [next[index], next[index - 1]];
    setRankings(next);
  };

  // Move a candidate down in the ranking
  const moveDown = (index: number) => {
    if (index === rankings.length - 1) return;
    const next = [...rankings];
    [next[index], next[index + 1]] = [next[index + 1], next[index]];
    setRankings(next);
  };

  // Submit encrypted ballot
  const castBallot = async () => {
    if (!client || !account || !sessionPubkey || !election) return;

    setLoading(true);
    setStatus("Encrypting ballot...");

    try {
      const ciphertext = encryptBallot(sessionPubkey, {
        ranked_choices: rankings,
      });

      setStatus("Submitting ballot...");

      const msg = {
        typeUrl: "/cosmwasm.wasm.v1.MsgExecuteContract",
        value: {
          sender: account.bech32Address,
          contract: CONTRACT_ADDRESS,
          msg: toUtf8(
            JSON.stringify({ cast_ballot: { ciphertext } })
          ),
          funds: [],
        },
      };

      const res = await client.signAndBroadcast(
        account.bech32Address,
        [msg],
        "auto",
        "Cast ranked choice ballot"
      );

      if (res.code === 0) {
        setStatus("Ballot cast successfully! Your rankings are encrypted — only the enclave can read them.");
      } else {
        setStatus(`Transaction failed: ${res.rawLog}`);
      }

      await refresh();
    } catch (e: any) {
      setStatus(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // ── Render ──

  if (!CONTRACT_ADDRESS) {
    return (
      <div>
        <h1>Ranked Choice Voting</h1>
        <p>
          Set <code>NEXT_PUBLIC_CONTRACT_ADDRESS</code> environment variable to
          the deployed contract address.
        </p>
      </div>
    );
  }

  return (
    <div>
      <h1>Ranked Choice Voting</h1>
      <p style={{ color: "#666", fontSize: 14 }}>
        Private ranked choice voting powered by Quartz TEE
      </p>

      {/* Connection */}
      <section style={{ marginBottom: 24 }}>
        {isConnected ? (
          <div>
            <p>
              Connected: <code>{account?.bech32Address}</code>
            </p>
            <button onClick={logout}>Disconnect</button>
          </div>
        ) : (
          <button onClick={login}>Connect Wallet</button>
        )}
      </section>

      {/* Election Info */}
      {election && (
        <section style={{ marginBottom: 24 }}>
          <h2>{election.title || "Election"}</h2>
          <p>
            Phase: <strong>{election.phase}</strong> | Ballots:{" "}
            {election.ballot_count} | ID: {election.election_id}
          </p>
          {election.phase === "voting" && (
            <p style={{ fontSize: 12, color: "#888" }}>
              Voting ends: {new Date(Number(election.voting_end) / 1e6).toLocaleString()}
            </p>
          )}
        </section>
      )}

      {/* Voting UI */}
      {election?.phase === "voting" && isConnected && sessionPubkey && (
        <section style={{ marginBottom: 24 }}>
          <h3>Rank the candidates</h3>
          <p style={{ fontSize: 13, color: "#666" }}>
            Drag or use arrows to reorder. Your #1 choice is at the top.
            Your ballot will be encrypted — nobody can see your rankings.
          </p>

          <ol style={{ listStyle: "none", padding: 0 }}>
            {rankings.map((candidate, i) => (
              <li
                key={candidate}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "8px 12px",
                  marginBottom: 4,
                  background: "#f5f5f5",
                  borderRadius: 4,
                  border: "1px solid #ddd",
                }}
              >
                <span style={{ fontWeight: "bold", width: 24 }}>
                  #{i + 1}
                </span>
                <span style={{ flex: 1 }}>{candidate}</span>
                <button
                  onClick={() => moveUp(i)}
                  disabled={i === 0}
                  style={{ padding: "2px 8px" }}
                >
                  Up
                </button>
                <button
                  onClick={() => moveDown(i)}
                  disabled={i === rankings.length - 1}
                  style={{ padding: "2px 8px" }}
                >
                  Down
                </button>
              </li>
            ))}
          </ol>

          <button
            onClick={castBallot}
            disabled={loading}
            style={{
              marginTop: 12,
              padding: "10px 24px",
              fontSize: 16,
              cursor: loading ? "wait" : "pointer",
            }}
          >
            {loading ? "Submitting..." : "Cast Encrypted Ballot"}
          </button>
        </section>
      )}

      {/* No session */}
      {election?.phase === "voting" && !sessionPubkey && (
        <p style={{ color: "red" }}>
          Enclave session not established. Run the Quartz handshake first.
        </p>
      )}

      {/* Results */}
      {result && (
        <section>
          <h3>Results</h3>
          <p>
            Winner: <strong>{result.winner}</strong> | Total ballots:{" "}
            {result.total_ballots}
          </p>

          {result.rounds.map((round) => (
            <div
              key={round.round}
              style={{
                marginBottom: 12,
                padding: 12,
                background: "#f9f9f9",
                borderRadius: 4,
              }}
            >
              <h4 style={{ margin: "0 0 8px" }}>Round {round.round}</h4>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                {round.counts.map(([candidate, votes]) => (
                  <li key={candidate}>
                    {candidate}: {votes} votes
                  </li>
                ))}
              </ul>
              {round.eliminated && (
                <p style={{ margin: "4px 0 0", color: "#c00", fontSize: 13 }}>
                  Eliminated: {round.eliminated}
                </p>
              )}
            </div>
          ))}
        </section>
      )}

      {/* Status */}
      {status && (
        <p
          style={{
            marginTop: 16,
            padding: 12,
            background: "#eef",
            borderRadius: 4,
            fontSize: 13,
          }}
        >
          {status}
        </p>
      )}

      <button onClick={refresh} style={{ marginTop: 16 }}>
        Refresh
      </button>
    </div>
  );
}
