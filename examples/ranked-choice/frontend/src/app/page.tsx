"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import {
  useAbstraxionAccount,
  useAbstraxionSigningClient,
} from "@burnt-labs/abstraxion";
import {
  CONTRACT_ADDRESS,
  queryConfig,
  queryElection,
  querySession,
  queryResult,
  createElection,
  openVoting,
  castBallot as submitBallot,
  type Config,
  type Election,
  type ElectionResult,
} from "@/lib/contract";
import { encryptBallot } from "@/lib/encrypt";

// ── Phase badge ────────────────────────────────────────────────────

const phaseColors: Record<string, string> = {
  setup: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  voting: "bg-green-500/20 text-green-300 border-green-500/30",
  tallying: "bg-blue-500/20 text-blue-300 border-blue-500/30",
  complete: "bg-purple-500/20 text-purple-300 border-purple-500/30",
};

function PhaseBadge({ phase }: { phase: string }) {
  return (
    <span
      className={`inline-block rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wider ${phaseColors[phase] || "bg-gray-500/20 text-gray-300"}`}
    >
      {phase}
    </span>
  );
}

// ── Countdown timer ────────────────────────────────────────────────

function Countdown({ endNanos }: { endNanos: string }) {
  const [remaining, setRemaining] = useState("");

  useEffect(() => {
    const endMs = Number(endNanos) / 1e6;
    const tick = () => {
      const diff = endMs - Date.now();
      if (diff <= 0) {
        setRemaining("Voting ended");
        return;
      }
      const h = Math.floor(diff / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setRemaining(
        `${h > 0 ? `${h}h ` : ""}${m}m ${s}s remaining`
      );
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [endNanos]);

  return <span className="text-sm text-slate-400">{remaining}</span>;
}

// ── Vote bar for results ───────────────────────────────────────────

function VoteBar({
  candidate,
  votes,
  maxVotes,
  eliminated,
  isWinner,
}: {
  candidate: string;
  votes: number;
  maxVotes: number;
  eliminated: boolean;
  isWinner: boolean;
}) {
  const pct = maxVotes > 0 ? (votes / maxVotes) * 100 : 0;
  return (
    <div className={`flex items-center gap-3 ${eliminated ? "opacity-40" : ""}`}>
      <span
        className={`w-28 shrink-0 truncate text-sm font-medium ${isWinner ? "text-purple-300" : "text-slate-300"}`}
      >
        {isWinner && <span className="mr-1">*</span>}
        {candidate}
      </span>
      <div className="flex-1">
        <div className="h-6 overflow-hidden rounded-md bg-surface-3">
          <div
            className={`h-full rounded-md transition-all duration-500 ${
              isWinner
                ? "bg-gradient-to-r from-purple-600 to-purple-400"
                : eliminated
                  ? "bg-slate-600"
                  : "bg-gradient-to-r from-xion-dark to-xion"
            }`}
            style={{ width: `${Math.max(pct, 2)}%` }}
          />
        </div>
      </div>
      <span className="w-12 text-right text-sm font-mono text-slate-400">
        {votes}
      </span>
    </div>
  );
}

// ── Admin: Create Election form ────────────────────────────────────

function CreateElectionForm({
  client,
  sender,
  onDone,
}: {
  client: any;
  sender: string;
  onDone: () => void;
}) {
  const [title, setTitle] = useState("");
  const [candidatesText, setCandidatesText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const handleCreate = async () => {
    const candidates = candidatesText
      .split("\n")
      .map((c) => c.trim())
      .filter(Boolean);
    if (!title.trim()) return setError("Title required");
    if (candidates.length < 2) return setError("Need at least 2 candidates");
    if (new Set(candidates).size !== candidates.length)
      return setError("Duplicate candidates");

    setBusy(true);
    setError("");
    try {
      const res = await createElection(
        client,
        sender,
        CONTRACT_ADDRESS,
        title.trim(),
        candidates
      );
      if (res.code !== 0) throw new Error(res.rawLog);
      onDone();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4 rounded-xl border border-border bg-surface-2 p-6">
      <h3 className="text-lg font-semibold text-slate-100">
        Create New Election
      </h3>
      <div>
        <label className="mb-1 block text-sm text-slate-400">Title</label>
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Board of Directors 2026"
          className="w-full rounded-lg border border-border bg-surface px-4 py-2.5 text-slate-200 placeholder-slate-500 outline-none focus:border-xion"
        />
      </div>
      <div>
        <label className="mb-1 block text-sm text-slate-400">
          Candidates (one per line)
        </label>
        <textarea
          value={candidatesText}
          onChange={(e) => setCandidatesText(e.target.value)}
          rows={5}
          placeholder={"Alice\nBob\nCharlie\nDiana"}
          className="w-full rounded-lg border border-border bg-surface px-4 py-2.5 font-mono text-sm text-slate-200 placeholder-slate-500 outline-none focus:border-xion"
        />
      </div>
      {error && (
        <p className="text-sm text-red-400">{error}</p>
      )}
      <button
        onClick={handleCreate}
        disabled={busy}
        className="w-full rounded-lg bg-xion px-4 py-2.5 font-semibold text-white transition hover:bg-xion-light disabled:opacity-50"
      >
        {busy ? "Creating..." : "Create Election"}
      </button>
    </div>
  );
}

// ── Admin: Open Voting button ──────────────────────────────────────

function OpenVotingButton({
  client,
  sender,
  onDone,
}: {
  client: any;
  sender: string;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const handleOpen = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await openVoting(client, sender, CONTRACT_ADDRESS);
      if (res.code !== 0) throw new Error(res.rawLog);
      onDone();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2">
      <button
        onClick={handleOpen}
        disabled={busy}
        className="w-full rounded-lg bg-green-600 px-4 py-2.5 font-semibold text-white transition hover:bg-green-500 disabled:opacity-50"
      >
        {busy ? "Opening..." : "Open Voting"}
      </button>
      {error && <p className="text-sm text-red-400">{error}</p>}
    </div>
  );
}

// ── Voter: Ranking UI ──────────────────────────────────────────────

function RankingUI({
  candidates,
  onSubmit,
  loading,
}: {
  candidates: string[];
  onSubmit: (rankings: string[]) => void;
  loading: boolean;
}) {
  const [rankings, setRankings] = useState<string[]>([]);

  useEffect(() => {
    if (candidates.length > 0 && rankings.length === 0) {
      setRankings([...candidates]);
    }
  }, [candidates, rankings.length]);

  const moveUp = (i: number) => {
    if (i === 0) return;
    const next = [...rankings];
    [next[i - 1], next[i]] = [next[i], next[i - 1]];
    setRankings(next);
  };

  const moveDown = (i: number) => {
    if (i === rankings.length - 1) return;
    const next = [...rankings];
    [next[i], next[i + 1]] = [next[i + 1], next[i]];
    setRankings(next);
  };

  return (
    <div className="space-y-4">
      <div>
        <h3 className="mb-1 text-lg font-semibold text-slate-100">
          Rank the Candidates
        </h3>
        <p className="text-sm text-slate-400">
          Your #1 choice is at the top. Use arrows to reorder.
          Your ballot is encrypted — only the TEE enclave can read it.
        </p>
      </div>

      <div className="space-y-2">
        {rankings.map((candidate, i) => (
          <div
            key={candidate}
            className="flex items-center gap-3 rounded-lg border border-border bg-surface-2 px-4 py-3 transition hover:border-xion/40"
          >
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-xion/20 text-xs font-bold text-xion-light">
              {i + 1}
            </span>
            <span className="flex-1 font-medium text-slate-200">
              {candidate}
            </span>
            <div className="flex gap-1">
              <button
                onClick={() => moveUp(i)}
                disabled={i === 0}
                className="rounded-md border border-border px-2 py-1 text-xs text-slate-400 transition hover:border-slate-400 hover:text-slate-200 disabled:opacity-25"
              >
                &#9650;
              </button>
              <button
                onClick={() => moveDown(i)}
                disabled={i === rankings.length - 1}
                className="rounded-md border border-border px-2 py-1 text-xs text-slate-400 transition hover:border-slate-400 hover:text-slate-200 disabled:opacity-25"
              >
                &#9660;
              </button>
            </div>
          </div>
        ))}
      </div>

      <button
        onClick={() => onSubmit(rankings)}
        disabled={loading || rankings.length === 0}
        className="w-full rounded-lg bg-xion px-4 py-3 text-base font-semibold text-white transition hover:bg-xion-light disabled:opacity-50"
      >
        {loading ? "Encrypting & Submitting..." : "Cast Encrypted Ballot"}
      </button>
    </div>
  );
}

// ── Results display ────────────────────────────────────────────────

function ResultsDisplay({ result }: { result: ElectionResult }) {
  return (
    <div className="space-y-6">
      {/* Winner banner */}
      <div className="rounded-xl border border-purple-500/30 bg-gradient-to-r from-purple-900/40 to-purple-800/20 p-6 text-center">
        <p className="mb-1 text-sm uppercase tracking-wider text-purple-400">
          Winner
        </p>
        <p className="text-3xl font-bold text-white">{result.winner}</p>
        <p className="mt-2 text-sm text-slate-400">
          {result.total_ballots} ballot{result.total_ballots !== 1 ? "s" : ""} cast
          {result.rounds.length > 1
            ? ` | ${result.rounds.length} rounds of instant-runoff`
            : " | Decided in round 1"}
        </p>
      </div>

      {/* Rounds */}
      {result.rounds.map((round) => {
        const maxVotes = Math.max(...round.counts.map(([, v]) => v), 1);
        const sorted = [...round.counts].sort((a, b) => b[1] - a[1]);
        return (
          <div
            key={round.round}
            className="rounded-xl border border-border bg-surface-2 p-5"
          >
            <div className="mb-3 flex items-center justify-between">
              <h4 className="font-semibold text-slate-200">
                Round {round.round}
              </h4>
              {round.eliminated && (
                <span className="rounded-full bg-red-500/15 px-3 py-0.5 text-xs text-red-400">
                  Eliminated: {round.eliminated}
                </span>
              )}
            </div>
            <div className="space-y-2">
              {sorted.map(([candidate, votes]) => (
                <VoteBar
                  key={candidate}
                  candidate={candidate}
                  votes={votes}
                  maxVotes={maxVotes}
                  eliminated={candidate === round.eliminated}
                  isWinner={candidate === result.winner}
                />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────

export default function RankedChoicePage() {
  const {
    data: account,
    isConnected,
    login,
    logout,
  } = useAbstraxionAccount();
  const { client } = useAbstraxionSigningClient();

  const [config, setConfig] = useState<Config | null>(null);
  const [election, setElection] = useState<Election | null>(null);
  const [sessionPubkey, setSessionPubkey] = useState<string | null>(null);
  const [result, setResult] = useState<ElectionResult | null>(null);
  const [status, setStatus] = useState<{
    msg: string;
    type: "info" | "success" | "error";
  } | null>(null);
  const [loading, setLoading] = useState(false);

  const sender = account?.bech32Address || "";
  const isAdmin = config ? sender === config.admin : false;

  // ── Fetch state ──────────────────────────────────────────────────

  const refresh = useCallback(async () => {
    if (!client || !CONTRACT_ADDRESS) return;
    try {
      const [cfg, el, session] = await Promise.all([
        queryConfig(client, CONTRACT_ADDRESS),
        queryElection(client, CONTRACT_ADDRESS).catch(() => null),
        querySession(client, CONTRACT_ADDRESS).catch(() => ({
          pub_key: null,
        })),
      ]);
      setConfig(cfg);
      setElection(el);
      setSessionPubkey(session.pub_key);

      if (el?.phase === "complete") {
        try {
          const res = await queryResult(
            client,
            CONTRACT_ADDRESS,
            el.election_id
          );
          setResult(res);
        } catch {
          setResult(null);
        }
      } else {
        setResult(null);
      }
    } catch (e: any) {
      setStatus({ msg: `Failed to load: ${e.message}`, type: "error" });
    }
  }, [client]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Auto-refresh during voting phase
  useEffect(() => {
    if (election?.phase !== "voting") return;
    const id = setInterval(refresh, 15000);
    return () => clearInterval(id);
  }, [election?.phase, refresh]);

  // ── Cast ballot ──────────────────────────────────────────────────

  const handleCastBallot = async (rankings: string[]) => {
    if (!client || !sender || !sessionPubkey) return;
    setLoading(true);
    setStatus({ msg: "Encrypting ballot...", type: "info" });
    try {
      const ciphertext = encryptBallot(sessionPubkey, {
        ranked_choices: rankings,
      });
      setStatus({ msg: "Submitting to chain...", type: "info" });
      const res = await submitBallot(
        client,
        sender,
        CONTRACT_ADDRESS,
        ciphertext
      );
      if (res.code !== 0) throw new Error(res.rawLog);
      setStatus({
        msg: "Ballot cast! Your rankings are encrypted and private.",
        type: "success",
      });
      await refresh();
    } catch (e: any) {
      setStatus({ msg: e.message, type: "error" });
    } finally {
      setLoading(false);
    }
  };

  // ── Voting time check ────────────────────────────────────────────

  const votingOpen = useMemo(() => {
    if (!election || election.phase !== "voting") return false;
    return Date.now() < Number(election.voting_end) / 1e6;
  }, [election]);

  // ── Render ───────────────────────────────────────────────────────

  if (!CONTRACT_ADDRESS) {
    return (
      <div className="flex min-h-screen items-center justify-center p-8">
        <div className="max-w-md rounded-xl border border-border bg-surface-2 p-8 text-center">
          <h1 className="mb-3 text-2xl font-bold">Ranked Choice Voting</h1>
          <p className="text-slate-400">
            Set{" "}
            <code className="rounded bg-surface-3 px-2 py-0.5 text-sm text-xion-light">
              NEXT_PUBLIC_CONTRACT_ADDRESS
            </code>{" "}
            in your <code>.env.local</code> to get started.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-8">
      {/* Header */}
      <header className="mb-8 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Ranked Choice Voting
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Private instant-runoff voting powered by Quartz TEE
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isConnected ? (
            <div className="flex items-center gap-2">
              {isAdmin && (
                <span className="rounded-full bg-yellow-500/15 px-2.5 py-0.5 text-xs font-medium text-yellow-400">
                  Admin
                </span>
              )}
              <span className="rounded-lg bg-surface-2 px-3 py-1.5 font-mono text-xs text-slate-400">
                {sender.slice(0, 10)}...{sender.slice(-4)}
              </span>
              <button
                onClick={logout}
                className="rounded-lg border border-border px-3 py-1.5 text-xs text-slate-400 transition hover:border-red-500/50 hover:text-red-400"
              >
                Disconnect
              </button>
            </div>
          ) : (
            <button
              onClick={login}
              className="rounded-lg bg-xion px-5 py-2 font-semibold text-white transition hover:bg-xion-light"
            >
              Connect
            </button>
          )}
        </div>
      </header>

      {/* Election info */}
      {election && (
        <div className="mb-6 rounded-xl border border-border bg-surface-2 p-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">
                {election.title || "Untitled Election"}
              </h2>
              <div className="mt-2 flex items-center gap-3 text-sm text-slate-400">
                <PhaseBadge phase={election.phase} />
                <span>
                  {election.ballot_count} ballot
                  {election.ballot_count !== 1 ? "s" : ""}
                </span>
                <span className="text-slate-600">#{election.election_id}</span>
              </div>
            </div>
            {election.phase === "voting" && (
              <Countdown endNanos={election.voting_end} />
            )}
          </div>

          {/* Candidates list (setup/voting) */}
          {(election.phase === "setup" || election.phase === "voting") && (
            <div className="mt-4 flex flex-wrap gap-2">
              {election.candidates.map((c) => (
                <span
                  key={c}
                  className="rounded-full border border-border bg-surface px-3 py-1 text-sm text-slate-300"
                >
                  {c}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Admin controls */}
      {isAdmin && isConnected && client && (
        <div className="mb-6">
          {/* No election or completed — show create form */}
          {(!election || election.phase === "complete") && (
            <CreateElectionForm
              client={client}
              sender={sender}
              onDone={refresh}
            />
          )}

          {/* Setup — show open voting */}
          {election?.phase === "setup" && (
            <div className="rounded-xl border border-border bg-surface-2 p-5">
              <h3 className="mb-3 text-lg font-semibold text-slate-100">
                Admin Controls
              </h3>
              <p className="mb-4 text-sm text-slate-400">
                Election is set up. When ready, open voting to allow ballot
                submissions. Voting will run for{" "}
                {config && Math.round(config.voting_duration / 60)} minutes.
              </p>
              {!sessionPubkey && (
                <p className="mb-4 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-sm text-yellow-300">
                  Enclave session not established. Run the Quartz handshake
                  before opening voting.
                </p>
              )}
              <OpenVotingButton
                client={client}
                sender={sender}
                onDone={refresh}
              />
            </div>
          )}

          {/* Voting — show status */}
          {election?.phase === "voting" && (
            <div className="rounded-xl border border-border bg-surface-2 p-5">
              <h3 className="mb-2 text-lg font-semibold text-slate-100">
                Admin Controls
              </h3>
              <p className="text-sm text-slate-400">
                Voting is open. The enclave will tally results once voting ends
                and the tally request is submitted.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Voting UI */}
      {election?.phase === "voting" && isConnected && votingOpen && (
        <>
          {sessionPubkey ? (
            <div className="mb-6 rounded-xl border border-border bg-surface-2 p-5">
              <RankingUI
                candidates={election.candidates}
                onSubmit={handleCastBallot}
                loading={loading}
              />
            </div>
          ) : (
            <div className="mb-6 rounded-xl border border-red-500/30 bg-red-500/10 p-5">
              <p className="text-sm text-red-300">
                Enclave session not established. The admin needs to run the
                Quartz handshake before ballots can be encrypted.
              </p>
            </div>
          )}
        </>
      )}

      {/* Voting ended but not yet tallied */}
      {election?.phase === "voting" && !votingOpen && (
        <div className="mb-6 rounded-xl border border-blue-500/30 bg-blue-500/10 p-5 text-center">
          <p className="text-blue-300">
            Voting has ended. Waiting for the enclave to compute results...
          </p>
        </div>
      )}

      {/* Not connected prompt */}
      {election?.phase === "voting" && !isConnected && (
        <div className="mb-6 rounded-xl border border-border bg-surface-2 p-8 text-center">
          <p className="mb-4 text-slate-400">
            Connect your wallet to cast your ballot.
          </p>
          <button
            onClick={login}
            className="rounded-lg bg-xion px-6 py-2.5 font-semibold text-white transition hover:bg-xion-light"
          >
            Connect to Vote
          </button>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="mb-6">
          <ResultsDisplay result={result} />
        </div>
      )}

      {/* Status toast */}
      {status && (
        <div
          className={`fixed bottom-6 right-6 max-w-sm rounded-xl border p-4 shadow-2xl backdrop-blur-sm ${
            status.type === "success"
              ? "border-green-500/30 bg-green-900/80 text-green-200"
              : status.type === "error"
                ? "border-red-500/30 bg-red-900/80 text-red-200"
                : "border-blue-500/30 bg-blue-900/80 text-blue-200"
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <p className="text-sm">{status.msg}</p>
            <button
              onClick={() => setStatus(null)}
              className="shrink-0 text-xs opacity-60 hover:opacity-100"
            >
              dismiss
            </button>
          </div>
        </div>
      )}

      {/* Refresh button */}
      <div className="text-center">
        <button
          onClick={refresh}
          className="rounded-lg border border-border px-4 py-2 text-sm text-slate-400 transition hover:border-slate-400 hover:text-slate-200"
        >
          Refresh
        </button>
      </div>
    </div>
  );
}
