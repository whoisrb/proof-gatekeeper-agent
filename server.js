"use strict";
/*
 * Proof Gatekeeper agent endpoint — zkVerify Agent Games.
 * Dependency-free Node.js (stdlib http/crypto/fs only; snarkjs used only by
 * proof.js when a circuit-input template is configured).
 *
 * Protocol (see ../SPEC.md):
 *  - POST <registered path> with header x-agent-games-signature =
 *    HMAC-SHA256 hex over the RAW body, keyed by AGENT_GAMES_HMAC_SECRET.
 *    Verified before parsing. Every response is signed the same way.
 *  - Preflight:  {type:"agent-games.preflight.v1"} -> {ok:true, protocolVersion:"v1"}
 *  - Tasks:      {type:"agent-games.proof-gatekeeper.v1", task_id, mode, input:{...}}
 *                -> {decision, reason_code, proof_tx[, proof, public_signals]}
 *  - GET on the handler path answers a health check.
 * Fail closed: any doubt -> REJECT (or 4xx for unparseable/unauthenticated).
 */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { tryProve, proofActive } = require("./proof");

const PORT = parseInt(process.env.PORT || "3210", 10);
const HANDLER_PATH = process.env.HANDLER_PATH || "/agent";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const DATA_DIR = process.env.AGENT_DATA_DIR || path.join(__dirname, "..", "data");
const SEEN_PATH = path.join(DATA_DIR, "seen-proof-tx.json");
const CACHE_PATH = path.join(DATA_DIR, "task-cache.json");
const LOG_PATH = path.join(DATA_DIR, "requests.jsonl");
const MAX_BODY = 1024 * 1024;
const CACHE_CAP = 5000;

if (!SECRET) {
  console.error("[agent] FATAL: AGENT_GAMES_HMAC_SECRET is not set");
  process.exit(1);
}
if (/PLACEHOLDER/i.test(SECRET)) {
  console.error("[agent] WARNING: running with a local placeholder secret. " +
    "Platform preflight will fail until the real Rotate Secret value is set.");
}

fs.mkdirSync(DATA_DIR, { recursive: true });

function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}
function saveJson(file, value) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value));
  fs.renameSync(tmp, file);
}

// proof_tx references accepted (approved) in previous tasks -> PROOF_REUSED set
const seen = new Set(loadJson(SEEN_PATH, []));
// task_id -> response object, for idempotent retries
const taskCache = loadJson(CACHE_PATH, {});

function persistSeen() { saveJson(SEEN_PATH, [...seen]); }
function persistCache() {
  const keys = Object.keys(taskCache);
  if (keys.length > CACHE_CAP) {
    for (const k of keys.slice(0, keys.length - CACHE_CAP)) delete taskCache[k];
  }
  saveJson(CACHE_PATH, taskCache);
}

function log(entry) {
  try {
    fs.appendFileSync(LOG_PATH, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
  } catch { /* logging must never break a response */ }
}

function hmacHex(rawBody) {
  return crypto.createHmac("sha256", SECRET).update(rawBody).digest("hex");
}
function signatureValid(rawBody, headerValue) {
  if (!headerValue || typeof headerValue !== "string") return false;
  const provided = headerValue.trim().replace(/^sha256=/i, "").toLowerCase();
  const expected = hmacHex(rawBody);
  if (provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

const normHex = (v) => String(v == null ? "" : v).trim().toLowerCase();
function toBigInt(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) ? BigInt(v) : null;
  if (typeof v === "string" && /^-?\d+$/.test(v.trim())) return BigInt(v.trim());
  return null;
}

/*
 * Decision engine — checks run in a fixed order; the first failure decides.
 * Order: VK -> reuse -> threshold -> expiry -> recipient -> amount.
 * A missing/unparseable field fails its own check (fail closed).
 */
function decide(input) {
  const registeredVk = normHex(input && input.registered_vk);
  const proofVk = normHex(input && input.proof_vk);
  if (!registeredVk || !proofVk || proofVk !== registeredVk) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  }

  const proofTx = normHex(input && input.proof_tx);
  if (proofTx && seen.has(proofTx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  }

  const balance = toBigInt(input && input.public_balance);
  const minimum = toBigInt(input && input.minimum);
  if (balance === null || minimum === null || balance < minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  }

  const currentBlock = toBigInt(input && input.current_block);
  const expiryBlock = toBigInt(input && input.expiry_block);
  if (currentBlock === null || expiryBlock === null || currentBlock > expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  }

  const recipient = normHex(input && input.recipient);
  const conditionRecipient = normHex(input && input.condition_recipient);
  if (!recipient || !conditionRecipient || recipient !== conditionRecipient) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  }

  const amount = toBigInt(input && input.amount);
  const maxTransfer = toBigInt(input && input.max_transfer);
  if (amount === null || maxTransfer === null || amount > maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  }

  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": hmacHex(body),
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const started = Date.now();
  const urlPath = (req.url || "").split("?")[0];

  if (req.method === "GET" && (urlPath === HANDLER_PATH || urlPath === "/health")) {
    return sendJson(res, 200, {
      ok: true,
      protocolVersion: "v1",
      agent: "proof-gatekeeper",
      proof_active: proofActive(),
    });
  }
  if (req.method !== "POST" || urlPath !== HANDLER_PATH) {
    return sendJson(res, 404, { ok: false, error: "not found" });
  }

  const chunks = [];
  let size = 0;
  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > MAX_BODY) { req.destroy(); return; }
    chunks.push(chunk);
  });
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    const sigOk = signatureValid(raw, req.headers["x-agent-games-signature"]);
    if (!sigOk) {
      log({ kind: "auth", result: "bad-signature", ms: Date.now() - started });
      return sendJson(res, 401, { ok: false, error: "invalid signature" });
    }

    let body;
    try { body = JSON.parse(raw.toString("utf8")); }
    catch {
      log({ kind: "parse", result: "invalid-json", ms: Date.now() - started });
      return sendJson(res, 400, { ok: false, error: "invalid json" });
    }

    if (body && body.type === "agent-games.preflight.v1") {
      log({ kind: "preflight", result: "ok", ms: Date.now() - started });
      return sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    }

    if (body && body.type === "agent-games.proof-gatekeeper.v1") {
      const taskId = typeof body.task_id === "string" ? body.task_id : "";
      if (taskId && taskCache[taskId]) {
        log({ kind: "task", task_id: taskId, mode: body.mode || null, result: "idempotent-replay", ms: Date.now() - started });
        return sendJson(res, 200, taskCache[taskId]);
      }
      const verdict = decide(body.input || {});
      const response = {
        decision: verdict.decision,
        reason_code: verdict.reason_code,
        proof_tx: body.input && body.input.proof_tx != null ? String(body.input.proof_tx) : null,
      };
      // Attach the agent's own Groth16 proof when the proof module is active.
      try {
        const proof = await tryProve(body, verdict.decision, verdict.reason_code);
        if (proof) {
          response.proof = proof.proof;
          response.public_signals = proof.public_signals;
        }
      } catch (e) {
        log({ kind: "proof", task_id: taskId, result: "proof-error", error: String(e && e.message || e) });
      }
      if (verdict.decision === "APPROVE") {
        const proofTx = normHex(body.input && body.input.proof_tx);
        if (proofTx && !seen.has(proofTx)) { seen.add(proofTx); persistSeen(); }
      }
      if (taskId) { taskCache[taskId] = response; persistCache(); }
      log({
        kind: "task", task_id: taskId, mode: body.mode || null,
        decision: verdict.decision, reason_code: verdict.reason_code,
        proof_attached: !!response.proof, ms: Date.now() - started,
      });
      return sendJson(res, 200, response);
    }

    log({ kind: "unknown", type: body && body.type || null, ms: Date.now() - started });
    return sendJson(res, 400, { ok: false, error: "unknown type" });
  });
  req.on("error", () => { try { res.destroy(); } catch { /* noop */ } });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`[agent] proof-gatekeeper listening on 127.0.0.1:${PORT}${HANDLER_PATH} proof_active=${proofActive()}`);
});
