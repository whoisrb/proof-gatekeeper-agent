"use strict";
/*
 * proof.js — Groth16 proof generation for Proof Gatekeeper decisions.
 *
 * Status: WIRED BUT INACTIVE.
 *
 * The platform expects, on every provable task, a Groth16 proof + public
 * signals generated locally with snarkjs over the event circuit
 * (../circuits/gatekeeper.wasm + gatekeeper_final.zkey, vk_hash
 * 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0).
 *
 * The circuit's input signal names/order (13 public signals per the exported
 * VK) are NOT published in the public docs, so a correct input object cannot
 * be constructed yet. Once the mapping is known (dashboard / onboarding),
 * drop a `circuit-inputs.json` next to this file describing how to build the
 * circuit input object from a task, using "{{path}}" placeholders resolved
 * against { task, decision, reason_code }, e.g.:
 *
 *   { "decision": "{{decisionCode}}", "amount": "{{task.input.amount}}", ... }
 *
 * and this module will start returning { proof, public_signals } for the
 * response. Until then it returns null and the endpoint answers with the
 * documented decision shape only (known cost: -2 per provable task, no
 * reliability bonus — decisions still score normally).
 */
const fs = require("fs");
const path = require("path");

const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const TEMPLATE_PATH = path.join(__dirname, "circuit-inputs.json");
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

let snarkjs = null;
let template = null;
try {
  if (fs.existsSync(TEMPLATE_PATH)) {
    template = JSON.parse(fs.readFileSync(TEMPLATE_PATH, "utf8"));
    snarkjs = require("snarkjs");
  }
} catch (e) {
  console.error("[proof] template present but failed to load:", e.message);
  template = null;
}

function resolvePlaceholders(value, ctx) {
  if (typeof value === "string") {
    const m = value.match(/^\{\{(.+)\}\}$/);
    if (!m) return value;
    let cur = ctx;
    for (const part of m[1].split(".")) {
      if (cur == null) return value;
      cur = cur[part];
    }
    return cur == null ? value : String(cur);
  }
  if (Array.isArray(value)) return value.map((v) => resolvePlaceholders(v, ctx));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolvePlaceholders(v, ctx);
    return out;
  }
  return value;
}

async function tryProve(task, decision, reason_code) {
  if (!template || !snarkjs) return null;
  const ctx = {
    task,
    decision,
    reason_code,
    decisionCode: decision === "APPROVE" ? "1" : "0",
  };
  const inputs = resolvePlaceholders(template, ctx);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
  return { proof, public_signals: publicSignals, vk_hash: VK_HASH };
}

module.exports = { tryProve, proofActive: () => !!(template && snarkjs), VK_HASH };
