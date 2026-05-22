// emailit-webhook — captures every EmailIt webhook event into public.emailit_events.
//
// Self-hosted log retention: EmailIt's long-term log history is a paid add-on.
// Logging every event here gives unlimited retention at no extra cost.
//
// EmailIt signs every request with two headers:
//   X-Emailit-Signature  — HMAC-SHA256 of "{timestamp}.{rawBody}" using the webhook secret
//   X-Emailit-Timestamp  — Unix timestamp (seconds) when the request was signed
//
// EMAILIT_WEBHOOK_SECRET is set in the function's secrets (EmailIt dashboard -> Webhooks).
// If unset, signature verification is skipped (local testing only).
//
// Event types captured: email.accepted, email.scheduled, email.delivered, email.bounced,
// email.attempted, email.failed, email.rejected, email.suppressed, email.received,
// email.complained, email.clicked, email.loaded (opens), suppression.created/updated/deleted.
//
// Hardened: all processing is wrapped in try/catch and timestamp parsing never throws,
// so a malformed payload returns a clean 500 (EmailIt retries) instead of crashing.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** SHA-256 hex digest of a string. */
async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Parse any timestamp shape EmailIt might send into an ISO string. Never throws.
 * Accepts: ISO strings, Unix seconds (number or numeric string), Unix millis.
 */
function safeTimestamp(raw: unknown): string | null {
  if (raw == null) return null;
  let d: Date;
  if (typeof raw === "number") {
    // Heuristic: < 1e12 is seconds, otherwise millis.
    d = new Date(raw < 1e12 ? raw * 1000 : raw);
  } else {
    const s = String(raw).trim();
    if (s === "") return null;
    const asNum = Number(s);
    d = Number.isFinite(asNum) && /^\d+$/.test(s)
      ? new Date(asNum < 1e12 ? asNum * 1000 : asNum)
      : new Date(s);
  }
  return isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * Verify EmailIt's HMAC-SHA256 signature.
 * Signed payload is "{timestamp}.{rawBody}". Rejects requests older than 5 minutes.
 */
async function verifySignature(
  secret: string,
  timestamp: string,
  rawBody: string,
  signature: string,
): Promise<boolean> {
  const ageMs = Date.now() - parseInt(timestamp) * 1000;
  if (ageMs > 5 * 60 * 1000) {
    console.error("Webhook rejected: timestamp too old", { ageMs });
    return false;
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const computed = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`${timestamp}.${rawBody}`),
  );
  const computedHex = Array.from(new Uint8Array(computed))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Timing-safe comparison.
  if (computedHex.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < computedHex.length; i++) {
    diff |= computedHex.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  // Raw body string first — signature verification needs the exact bytes.
  const rawBody = await req.text();

  const webhookSecret = Deno.env.get("EMAILIT_WEBHOOK_SECRET");
  if (webhookSecret) {
    const signature = req.headers.get("X-Emailit-Signature") ?? "";
    const timestamp = req.headers.get("X-Emailit-Timestamp") ?? "";
    if (!signature || !timestamp) {
      console.error("Webhook rejected: missing signature headers");
      return new Response("Unauthorized", { status: 401 });
    }
    const valid = await verifySignature(webhookSecret, timestamp, rawBody, signature);
    if (!valid) {
      console.error("Webhook rejected: invalid signature");
      return new Response("Unauthorized", { status: 401 });
    }
  }

  try {
    const payload: unknown = JSON.parse(rawBody);

    // EmailIt sends a single event or an array. Normalize to array.
    const events: Record<string, unknown>[] = Array.isArray(payload)
      ? payload
      : [payload as Record<string, unknown>];

    const records = await Promise.all(events.map(async (evt) => {
      const data = (evt?.data as Record<string, unknown>) ?? {};
      const obj = (data.object as Record<string, unknown>) ?? {};

      // EmailIt event id when present; otherwise hash the event so retries dedupe.
      const eventId = evt?.id ?? evt?.event_id ?? data?.id;
      const dedupKey = eventId != null
        ? String(eventId)
        : await sha256Hex(JSON.stringify(evt));

      return {
        event_type: String(evt?.type ?? "unknown"),
        event_id: eventId != null ? String(eventId) : null,
        message_id: (obj.id ?? data.id ?? null) as string | null,
        recipient: (obj.to ?? obj.recipient ?? null) as string | null,
        subject: (obj.subject ?? null) as string | null,
        reason: (obj.reason ?? null) as string | null,
        url: (obj.url ?? null) as string | null,
        event_timestamp: safeTimestamp(obj.created_at ?? obj.timestamp ?? data.created_at),
        dedup_key: dedupKey,
        raw_payload: evt,
      };
    }));

    // Idempotent: a retried webhook carries the same dedup_key and is ignored.
    const { error } = await supabase
      .from("emailit_events")
      .upsert(records, { onConflict: "dedup_key", ignoreDuplicates: true });

    if (error) {
      console.error("emailit upsert error:", JSON.stringify(error), "| rawBody:", rawBody);
      // 500 -> EmailIt retries. Safe: upsert is idempotent.
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: JSON_HEADERS,
      });
    }

    return new Response(JSON.stringify({ ok: true, count: records.length }), {
      status: 200,
      headers: JSON_HEADERS,
    });
  } catch (e) {
    const err = e as Error;
    console.error("emailit handler exception:", err.message, "| stack:", err.stack, "| rawBody:", rawBody);
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: JSON_HEADERS,
    });
  }
});
