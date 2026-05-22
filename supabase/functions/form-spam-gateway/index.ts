// form-spam-gateway
// Stateless anti-spam mediator for VENTR client contact forms.
//
// An n8n workflow calls this as step 1. It classifies ONE submission and
// returns a verdict. It never forwards, never routes, and knows nothing about
// any client registry. n8n owns all routing downstream.
//
// Request  -- POST, JSON body, header: Authorization: Bearer <SPAM_GATEWAY_SECRET>
//   {
//     "client_id":    "acme-co",          // required -- stable slug, the report key
//     "organization": "Acme Co",          // optional -- display name
//     "source_label": "contact",          // optional -- which form
//     "context":      "B2B SaaS company", // optional -- sharpens the AI layer
//     "submission":   { ...raw form fields... },      // required
//     "meta": {
//       "ip":         "1.2.3.4",
//       "user_agent": "...",
//       "source_url": "https://client.com/contact",
//       "honeypot":   "",                            // value of the hidden honeypot field
//       "elapsed_ms": 8400                           // ms from form load to submit
//     }
//   }
//
// Response -- JSON
//   {
//     "verdict":       "legit" | "review" | "spam",
//     "reason":        "...",
//     "confidence":    0-100,        // how sure the gateway is of the verdict
//     "layer":         "honeypot|timetrap|rate_limit|disposable|content|stopforumspam|mx|ai|ai_failopen",
//     "model":         "anthropic/claude-haiku-4.5" | null,
//     "submission_id": "<uuid>"
//   }
//
// n8n branches on `verdict`: spam = stop, legit/review = continue the workflow.
//
// Env (Supabase function secrets):
//   SPAM_GATEWAY_SECRET        -- shared secret every n8n workflow sends
//   OPENROUTER_API_KEY         -- single LLM key (OpenRouter handles model fallback)
//   SUPABASE_URL               -- auto-injected by Supabase
//   SUPABASE_SERVICE_ROLE_KEY  -- auto-injected by Supabase

import { createClient } from "npm:@supabase/supabase-js@2";

// ---- tunables ---------------------------------------------------------------
// Internal spam-likelihood band (0..1) used by the AI layer to pick a verdict.
const REVIEW_THRESHOLD = 0.30; // likelihood >= this (and < SPAM) => review
const SPAM_THRESHOLD = 0.70;   // likelihood >= this => spam
const RATE_LIMIT_MAX = 10;     // submissions per IP ...
const RATE_LIMIT_MINUTES = 5;  // ... within this many minutes => spam
const MIN_FILL_MS = 2000;      // submitted faster than this => bot
const EXTERNAL_TIMEOUT_MS = 2000; // budget for StopForumSpam / MX lookups

// OpenRouter model fallback chain. OpenRouter tries these in order and falls
// through automatically if one is unavailable.
const AI_MODELS = ["anthropic/claude-haiku-4.5", "openai/gpt-4o-mini"];

// ---- disposable / throwaway email domains -----------------------------------
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "10minutemail.com", "guerrillamail.com", "guerrillamail.net",
  "guerrillamailblock.com", "sharklasers.com", "grr.la", "spam4.me", "trashmail.com",
  "trashmail.net", "temp-mail.org", "tempmail.com", "tempmailo.com", "tempmail.net",
  "throwawaymail.com", "throwawaymail.org", "yopmail.com", "yopmail.net", "yopmail.fr",
  "getnada.com", "nada.email", "maildrop.cc", "dispostable.com", "fakeinbox.com",
  "mailnesia.com", "mintemail.com", "mailcatch.com", "emailondeck.com", "mohmal.com",
  "mailsac.com", "inboxkitten.com", "tempr.email", "discard.email", "discardmail.com",
  "maileater.com", "spambog.com", "mytemp.email", "33mail.com", "anonbox.net",
  "mailnull.com", "spamgourmet.com", "jetable.org", "tempinbox.com", "owlymail.com",
  "e4ward.com", "incognitomail.com", "incognitomail.org", "tempmailaddress.com",
  "fakemailgenerator.com", "burnermail.io", "tempemail.net", "mail-temp.com",
  "1secmail.com", "1secmail.org", "1secmail.net", "byom.de", "emailfake.com",
  "email-fake.com", "fakemail.net", "dropmail.me", "10minutemail.net", "10mail.org",
  "20minutemail.com", "33mail.net", "armyspy.com", "cuvox.de", "dayrep.com",
  "einrot.com", "fleckens.hu", "gustr.com", "jourrapide.com", "rhyta.com",
  "superrito.com", "teleworm.us", "trbvm.com", "wegwerfmail.de", "wegwerfmail.net",
  "spambox.us", "mailexpire.com", "mailforspam.com", "mailmoat.com", "tafmail.com",
  "trashinbox.com", "guerrillamail.org", "guerrillamail.de", "guerrillamail.info",
  "guerrillamail.biz", "pokemail.net", "spamavert.com", "spamfree24.org",
  "spamhereplease.com", "tempmailer.com", "tempmailer.de", "throwam.com",
  "throwawayemailaddresses.com", "trash-mail.com", "trash-mail.de", "kurzepost.de",
  "objectmail.com", "proxymail.eu", "rcpt.at", "now.im", "deadaddress.com",
  "despam.it", "fastmail.fm", "filzmail.com", "get1mail.com", "gishpuppy.com",
  "haltospam.com", "hidemail.de", "hochsitze.com", "hulapla.de", "mail-easy.fr",
  "mailbidon.com", "mailblocks.com", "mailde.de", "maileimer.de", "mailfreeonline.com",
  "mailme.lv", "mailme24.com", "mailpick.biz", "mailrock.biz", "mailscrap.com",
  "mailshell.com", "mailsiphon.com", "mailtome.de", "mailzilla.com", "mailzilla.org",
  "noclickemail.com", "noref.in", "nospam4.us", "nospamfor.us", "nowmymail.com",
  "obobbo.com", "onewaymail.com", "ovpn.to", "pjjkp.com", "punkass.com",
  "quickinbox.com", "rppkn.com", "safe-mail.net", "selfdestructingmail.com",
  "sneakemail.com", "snkmail.com", "sofort-mail.de", "sogetthis.com", "spam.la",
  "spamcero.com", "spamcorptastic.com", "spamday.com", "spamex.com", "spamfree.eu",
  "tempemail.com", "tempinbox.co.uk", "thanksnospam.info", "thisisnotmyrealemail.com",
  "tmail.ws", "tmailinator.com", "tradermail.info", "veryrealemail.com", "wh4f.org",
  "willhackforfood.biz", "willselfdestruct.com", "wuzup.net", "wuzupmail.net",
  "yepmail.net", "zoemail.org", "moakt.com", "luxusmail.org", "mailto.plus",
  "fexpost.com", "fexbox.org", "tmpmail.org", "tmpmail.net", "tmpbox.net",
]);

// ---- content-pattern rules --------------------------------------------------
// Each hit adds its weight. The weighted sum (capped at 1.0) is the content
// score. >= SPAM_THRESHOLD => decided as spam here; otherwise the AI layer judges.
const CONTENT_PATTERNS: { re: RegExp; weight: number; tag: string }[] = [
  // SEO / link-building outreach
  { re: /\b(link\s?building|back\s?links?|guest\s?post|domain\s?authority|\bda\s?\d{2}\b|improve your (google\s)?rank|first page of google|seo (services?|audit|expert|company|agency))\b/i, weight: 0.50, tag: "seo-pitch" },
  // web design / dev outsourcing pitches
  { re: /\b(redesign your (website|site)|web\s?design services|develop your (website|app)|offshore (team|developers?)|software development (company|services)|hire (dedicated )?developers?|outsourcing)\b/i, weight: 0.45, tag: "dev-pitch" },
  // pharma
  { re: /\b(viagra|cialis|levitra|online pharmacy|prescription drugs|\bcheap meds?\b)\b/i, weight: 0.85, tag: "pharma" },
  // gambling
  { re: /\b(online casino|sports betting|\bpoker\b|slots? bonus|gambling site)\b/i, weight: 0.80, tag: "gambling" },
  // crypto pitches
  { re: /\b(bitcoin|cryptocurrency|crypto (investment|trading)|forex (trading|signals)|invest(ment)? opportunity|double your (money|investment)|binary options)\b/i, weight: 0.70, tag: "crypto" },
  // loans / financial spam
  { re: /\b(payday loan|quick loan|loan offer|credit repair|debt relief|wire transfer)\b/i, weight: 0.60, tag: "loan" },
  // adult
  { re: /\b(porn|xxx|escorts?|adult (dating|content)|hot singles)\b/i, weight: 0.85, tag: "adult" },
  // counterfeit / replica goods
  { re: /\b(replica (watches|bags|handbags)|counterfeit|knockoff)\b/i, weight: 0.70, tag: "replica" },
  // generic mass-template tells
  { re: /\b(dear (sir|madam|sir\/madam)|to whom it may concern|i hope this (email|message) finds you well)\b/i, weight: 0.30, tag: "template" },
  // bulk-list / marketing-database pitches
  { re: /\b(email (list|database) of|verified (leads?|contacts?)|targeted (email )?list|b2b (data|leads?)|millions of (emails?|leads?))\b/i, weight: 0.55, tag: "leadlist" },
  // social-media-growth pitches
  { re: /\b(buy (followers|likes)|grow your (instagram|tiktok|social)|social media (growth|marketing) (services|package))\b/i, weight: 0.50, tag: "smm-pitch" },
];

const EMAIL_RE = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i;
const URL_RE = /https?:\/\//gi;

// ---- helpers ----------------------------------------------------------------
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// Flatten every string value of the submission into one searchable blob.
function extractText(submission: Record<string, unknown>): string {
  const parts: string[] = [];
  const walk = (v: unknown) => {
    if (typeof v === "string") parts.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  };
  walk(submission);
  return parts.join(" \n ");
}

function extractEmail(submission: Record<string, unknown>, text: string): string | null {
  // prefer an explicit email-ish field, fall back to scanning the text blob
  for (const [k, v] of Object.entries(submission)) {
    if (typeof v === "string" && /e-?mail/i.test(k) && EMAIL_RE.test(v)) {
      return v.match(EMAIL_RE)![0].toLowerCase();
    }
  }
  const m = text.match(EMAIL_RE);
  return m ? m[0].toLowerCase() : null;
}

function contentScore(text: string): { score: number; tags: string[] } {
  let score = 0;
  const tags: string[] = [];
  for (const p of CONTENT_PATTERNS) {
    if (p.re.test(text)) {
      score += p.weight;
      tags.push(p.tag);
    }
  }
  const urlCount = (text.match(URL_RE) || []).length;
  if (urlCount >= 3) {
    score += 0.45;
    tags.push("many-urls");
  }
  return { score: Math.min(score, 1), tags };
}

// fetch with a hard timeout -- never let an external check hang the request
async function fetchWithTimeout(url: string, ms: number, init?: RequestInit): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// StopForumSpam: free community DB of known spammer IPs / emails.
async function checkStopForumSpam(ip: string | null, email: string | null): Promise<boolean> {
  const params = new URLSearchParams({ json: "" });
  if (ip) params.set("ip", ip);
  if (email) params.set("email", email);
  if (!ip && !email) return false;
  try {
    const res = await fetchWithTimeout(
      `https://api.stopforumspam.com/api?${params.toString()}`,
      EXTERNAL_TIMEOUT_MS,
    );
    if (!res.ok) return false;
    const data = await res.json();
    const ipHit = data?.ip?.appears === 1 && (data?.ip?.frequency ?? 0) > 0;
    const emailHit = data?.email?.appears === 1 && (data?.email?.frequency ?? 0) > 0;
    return Boolean(ipHit || emailHit);
  } catch {
    return false; // never block a submission because an external check failed
  }
}

// MX check: a real business email domain has mail servers. None => fake domain.
async function hasMxRecord(domain: string): Promise<boolean> {
  try {
    const res = await fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
      EXTERNAL_TIMEOUT_MS,
      { headers: { accept: "application/dns-json" } },
    );
    if (!res.ok) return true; // inconclusive => do not block
    const data = await res.json();
    return Array.isArray(data?.Answer) && data.Answer.length > 0;
  } catch {
    return true; // inconclusive => do not block
  }
}

// Parse a model's JSON reply, tolerating markdown code fences -- Claude often
// wraps JSON in ```json ... ``` even when asked for a raw JSON object.
function parseJsonLoose(raw: string): Record<string, unknown> {
  let s = raw.trim();
  if (s.startsWith("```")) {
    s = s.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
  }
  try {
    return JSON.parse(s);
  } catch {
    const m = s.match(/\{[\s\S]*\}/); // last resort: first {...} block
    if (m) return JSON.parse(m[0]);
    throw new Error("AI response was not parseable JSON");
  }
}

// AI classification via OpenRouter. Returns a spam likelihood 0..1 + reason + model.
async function classifyWithAI(
  submission: Record<string, unknown>,
  context: string | null,
): Promise<{ likelihood: number; reason: string; model: string }> {
  const apiKey = Deno.env.get("OPENROUTER_API_KEY");
  if (!apiKey) throw new Error("OPENROUTER_API_KEY not set");

  const system =
    "You are a spam classifier for business website contact-form submissions. " +
    "Decide whether a submission is a genuine inquiry from a potential customer, " +
    "or spam / an unsolicited sales pitch (SEO services, web design, software " +
    "development outsourcing, link building, lead lists, crypto, etc.). " +
    'Respond ONLY with JSON: {"score": <number 0..1>, "reason": "<short phrase>"}. ' +
    "score 0 = clearly genuine, 1 = clearly spam.";

  const user =
    (context ? `Business context: ${context}\n\n` : "") +
    `Submission:\n${JSON.stringify(submission, null, 2)}`;

  const res = await fetchWithTimeout(
    "https://openrouter.ai/api/v1/chat/completions",
    8000,
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://ventr.studio",
        "X-Title": "VENTR form-spam-gateway",
      },
      body: JSON.stringify({
        models: AI_MODELS,
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
        response_format: { type: "json_object" },
        temperature: 0,
        max_tokens: 200,
      }),
    },
  );

  if (!res.ok) {
    throw new Error(`OpenRouter ${res.status}: ${await res.text()}`);
  }
  const data = await res.json();
  const content = data?.choices?.[0]?.message?.content ?? "{}";
  const model = data?.model ?? AI_MODELS[0];
  const parsed = parseJsonLoose(content);
  let likelihood = Number(parsed.score);
  if (!Number.isFinite(likelihood)) likelihood = 0.5;
  likelihood = Math.min(Math.max(likelihood, 0), 1);
  return {
    likelihood,
    reason: typeof parsed.reason === "string" ? parsed.reason : "AI classification",
    model,
  };
}

function verdictFromLikelihood(s: number): "legit" | "review" | "spam" {
  if (s >= SPAM_THRESHOLD) return "spam";
  if (s >= REVIEW_THRESHOLD) return "review";
  return "legit";
}

// confidence 0-100 = how sure we are of the verdict. A likelihood far from the
// uncertain midpoint (0.5) means a confident call; near 0.5 means unsure.
function confidenceFromLikelihood(s: number): number {
  return Math.min(100, Math.max(0, Math.round(Math.abs(s - 0.5) * 200)));
}

// ---- handler ----------------------------------------------------------------
Deno.serve(async (req: Request): Promise<Response> => {
  const started = Date.now();

  if (req.method === "OPTIONS") return new Response(null, { status: 204 });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  // auth -- shared secret in the Authorization header
  const secret = Deno.env.get("SPAM_GATEWAY_SECRET");
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!secret || token !== secret) {
    return json({ error: "Unauthorized" }, 401);
  }

  // parse + validate
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const clientId = typeof body.client_id === "string" ? body.client_id.trim() : "";
  const submission = (body.submission && typeof body.submission === "object")
    ? body.submission as Record<string, unknown>
    : null;
  if (!clientId || !submission) {
    return json({ error: "client_id and submission are required" }, 400);
  }

  const organization = typeof body.organization === "string" ? body.organization : null;
  const sourceLabel = typeof body.source_label === "string" ? body.source_label : null;
  const context = typeof body.context === "string" && body.context.trim()
    ? body.context.trim()
    : null;
  const meta = (body.meta && typeof body.meta === "object")
    ? body.meta as Record<string, unknown>
    : {};
  const ip = typeof meta.ip === "string" ? meta.ip : null;
  const userAgent = typeof meta.user_agent === "string" ? meta.user_agent : null;
  const sourceUrl = typeof meta.source_url === "string" ? meta.source_url : null;
  const honeypot = typeof meta.honeypot === "string" ? meta.honeypot.trim() : "";
  const elapsedMs = typeof meta.elapsed_ms === "number" ? meta.elapsed_ms : null;

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );

  const text = extractText(submission);
  const email = extractEmail(submission, text);

  // run the layers -- first one to decide short-circuits the rest.
  // confidence is 0-100: how sure that layer is of the verdict it set.
  let decided: { verdict: "legit" | "review" | "spam"; confidence: number; reason: string; layer: string } | null = null;
  let model: string | null = null;

  // layer 1: honeypot -- a human never fills the hidden field
  if (!decided && honeypot) {
    decided = { verdict: "spam", confidence: 100, reason: "Honeypot field was filled", layer: "honeypot" };
  }

  // layer 2: time-trap -- a human cannot complete a form this fast
  if (!decided && elapsedMs !== null && elapsedMs < MIN_FILL_MS) {
    decided = { verdict: "spam", confidence: 99, reason: `Form submitted in ${elapsedMs}ms`, layer: "timetrap" };
  }

  // layer 3: rate limit -- one IP flooding the same form
  if (!decided && ip) {
    const since = new Date(Date.now() - RATE_LIMIT_MINUTES * 60_000).toISOString();
    const { count, error } = await supabase
      .from("spam_checks")
      .select("id", { count: "exact", head: true })
      .eq("ip_address", ip)
      .gte("created_at", since);
    if (!error && (count ?? 0) >= RATE_LIMIT_MAX) {
      decided = {
        verdict: "spam",
        confidence: 95,
        reason: `Rate limit: ${count} submissions in ${RATE_LIMIT_MINUTES}m`,
        layer: "rate_limit",
      };
    }
  }

  // layer 4: disposable email domain
  if (!decided && email) {
    const domain = email.split("@")[1] ?? "";
    if (DISPOSABLE_DOMAINS.has(domain)) {
      decided = { verdict: "spam", confidence: 96, reason: `Disposable email domain: ${domain}`, layer: "disposable" };
    }
  }

  // layer 5: content patterns
  if (!decided) {
    const cs = contentScore(text);
    if (cs.score >= SPAM_THRESHOLD) {
      decided = {
        verdict: "spam",
        confidence: 90,
        reason: `Spam content patterns: ${cs.tags.join(", ")}`,
        layer: "content",
      };
    }
  }

  // layer 6: StopForumSpam community blocklist
  if (!decided && (ip || email)) {
    if (await checkStopForumSpam(ip, email)) {
      decided = { verdict: "spam", confidence: 95, reason: "Listed on StopForumSpam", layer: "stopforumspam" };
    }
  }

  // layer 7: MX record -- the email domain must have real mail servers
  if (!decided && email) {
    const domain = email.split("@")[1] ?? "";
    if (domain && !(await hasMxRecord(domain))) {
      // no MX => the email is undeliverable. Usually spam, but it could be a
      // typo from a real lead -- flag for review (low confidence), never hard-drop.
      decided = { verdict: "review", confidence: 55, reason: `Email domain has no MX records: ${domain}`, layer: "mx" };
    }
  }

  // layer 8: AI classification -- only the ambiguous remainder reaches here
  if (!decided) {
    try {
      const ai = await classifyWithAI(submission, context);
      model = ai.model;
      decided = {
        verdict: verdictFromLikelihood(ai.likelihood),
        confidence: confidenceFromLikelihood(ai.likelihood),
        reason: `AI: ${ai.reason}`,
        layer: "ai",
      };
    } catch (err) {
      // fail open -- never lose a real lead to an API outage
      decided = {
        verdict: "review",
        confidence: 0,
        reason: `AI unavailable, flagged for manual review (${err instanceof Error ? err.message : "error"})`,
        layer: "ai_failopen",
      };
    }
  }

  const latencyMs = Date.now() - started;

  // log -- every submission, spam or not
  let submissionId: string | null = null;
  const { data: inserted, error: insertErr } = await supabase
    .from("spam_checks")
    .insert({
      client_id: clientId,
      organization,
      source_label: sourceLabel,
      source_url: sourceUrl,
      ip_address: ip,
      user_agent: userAgent,
      payload: submission,
      verdict: decided.verdict,
      confidence: decided.confidence,
      reason: decided.reason,
      layer: decided.layer,
      model,
      latency_ms: latencyMs,
    })
    .select("id")
    .single();
  if (insertErr) {
    console.error("spam_checks insert failed:", insertErr.message);
  } else {
    submissionId = inserted?.id ?? null;
  }

  return json({
    verdict: decided.verdict,
    reason: decided.reason,
    confidence: decided.confidence,
    layer: decided.layer,
    model,
    submission_id: submissionId,
  });
});
