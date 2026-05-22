# VENTR Edge Functions

Two production Supabase Edge Functions from VENTR's operations stack. Both are
TypeScript on Deno, handle live traffic, and keep every secret in environment
variables.

- [`form-spam-gateway`](supabase/functions/form-spam-gateway/index.ts): an
  AI-assisted spam classifier for client website contact forms.
- [`emailit-webhook`](supabase/functions/emailit-webhook/index.ts): a webhook
  handler that captures transactional email events into Postgres.

## form-spam-gateway

A stateless classifier that an n8n workflow calls as step one of every contact
form submission. It judges one submission and returns a verdict (`legit`,
`review`, or `spam`). n8n owns all routing downstream.

It runs eight layers, cheapest first. The first layer to reach a decision
short-circuits the rest:

1. **Honeypot**: a hidden field a real person never fills.
2. **Time-trap**: a form completed faster than a human can type.
3. **Rate limit**: one IP flooding the same form.
4. **Disposable email**: throwaway inbox domains.
5. **Content patterns**: weighted regex for SEO pitches, pharma, crypto, and similar.
6. **StopForumSpam**: community blocklist of known spammer IPs and emails.
7. **MX record**: the email domain must have real mail servers.
8. **AI classification**: only the ambiguous remainder reaches the LLM.

Design decisions worth noting:

- **Deterministic checks run before the expensive one.** The LLM call only
  fires for submissions the cheap rule layers could not settle, which keeps
  cost and latency down.
- **Every external call has a timeout budget.** StopForumSpam, the MX lookup,
  and the LLM each run under an `AbortController` deadline, so a slow third
  party can never hang a form submission.
- **It fails open.** If the AI layer errors or times out, the submission is
  flagged `review`, never dropped. A real lead is never lost to an API outage.
- **The LLM goes through OpenRouter** with a model fallback chain, so one
  provider being unavailable does not break classification.
- **Every submission is logged**, spam or not, with the verdict, the deciding
  layer, the latency, and the raw payload.

Schema: [`form_spam_gateway.sql`](supabase/migrations/20260521000000_form_spam_gateway.sql)

## emailit-webhook

A webhook handler that captures every event from EmailIt, a transactional email
provider, into a Postgres table. EmailIt charges for long-term log retention.
This stores the full event history at no extra cost.

Design decisions worth noting:

- **HMAC-SHA256 signature verification.** Every request is verified against a
  shared secret with a constant-time compare and a five-minute timestamp window
  for replay protection. Bad signatures are rejected with `401`.
- **Idempotent capture.** Each event gets a dedup key: EmailIt's event id, or a
  SHA-256 of the payload when there is none. A `UNIQUE` index plus an
  ignore-duplicates upsert means EmailIt's at-least-once retries never create
  duplicate rows.
- **Store and replay.** The full raw payload of every event is kept, so any
  event can be inspected or replayed after a fix.
- **Retry-safe.** On any failure the function returns `500`, which tells EmailIt
  to retry. That is safe precisely because the upsert is idempotent.

Schema: [`emailit_events.sql`](supabase/migrations/20260521130000_emailit_events.sql)

## Notes

These are real functions, lightly scrubbed for public release: project
identifiers removed, example client names genericized. No secrets are committed.
See [`.env.example`](.env.example) for the variables each function reads.

Deploy with the Supabase CLI: `supabase functions deploy <name>`.
