-- spam_checks: every submission seen by the form-spam-gateway function.
--
-- A flat, append-only log. The n8n workflow that calls the gateway stamps
-- client_id + organization on every request; there is no client registry.
-- The gateway classifies one submission and logs the verdict here.
--
-- Schema notes:
--   1. RLS on, no policies: the table holds PII (emails, IPs, messages), so
--      only the service-role key (used by the edge function) can read it.
--   2. spam_stats view: a live daily roll-up. security_invoker = on so it
--      enforces the querying role's RLS rather than the owner's.
--   3. pg_cron retention: rows older than 90 days are deleted nightly.

create table spam_checks (
  id            uuid primary key default gen_random_uuid(),
  created_at    timestamptz not null default now(),

  -- identity, stamped by the n8n workflow (plain text, no registry, no FK)
  client_id     text not null,        -- stable slug, e.g. 'acme-co' -- the query key for reports
  organization  text,                 -- display name, e.g. 'Acme Co' -- report header
  source_label  text,                 -- which form, e.g. 'contact' or 'quote-request'
  source_url    text,                 -- the page the form lived on

  -- request metadata (n8n forwards these from the original form request)
  ip_address    inet,
  user_agent    text,

  -- the submission itself
  payload       jsonb not null,       -- raw form fields

  -- the verdict
  verdict       text not null check (verdict in ('legit','review','spam')),
  confidence    integer check (confidence between 0 and 100),  -- how sure of the verdict
  reason        text,                 -- human-readable why
  layer         text,                 -- which layer decided: honeypot|timetrap|rate_limit|disposable|content|stopforumspam|mx|ai|ai_failopen
  model         text,                 -- AI model used (null when a rule decided)
  latency_ms    integer
);

comment on table spam_checks is
  'Every form submission seen by form-spam-gateway. Flat log, no registry. Per-client reports: WHERE client_id = ''slug''.';

create index spam_checks_client_idx  on spam_checks (client_id, created_at desc);
create index spam_checks_created_idx on spam_checks (created_at);
create index spam_checks_verdict_idx on spam_checks (verdict);
create index spam_checks_ip_idx      on spam_checks (ip_address, created_at desc);

-- RLS: lock the table to the service-role key only. It holds PII.
-- The edge function uses the service role, which bypasses RLS.
-- No policies => nothing else can read it.
alter table spam_checks enable row level security;

-- Live daily stats per client, built straight off spam_checks.
-- security_invoker = on so the view enforces the querying role's RLS, not the owner's.
create or replace view spam_stats with (security_invoker = on) as
select
  client_id,
  organization,
  date_trunc('day', created_at)::date          as day,
  count(*)                                     as total,
  count(*) filter (where verdict = 'legit')    as legit,
  count(*) filter (where verdict = 'review')   as review,
  count(*) filter (where verdict = 'spam')     as spam,
  count(*) filter (where verdict <> 'spam')    as passed
from spam_checks
group by client_id, organization, date_trunc('day', created_at);

comment on view spam_stats is
  'Daily spam/legit/review counts per client. Built live from spam_checks.';

-- Retention: nightly cleanup at 04:00, 90-day window.
create extension if not exists pg_cron;
select cron.schedule(
  'spam-checks-retention',
  '0 4 * * *',
  $$ delete from spam_checks where created_at < now() - interval '90 days' $$
);
