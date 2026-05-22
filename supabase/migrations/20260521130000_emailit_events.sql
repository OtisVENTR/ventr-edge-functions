-- emailit_events: self-hosted EmailIt log retention.
--
-- EmailIt keeps no long-term event history (their retained-logs feature is a paid
-- add-on). Capturing every webhook event into this table gives unlimited retention
-- at no extra cost.
--
-- Schema notes:
--   1. Idempotent capture: dedup_key unique index + upsert ignore-duplicates,
--      so EmailIt webhook retries never create duplicate rows.
--   2. RLS on, no policies: service_role only.
--   3. emailit_deliverability_daily view for bounce / complaint / open rates.
--
-- Populated by the emailit-webhook Edge Function (HMAC-SHA256 verified).

create table if not exists public.emailit_events (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),  -- when WE captured the row
  event_type      text not null,                       -- email.delivered, email.bounced, ...
  event_id        text,                                -- EmailIt event id when present
  message_id      text,                                -- correlates events to a single send
  recipient       text,
  subject         text,
  reason          text,                                -- bounce / fail reason
  url             text,                                -- target url on email.clicked
  event_timestamp timestamptz,                         -- when EmailIt fired the event
  dedup_key       text not null,                       -- event_id, else sha256(event payload)
  raw_payload     jsonb not null                       -- full event for debugging / replay
);

comment on table public.emailit_events is
  'EmailIt transactional + suppression events. Self-hosted log retention (replaces EmailIt paid log add-on). Captured by emailit-webhook Edge Function, HMAC-verified, idempotent on dedup_key.';

-- Idempotency: a retried webhook carries the same dedup_key -> upsert ignores it.
create unique index if not exists uq_emailit_events_dedup
  on public.emailit_events (dedup_key);

-- Query patterns: events for a recipient, filter by type, correlate by message_id, recent-first.
create index if not exists idx_emailit_events_recipient
  on public.emailit_events (recipient);
create index if not exists idx_emailit_events_event_type
  on public.emailit_events (event_type);
create index if not exists idx_emailit_events_message_id
  on public.emailit_events (message_id);
create index if not exists idx_emailit_events_event_ts
  on public.emailit_events (event_timestamp desc);

-- RLS on, no policies -> anon + authenticated blocked, service_role unaffected.
alter table public.emailit_events enable row level security;

-- Daily deliverability rollup. Query: select * from emailit_deliverability_daily;
-- security_invoker = on so the view enforces the querying role's RLS, not the owner's.
create or replace view public.emailit_deliverability_daily
  with (security_invoker = on) as
select
  date_trunc('day', coalesce(event_timestamp, created_at))::date as day,
  count(*) filter (where event_type = 'email.delivered')   as delivered,
  count(*) filter (where event_type = 'email.bounced')     as bounced,
  count(*) filter (where event_type = 'email.complained')  as complained,
  count(*) filter (where event_type = 'email.failed')      as failed,
  count(*) filter (where event_type = 'email.rejected')    as rejected,
  count(*) filter (where event_type = 'email.suppressed')  as suppressed,
  count(*) filter (where event_type = 'email.loaded')      as opens,
  count(*) filter (where event_type = 'email.clicked')     as clicks,
  round(
    100.0 * count(*) filter (where event_type = 'email.bounced')
    / nullif(count(*) filter (where event_type in ('email.delivered', 'email.bounced')), 0)
  , 2) as bounce_rate_pct,
  round(
    100.0 * count(*) filter (where event_type = 'email.complained')
    / nullif(count(*) filter (where event_type = 'email.delivered'), 0)
  , 2) as complaint_rate_pct
from public.emailit_events
group by 1
order by 1 desc;

comment on view public.emailit_deliverability_daily is
  'Daily EmailIt deliverability rollup: delivered / bounced / complained counts + bounce & complaint rates.';
