create table if not exists public.trip_votes (
  name_key text primary key,
  display_name text not null,
  picks text[] not null check (cardinality(picks) = 3),
  updated_at timestamptz not null default now()
);

alter table public.trip_votes enable row level security;
revoke all on public.trip_votes from anon, authenticated;
grant select, insert, update on public.trip_votes to service_role;

create table if not exists public.site_login_attempts (
  ip_hash text primary key,
  window_started_at timestamptz not null,
  attempts integer not null default 0,
  locked_until timestamptz
);

alter table public.site_login_attempts enable row level security;
revoke all on public.site_login_attempts from anon, authenticated;
grant select, insert, update on public.site_login_attempts to service_role;

create or replace function public.consume_site_login_attempt(p_ip_hash text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  allowed boolean;
begin
  insert into public.site_login_attempts (ip_hash, window_started_at, attempts)
  values (p_ip_hash, now(), 1)
  on conflict (ip_hash) do update
  set
    window_started_at = case
      when site_login_attempts.window_started_at <= now() - interval '15 minutes'
        or site_login_attempts.locked_until <= now()
      then now()
      else site_login_attempts.window_started_at
    end,
    attempts = case
      when site_login_attempts.window_started_at <= now() - interval '15 minutes'
        or site_login_attempts.locked_until <= now()
      then 1
      else site_login_attempts.attempts + 1
    end,
    locked_until = case
      when site_login_attempts.window_started_at <= now() - interval '15 minutes'
        or site_login_attempts.locked_until <= now()
      then null
      when site_login_attempts.attempts >= 19
      then now() + interval '15 minutes'
      else site_login_attempts.locked_until
    end
  returning locked_until is null or locked_until <= now() into allowed;

  return allowed;
end;
$$;

revoke all on function public.consume_site_login_attempt(text) from public, anon, authenticated;
grant execute on function public.consume_site_login_attempt(text) to service_role;
