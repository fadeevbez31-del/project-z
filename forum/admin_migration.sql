-- PROJECT Z forum administration migration
-- Run once in Supabase SQL Editor as the project owner. Review existing RLS policies first.
begin;
alter table public.forum_topics add column if not exists pinned boolean not null default false;
alter table public.forum_topics add column if not exists locked boolean not null default false;
alter table public.forum_topics add column if not exists views bigint not null default 0;
alter table public.forum_categories add column if not exists is_hidden boolean not null default false;
create table if not exists public.forum_reports(
 id bigint generated always as identity primary key,
 reporter_id uuid not null references auth.users(id) on delete cascade,
 topic_id text not null,
 reason text not null check (char_length(reason) between 5 and 1000),
 status text not null default 'open' check (status in ('open','resolved','rejected')),
 created_at timestamptz not null default now()
);
create table if not exists public.forum_bans(
 user_id uuid primary key references auth.users(id) on delete cascade,
 reason text not null,
 expires_at timestamptz,
 created_at timestamptz not null default now()
);
create table if not exists public.forum_admin_log(
 id bigint generated always as identity primary key,
 actor_id uuid references auth.users(id) on delete set null,
 action text not null,
 target text,
 details jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);
create or replace function public.forum_is_admin()
returns boolean language sql stable security definer set search_path = ''
as $$select exists(select 1 from public.profiles where id = (select auth.uid()) and role = 'admin')$$;
revoke all on function public.forum_is_admin() from public;
grant execute on function public.forum_is_admin() to authenticated;

-- Deny direct privilege escalation, including via permissive pre-existing UPDATE policies.
create or replace function public.forum_guard_profile_role()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if new.role is distinct from old.role and current_setting('app.forum_role_change',true) is distinct from 'allowed' then
   raise exception 'Roles may only be changed through forum_admin_action';
 end if;
 return new;
end;$$;
create or replace function public.forum_guard_profile_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if auth.uid() is not null and new.role is distinct from 'player'
 then raise exception 'New profiles must start as player'; end if;
 return new;
end;$$;
drop trigger if exists forum_guard_profile_insert_trigger on public.profiles;
create trigger forum_guard_profile_insert_trigger before insert on public.profiles
for each row execute function public.forum_guard_profile_insert();
drop trigger if exists forum_guard_profile_role_trigger on public.profiles;
create trigger forum_guard_profile_role_trigger before update on public.profiles
for each row execute function public.forum_guard_profile_role();

-- Allow admins to read records even if existing user-only RLS policies are restrictive.
alter table public.profiles enable row level security;
drop policy if exists forum_admin_read_profiles on public.profiles;
create policy forum_admin_read_profiles on public.profiles for select to authenticated
using ((select public.forum_is_admin()));
alter table public.forum_topics enable row level security;
drop policy if exists forum_admin_read_topics on public.forum_topics;
create policy forum_admin_read_topics on public.forum_topics for select to authenticated
using ((select public.forum_is_admin()));
alter table public.forum_categories enable row level security;
drop policy if exists forum_admin_read_categories on public.forum_categories;
create policy forum_admin_read_categories on public.forum_categories for select to authenticated
using ((select public.forum_is_admin()));
alter table public.forum_replies enable row level security;
drop policy if exists forum_admin_read_replies on public.forum_replies;
create policy forum_admin_read_replies on public.forum_replies for select to authenticated
using ((select public.forum_is_admin()));
alter table public.forum_reports enable row level security;
alter table public.forum_bans enable row level security;
alter table public.forum_admin_log enable row level security;
drop policy if exists forum_reports_read on public.forum_reports;
create policy forum_reports_read on public.forum_reports for select to authenticated
using (reporter_id = (select auth.uid()) or (select public.forum_is_admin()));
drop policy if exists forum_reports_create on public.forum_reports;
create policy forum_reports_create on public.forum_reports for insert to authenticated
with check (reporter_id = (select auth.uid()) and status = 'open');
drop policy if exists forum_bans_admin_read on public.forum_bans;
create policy forum_bans_admin_read on public.forum_bans for select to authenticated
using ((select public.forum_is_admin()) or user_id = (select auth.uid()));
drop policy if exists forum_admin_log_read on public.forum_admin_log;
create policy forum_admin_log_read on public.forum_admin_log for select to authenticated
using ((select public.forum_is_admin()));
grant select,insert on public.forum_reports to authenticated;
grant select on public.forum_bans,public.forum_admin_log to authenticated;
grant usage,select on sequence public.forum_reports_id_seq to authenticated;
grant select on public.profiles,public.forum_topics,public.forum_categories,public.forum_replies to authenticated;

-- Protect sensitive topic/category fields even if an old RLS policy allows UPDATE.
create or replace function public.forum_guard_topic_flags()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if (new.pinned is distinct from old.pinned or new.locked is distinct from old.locked)
    and not public.forum_is_admin() then raise exception 'Only admins can manage topic flags'; end if;
 if new.views is distinct from old.views and current_setting('app.forum_view_increment',true) is distinct from 'allowed'
 then raise exception 'Use increment_topic_views'; end if;
 return new;
end;$$;
drop trigger if exists forum_guard_topic_flags_trigger on public.forum_topics;
create trigger forum_guard_topic_flags_trigger before update on public.forum_topics
for each row execute function public.forum_guard_topic_flags();
create or replace function public.forum_guard_category_visibility()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if new.is_hidden is distinct from old.is_hidden and not public.forum_is_admin()
 then raise exception 'Only admins can hide categories'; end if;
 return new;
end;$$;
drop trigger if exists forum_guard_category_visibility_trigger on public.forum_categories;
create trigger forum_guard_category_visibility_trigger before update on public.forum_categories
for each row execute function public.forum_guard_category_visibility();

-- Count once per browser session in UI; increments are not a unique-person metric.
create or replace function public.forum_increment_topic_views(topic_id text)
returns void language plpgsql security definer set search_path = ''
as $$
begin
 perform set_config('app.forum_view_increment','allowed',true);
 update public.forum_topics set views = views + 1 where id::text = topic_id;
end;$$;
revoke all on function public.forum_increment_topic_views(text) from public;
grant execute on function public.forum_increment_topic_views(text) to anon,authenticated;

-- Only admin role can execute writes. All actions are whitelisted, never dynamic SQL.
create or replace function public.forum_admin_action(p_action text,p_data jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_id text := p_data->>'id'; v_uid uuid; v_role text;
begin
 if auth.uid() is null or not public.forum_is_admin() then raise exception 'Admin access required'; end if;
 if p_action = 'topic_pin' then
   update public.forum_topics set pinned = coalesce((p_data->>'value')::boolean,false) where id::text = v_id;
 elsif p_action = 'topic_lock' then
   update public.forum_topics set locked = coalesce((p_data->>'value')::boolean,false) where id::text = v_id;
 elsif p_action = 'topic_rename' then
   if char_length(trim(p_data->>'title')) not between 1 and 140 then raise exception 'Invalid title'; end if;
   update public.forum_topics set title = trim(p_data->>'title') where id::text = v_id;
 elsif p_action = 'topic_delete' then
   delete from public.forum_topics where id::text = v_id;
 elsif p_action = 'category_rename' then
   if char_length(trim(p_data->>'name')) not between 1 and 100 then raise exception 'Invalid name'; end if;
   update public.forum_categories set name = trim(p_data->>'name') where id::text = v_id;
 elsif p_action = 'category_hide' then
   update public.forum_categories set is_hidden = coalesce((p_data->>'value')::boolean,false) where id::text = v_id;
 elsif p_action = 'category_delete' then
   if exists(select 1 from public.forum_topics where category_id::text=v_id) then raise exception 'Move/delete topics before deleting category'; end if;
   delete from public.forum_categories where id::text = v_id;
 elsif p_action = 'category_create' then
   if char_length(trim(p_data->>'name')) not between 1 and 100 then raise exception 'Invalid name'; end if;
   insert into public.forum_categories(name,description,icon,sort_order)
   values(trim(p_data->>'name'),coalesce(p_data->>'description',''),coalesce(nullif(p_data->>'icon',''),'📁'),coalesce((p_data->>'sort_order')::integer,100));
 elsif p_action = 'user_role' then
   v_uid := (p_data->>'user_id')::uuid; v_role := p_data->>'role';
   if v_role not in ('player','vip','moderator','admin') then raise exception 'Invalid role'; end if;
   if v_uid=auth.uid() then raise exception 'Cannot change your own role'; end if;
   perform set_config('app.forum_role_change','allowed',true);
   update public.profiles set role=v_role where id=v_uid;
 elsif p_action = 'user_ban' then
   v_uid := (p_data->>'user_id')::uuid;
   if v_uid=auth.uid() then raise exception 'Cannot ban yourself'; end if;
   if exists(select 1 from public.profiles where id=v_uid and role='admin') then raise exception 'Cannot ban an administrator'; end if;
   insert into public.forum_bans(user_id,reason,expires_at)
   values(v_uid,left(coalesce(nullif(p_data->>'reason',''),'Forum rule violation'),500),nullif(p_data->>'expires_at','')::timestamptz)
   on conflict(user_id) do update set reason=excluded.reason,expires_at=excluded.expires_at,created_at=now();
 elsif p_action = 'user_unban' then
   delete from public.forum_bans where user_id=(p_data->>'user_id')::uuid;
 elsif p_action = 'report_status' then
   if p_data->>'status' not in ('open','resolved','rejected') then raise exception 'Invalid status'; end if;
   update public.forum_reports set status=p_data->>'status' where id::text=v_id;
 else raise exception 'Unknown action';
 end if;
 insert into public.forum_admin_log(actor_id,action,target,details)
 values(auth.uid(),p_action,coalesce(v_id,p_data->>'user_id'),p_data);
end;$$;
revoke all on function public.forum_admin_action(text,jsonb) from public;
grant execute on function public.forum_admin_action(text,jsonb) to authenticated;

-- Secure topic/reply creation for banned users and locked topics, independent of frontend.
create or replace function public.forum_guard_posts()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_user uuid; v_topic text;
begin
 v_user := new.author_id;
 if exists(select 1 from public.forum_bans where user_id=v_user and (expires_at is null or expires_at>now())) then
   raise exception 'Forum account is banned';
 end if;
 if tg_table_name='forum_replies' then
   v_topic := new.topic_id::text;
   if exists(select 1 from public.forum_topics where id::text=v_topic and locked=true) and not public.forum_is_admin() then
     raise exception 'Topic is locked';
   end if;
 end if;
 return new;
end;$$;
drop trigger if exists forum_guard_topic_insert on public.forum_topics;
create trigger forum_guard_topic_insert before insert on public.forum_topics
for each row execute function public.forum_guard_posts();
drop trigger if exists forum_guard_reply_insert on public.forum_replies;
create trigger forum_guard_reply_insert before insert on public.forum_replies
for each row execute function public.forum_guard_posts();

-- Never expose SourceBans MySQL credentials in the frontend; use an external read-only API.
commit;
