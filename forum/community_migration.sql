-- PROJECT Z community extension. Run AFTER admin_migration.sql.
-- Verify current profiles schema, backups and existing RLS policies before running.
begin;
alter table public.profiles add column if not exists bio text not null default '';
alter table public.profiles add column if not exists banner_url text;
alter table public.profiles add column if not exists xp integer not null default 0;
alter table public.profiles add column if not exists updated_at timestamptz default now();
alter table public.forum_topics add column if not exists edited_at timestamptz;
alter table public.forum_replies add column if not exists edited_at timestamptz;

create table if not exists public.forum_reactions(
 user_id uuid not null references auth.users(id) on delete cascade,
 topic_id text not null,
 emoji text not null check(emoji in ('👍','❤️','🔥','💀')),
 created_at timestamptz not null default now(),
 primary key(user_id,topic_id)
);
create table if not exists public.forum_favorites(
 user_id uuid not null references auth.users(id) on delete cascade,
 topic_id text not null,
 created_at timestamptz not null default now(),
 primary key(user_id,topic_id)
);
create table if not exists public.forum_notifications(
 id bigint generated always as identity primary key,
 user_id uuid not null references auth.users(id) on delete cascade,
 actor_id uuid references auth.users(id) on delete set null,
 body text not null,
 topic_id text,
 read_at timestamptz,
 created_at timestamptz not null default now()
);
create table if not exists public.forum_messages(
 id bigint generated always as identity primary key,
 sender_id uuid not null references auth.users(id) on delete cascade,
 recipient_id uuid not null references auth.users(id) on delete cascade,
 body text not null check(char_length(body) between 1 and 3000),
 created_at timestamptz not null default now(),
 check(sender_id <> recipient_id)
);
create table if not exists public.forum_requests(
 id bigint generated always as identity primary key,
 author_id uuid not null references auth.users(id) on delete cascade,
 kind text not null check(kind in ('vip','unban')),
 steam_id text not null,
 body text not null check(char_length(body) between 10 and 3000),
 status text not null default 'open' check(status in ('open','approved','rejected')),
 created_at timestamptz not null default now()
);
create table if not exists public.forum_map_votes(
 user_id uuid not null references auth.users(id) on delete cascade,
 map_name text not null check(char_length(map_name) between 3 and 80),
 created_at timestamptz not null default now(),
 primary key(user_id,map_name)
);
create table if not exists public.forum_xp_events(
 id bigint generated always as identity primary key,
 user_id uuid not null references auth.users(id) on delete cascade,
 event_type text not null,
 source_id text not null,
 points integer not null check(points between 1 and 100),
 created_at timestamptz not null default now(),
 unique(user_id,event_type,source_id)
);
create table if not exists public.forum_achievements(
 user_id uuid not null references auth.users(id) on delete cascade,
 code text not null check(code in ('first_topic','first_reply','ten_posts','hundred_xp')),
 earned_at timestamptz not null default now(),
 primary key(user_id,code)
);
-- RLS, no direct insert/update/delete grants on private tables.
alter table public.forum_reactions enable row level security;
alter table public.forum_favorites enable row level security;
alter table public.forum_notifications enable row level security;
alter table public.forum_messages enable row level security;
alter table public.forum_requests enable row level security;
alter table public.forum_map_votes enable row level security;
alter table public.forum_xp_events enable row level security;
alter table public.forum_achievements enable row level security;
drop policy if exists pz_reactions_read on public.forum_reactions;
create policy pz_reactions_read on public.forum_reactions for select to authenticated using (true);
drop policy if exists pz_favorites_read on public.forum_favorites;
create policy pz_favorites_read on public.forum_favorites for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists pz_notifications_read on public.forum_notifications;
create policy pz_notifications_read on public.forum_notifications for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists pz_messages_read on public.forum_messages;
create policy pz_messages_read on public.forum_messages for select to authenticated using (sender_id=(select auth.uid()) or recipient_id=(select auth.uid()));
drop policy if exists pz_requests_read on public.forum_requests;
create policy pz_requests_read on public.forum_requests for select to authenticated using (author_id=(select auth.uid()) or (select public.forum_is_admin()));
drop policy if exists pz_map_votes_read on public.forum_map_votes;
create policy pz_map_votes_read on public.forum_map_votes for select to authenticated using (true);
drop policy if exists pz_xp_read on public.forum_xp_events;
create policy pz_xp_read on public.forum_xp_events for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists pz_achievements_read on public.forum_achievements;
create policy pz_achievements_read on public.forum_achievements for select to authenticated using (true);
revoke all on public.forum_reactions,public.forum_favorites,public.forum_notifications,public.forum_messages,public.forum_requests,public.forum_map_votes,public.forum_xp_events,public.forum_achievements from anon,authenticated;
grant select on public.forum_reactions,public.forum_favorites,public.forum_notifications,public.forum_messages,public.forum_requests,public.forum_map_votes,public.forum_xp_events,public.forum_achievements to authenticated;

-- Guard profile XP and URLs from arbitrary browser-side updates.
create or replace function public.forum_community_profile_guard()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if new.xp is distinct from old.xp and current_setting('app.pz_xp_change',true) is distinct from 'allowed'
 then raise exception 'XP is server managed'; end if;
 if new.banner_url is distinct from old.banner_url or new.avatar_url is distinct from old.avatar_url then
   if new.banner_url is not null and (length(new.banner_url)>500 or new.banner_url !~ '^https://[^[:space:]]+ then raise exception 'Invalid banner URL'; end if;
   if new.avatar_url is not null and (length(new.avatar_url)>500 or new.avatar_url !~ '^https://[^[:space:]]+ then raise exception 'Invalid avatar URL'; end if;
 end if;
 if length(new.bio)>500 then raise exception 'Bio too long'; end if;
 return new;
end;$$;
drop trigger if exists forum_community_profile_guard_trigger on public.profiles;
create trigger forum_community_profile_guard_trigger before update on public.profiles
for each row execute function public.forum_community_profile_guard();

-- XP credited on genuine topic/reply creation; no client-controlled points.
create or replace function public.forum_award_xp()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_points integer; v_event text; v_total integer;
begin
 v_points:=case when tg_table_name='forum_topics' then 10 else 3 end;
 v_event:=case when tg_table_name='forum_topics' then 'topic' else 'reply' end;
 insert into public.forum_xp_events(user_id,event_type,source_id,points)
 values(new.author_id,v_event,new.id::text,v_points) on conflict do nothing;
 if found then
   perform set_config('app.pz_xp_change','allowed',true);
   update public.profiles set xp=xp+v_points where id=new.author_id;
   select xp into v_total from public.profiles where id=new.author_id;
   if v_total>=100 then insert into public.forum_achievements(user_id,code) values(new.author_id,'hundred_xp') on conflict do nothing; end if;
   if v_event='topic' then insert into public.forum_achievements(user_id,code) values(new.author_id,'first_topic') on conflict do nothing;
   else insert into public.forum_achievements(user_id,code) values(new.author_id,'first_reply') on conflict do nothing; end if;
 end if;
 return new;
end;$$;
drop trigger if exists forum_xp_topic_trigger on public.forum_topics;
create trigger forum_xp_topic_trigger after insert on public.forum_topics for each row execute function public.forum_award_xp();
drop trigger if exists forum_xp_reply_trigger on public.forum_replies;
create trigger forum_xp_reply_trigger after insert on public.forum_replies for each row execute function public.forum_award_xp();

-- Explicit allowlist. All mutations authenticated and server-validated.
create or replace function public.forum_community_action(p_action text,p_data jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid:=auth.uid();v_id text:=p_data->>'id';v_target uuid;v_body text;v_topic public.forum_topics%rowtype;v_emoji text;
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 if exists(select 1 from public.forum_bans where user_id=v_uid and (expires_at is null or expires_at>now())) then raise exception 'Forum account banned'; end if;
 if p_action='reaction' then
   v_emoji:=p_data->>'emoji';
   if v_emoji not in ('👍','❤️','🔥','💀') then raise exception 'Invalid reaction'; end if;
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_reactions(user_id,topic_id,emoji) values(v_uid,v_id,v_emoji)
   on conflict(user_id,topic_id) do update set emoji=excluded.emoji;
 elsif p_action='unreact' then
   delete from public.forum_reactions where user_id=v_uid and topic_id=v_id;
 elsif p_action='favorite' then
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_favorites(user_id,topic_id) values(v_uid,v_id) on conflict do nothing;
 elsif p_action='unfavorite' then
   delete from public.forum_favorites where user_id=v_uid and topic_id=v_id;
 elsif p_action='message' then
   v_target:=(p_data->>'recipient_id')::uuid;v_body:=trim(p_data->>'body');
   if v_target=v_uid or length(v_body) not between 1 and 3000 then raise exception 'Invalid message'; end if;
   if not exists(select 1 from public.profiles where id=v_target) then raise exception 'Recipient not found'; end if;
   insert into public.forum_messages(sender_id,recipient_id,body) values(v_uid,v_target,v_body);
   insert into public.forum_notifications(user_id,actor_id,body) values(v_target,v_uid,'Новое личное сообщение');
 elsif p_action='notification_read' then
   update public.forum_notifications set read_at=now() where user_id=v_uid and id::text=v_id;
 elsif p_action='edit_topic' then
   select * into v_topic from public.forum_topics where id::text=v_id for update;
   if not found or (v_topic.author_id<>v_uid and not public.forum_is_admin()) then raise exception 'No permission'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   -- Preserve existing attachment metadata when editing text.
   if position('[[ATTACHMENT]]' in v_topic.body)>0 then
     v_body:=v_body||E'\\n\\n'||substring(v_topic.body from position('[[ATTACHMENT]]' in v_topic.body));
   end if;
   update public.forum_topics set body=v_body,edited_at=now() where id=v_topic.id;
 elsif p_action='edit_reply' then
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   update public.forum_replies set body=v_body,edited_at=now()
   where id::text=v_id and (author_id=v_uid or public.forum_is_admin());
   if not found then raise exception 'No permission'; end if;
 elsif p_action='request' then
   if p_data->>'kind' not in ('vip','unban') then raise exception 'Invalid request type'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 10 and 3000 or length(trim(p_data->>'steam_id')) not between 5 and 80 then raise exception 'Invalid request'; end if;
   insert into public.forum_requests(author_id,kind,steam_id,body) values(v_uid,p_data->>'kind',trim(p_data->>'steam_id'),v_body);
 elsif p_action='map_vote' then
   v_body:=trim(p_data->>'map_name');
   if length(v_body) not between 3 and 80 or v_body !~ '^[a-zA-Z0-9_]+$' then raise exception 'Invalid map name'; end if;
   insert into public.forum_map_votes(user_id,map_name) values(v_uid,lower(v_body)) on conflict do nothing;
 elsif p_action='map_unvote' then
   delete from public.forum_map_votes where user_id=v_uid and map_name=p_data->>'map_name';
 elsif p_action='request_status' then
   if not public.forum_is_admin() then raise exception 'Admin only'; end if;
   if p_data->>'status' not in ('open','approved','rejected') then raise exception 'Invalid status'; end if;
   update public.forum_requests set status=p_data->>'status' where id::text=v_id;
   insert into public.forum_admin_log(actor_id,action,target,details)
   values(v_uid,'request_status',v_id,p_data);
 elsif p_action='profile' then
   v_body:=trim(coalesce(p_data->>'bio',''));
   if length(v_body)>500 then raise exception 'Bio too long'; end if;
   update public.profiles set bio=v_body,avatar_url=nullif(p_data->>'avatar_url',''),
   banner_url=nullif(p_data->>'banner_url',''),updated_at=now() where id=v_uid;
 else raise exception 'Unknown action'; end if;
end;$$;
revoke all on function public.forum_community_action(text,jsonb) from public;
grant execute on function public.forum_community_action(text,jsonb) to authenticated;

-- Mention/reply notifications are created by trusted database triggers.
create or replace function public.forum_notify_reply()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_owner uuid;
begin
 select author_id into v_owner from public.forum_topics where id=new.topic_id;
 if v_owner is not null and v_owner<>new.author_id then
  insert into public.forum_notifications(user_id,actor_id,body,topic_id)
  values(v_owner,new.author_id,'Ответ в вашей теме',new.topic_id::text);
 end if;
 return new;
end;$$;
drop trigger if exists forum_notify_reply_trigger on public.forum_replies;
create trigger forum_notify_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_reply();

-- Mention format: @nickname. Only existing nickname, up to 5 distinct per new post.
create or replace function public.forum_notify_mentions()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_name text;v_target uuid;v_count integer:=0;
begin
 for v_name in select distinct (regexp_matches(new.body,'@([A-Za-z0-9_]{3,40})','g'))[1] limit 5 loop
   select id into v_target from public.profiles where nickname=v_name limit 1;
   if v_target is not null and v_target<>new.author_id then
     insert into public.forum_notifications(user_id,actor_id,body,topic_id)
     values(v_target,new.author_id,'Вас упомянули: @'||v_name,
       case when tg_table_name='forum_topics' then new.id::text else new.topic_id::text end);
   end if;
 end loop;
 return new;
end;$$;
drop trigger if exists forum_mention_topic_trigger on public.forum_topics;
create trigger forum_mention_topic_trigger after insert on public.forum_topics for each row execute function public.forum_notify_mentions();
drop trigger if exists forum_mention_reply_trigger on public.forum_replies;
create trigger forum_mention_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_mentions();
commit;
) then raise exception 'Invalid banner URL'; end if;
   if new.avatar_url is not null and new.avatar_url !~ '^https://[^[:space:]]{1,500}$' then raise exception 'Invalid avatar URL'; end if;
 end if;
 if length(new.bio)>500 then raise exception 'Bio too long'; end if;
 return new;
end;$$;
drop trigger if exists forum_community_profile_guard_trigger on public.profiles;
create trigger forum_community_profile_guard_trigger before update on public.profiles
for each row execute function public.forum_community_profile_guard();

-- XP credited on genuine topic/reply creation; no client-controlled points.
create or replace function public.forum_award_xp()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_points integer; v_event text; v_total integer;
begin
 v_points:=case when tg_table_name='forum_topics' then 10 else 3 end;
 v_event:=case when tg_table_name='forum_topics' then 'topic' else 'reply' end;
 insert into public.forum_xp_events(user_id,event_type,source_id,points)
 values(new.author_id,v_event,new.id::text,v_points) on conflict do nothing;
 if found then
   perform set_config('app.pz_xp_change','allowed',true);
   update public.profiles set xp=xp+v_points where id=new.author_id;
   select xp into v_total from public.profiles where id=new.author_id;
   if v_total>=100 then insert into public.forum_achievements(user_id,code) values(new.author_id,'hundred_xp') on conflict do nothing; end if;
   if v_event='topic' then insert into public.forum_achievements(user_id,code) values(new.author_id,'first_topic') on conflict do nothing;
   else insert into public.forum_achievements(user_id,code) values(new.author_id,'first_reply') on conflict do nothing; end if;
 end if;
 return new;
end;$$;
drop trigger if exists forum_xp_topic_trigger on public.forum_topics;
create trigger forum_xp_topic_trigger after insert on public.forum_topics for each row execute function public.forum_award_xp();
drop trigger if exists forum_xp_reply_trigger on public.forum_replies;
create trigger forum_xp_reply_trigger after insert on public.forum_replies for each row execute function public.forum_award_xp();

-- Explicit allowlist. All mutations authenticated and server-validated.
create or replace function public.forum_community_action(p_action text,p_data jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid:=auth.uid();v_id text:=p_data->>'id';v_target uuid;v_body text;v_topic public.forum_topics%rowtype;v_emoji text;
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 if exists(select 1 from public.forum_bans where user_id=v_uid and (expires_at is null or expires_at>now())) then raise exception 'Forum account banned'; end if;
 if p_action='reaction' then
   v_emoji:=p_data->>'emoji';
   if v_emoji not in ('👍','❤️','🔥','💀') then raise exception 'Invalid reaction'; end if;
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_reactions(user_id,topic_id,emoji) values(v_uid,v_id,v_emoji)
   on conflict(user_id,topic_id) do update set emoji=excluded.emoji;
 elsif p_action='unreact' then
   delete from public.forum_reactions where user_id=v_uid and topic_id=v_id;
 elsif p_action='favorite' then
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_favorites(user_id,topic_id) values(v_uid,v_id) on conflict do nothing;
 elsif p_action='unfavorite' then
   delete from public.forum_favorites where user_id=v_uid and topic_id=v_id;
 elsif p_action='message' then
   v_target:=(p_data->>'recipient_id')::uuid;v_body:=trim(p_data->>'body');
   if v_target=v_uid or length(v_body) not between 1 and 3000 then raise exception 'Invalid message'; end if;
   if not exists(select 1 from public.profiles where id=v_target) then raise exception 'Recipient not found'; end if;
   insert into public.forum_messages(sender_id,recipient_id,body) values(v_uid,v_target,v_body);
   insert into public.forum_notifications(user_id,actor_id,body) values(v_target,v_uid,'Новое личное сообщение');
 elsif p_action='notification_read' then
   update public.forum_notifications set read_at=now() where user_id=v_uid and id::text=v_id;
 elsif p_action='edit_topic' then
   select * into v_topic from public.forum_topics where id::text=v_id for update;
   if not found or (v_topic.author_id<>v_uid and not public.forum_is_admin()) then raise exception 'No permission'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   -- Preserve existing attachment metadata when editing text.
   if position('[[ATTACHMENT]]' in v_topic.body)>0 then
     v_body:=v_body||E'\\n\\n'||substring(v_topic.body from position('[[ATTACHMENT]]' in v_topic.body));
   end if;
   update public.forum_topics set body=v_body,edited_at=now() where id=v_topic.id;
 elsif p_action='edit_reply' then
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   update public.forum_replies set body=v_body,edited_at=now()
   where id::text=v_id and (author_id=v_uid or public.forum_is_admin());
   if not found then raise exception 'No permission'; end if;
 elsif p_action='request' then
   if p_data->>'kind' not in ('vip','unban') then raise exception 'Invalid request type'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 10 and 3000 or length(trim(p_data->>'steam_id')) not between 5 and 80 then raise exception 'Invalid request'; end if;
   insert into public.forum_requests(author_id,kind,steam_id,body) values(v_uid,p_data->>'kind',trim(p_data->>'steam_id'),v_body);
 elsif p_action='map_vote' then
   v_body:=trim(p_data->>'map_name');
   if length(v_body) not between 3 and 80 or v_body !~ '^[a-zA-Z0-9_]+$' then raise exception 'Invalid map name'; end if;
   insert into public.forum_map_votes(user_id,map_name) values(v_uid,lower(v_body)) on conflict do nothing;
 elsif p_action='map_unvote' then
   delete from public.forum_map_votes where user_id=v_uid and map_name=p_data->>'map_name';
 elsif p_action='request_status' then
   if not public.forum_is_admin() then raise exception 'Admin only'; end if;
   if p_data->>'status' not in ('open','approved','rejected') then raise exception 'Invalid status'; end if;
   update public.forum_requests set status=p_data->>'status' where id::text=v_id;
   insert into public.forum_admin_log(actor_id,action,target,details)
   values(v_uid,'request_status',v_id,p_data);
 elsif p_action='profile' then
   v_body:=trim(coalesce(p_data->>'bio',''));
   if length(v_body)>500 then raise exception 'Bio too long'; end if;
   update public.profiles set bio=v_body,avatar_url=nullif(p_data->>'avatar_url',''),
   banner_url=nullif(p_data->>'banner_url',''),updated_at=now() where id=v_uid;
 else raise exception 'Unknown action'; end if;
end;$$;
revoke all on function public.forum_community_action(text,jsonb) from public;
grant execute on function public.forum_community_action(text,jsonb) to authenticated;

-- Mention/reply notifications are created by trusted database triggers.
create or replace function public.forum_notify_reply()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_owner uuid;
begin
 select author_id into v_owner from public.forum_topics where id=new.topic_id;
 if v_owner is not null and v_owner<>new.author_id then
  insert into public.forum_notifications(user_id,actor_id,body,topic_id)
  values(v_owner,new.author_id,'Ответ в вашей теме',new.topic_id::text);
 end if;
 return new;
end;$$;
drop trigger if exists forum_notify_reply_trigger on public.forum_replies;
create trigger forum_notify_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_reply();

-- Mention format: @nickname. Only existing nickname, up to 5 distinct per new post.
create or replace function public.forum_notify_mentions()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_name text;v_target uuid;v_count integer:=0;
begin
 for v_name in select distinct (regexp_matches(new.body,'@([A-Za-z0-9_]{3,40})','g'))[1] limit 5 loop
   select id into v_target from public.profiles where nickname=v_name limit 1;
   if v_target is not null and v_target<>new.author_id then
     insert into public.forum_notifications(user_id,actor_id,body,topic_id)
     values(v_target,new.author_id,'Вас упомянули: @'||v_name,
       case when tg_table_name='forum_topics' then new.id::text else new.topic_id::text end);
   end if;
 end loop;
 return new;
end;$$;
drop trigger if exists forum_mention_topic_trigger on public.forum_topics;
create trigger forum_mention_topic_trigger after insert on public.forum_topics for each row execute function public.forum_notify_mentions();
drop trigger if exists forum_mention_reply_trigger on public.forum_replies;
create trigger forum_mention_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_mentions();
commit;
) then raise exception 'Invalid avatar URL'; end if;
 end if;
 if length(new.bio)>500 then raise exception 'Bio too long'; end if;
 return new;
end;$$;
drop trigger if exists forum_community_profile_guard_trigger on public.profiles;
create trigger forum_community_profile_guard_trigger before update on public.profiles
for each row execute function public.forum_community_profile_guard();

-- XP credited on genuine topic/reply creation; no client-controlled points.
create or replace function public.forum_award_xp()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_points integer; v_event text; v_total integer;
begin
 v_points:=case when tg_table_name='forum_topics' then 10 else 3 end;
 v_event:=case when tg_table_name='forum_topics' then 'topic' else 'reply' end;
 insert into public.forum_xp_events(user_id,event_type,source_id,points)
 values(new.author_id,v_event,new.id::text,v_points) on conflict do nothing;
 if found then
   perform set_config('app.pz_xp_change','allowed',true);
   update public.profiles set xp=xp+v_points where id=new.author_id;
   select xp into v_total from public.profiles where id=new.author_id;
   if v_total>=100 then insert into public.forum_achievements(user_id,code) values(new.author_id,'hundred_xp') on conflict do nothing; end if;
   if v_event='topic' then insert into public.forum_achievements(user_id,code) values(new.author_id,'first_topic') on conflict do nothing;
   else insert into public.forum_achievements(user_id,code) values(new.author_id,'first_reply') on conflict do nothing; end if;
 end if;
 return new;
end;$$;
drop trigger if exists forum_xp_topic_trigger on public.forum_topics;
create trigger forum_xp_topic_trigger after insert on public.forum_topics for each row execute function public.forum_award_xp();
drop trigger if exists forum_xp_reply_trigger on public.forum_replies;
create trigger forum_xp_reply_trigger after insert on public.forum_replies for each row execute function public.forum_award_xp();

-- Explicit allowlist. All mutations authenticated and server-validated.
create or replace function public.forum_community_action(p_action text,p_data jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid:=auth.uid();v_id text:=p_data->>'id';v_target uuid;v_body text;v_topic public.forum_topics%rowtype;v_emoji text;
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 if exists(select 1 from public.forum_bans where user_id=v_uid and (expires_at is null or expires_at>now())) then raise exception 'Forum account banned'; end if;
 if p_action='reaction' then
   v_emoji:=p_data->>'emoji';
   if v_emoji not in ('👍','❤️','🔥','💀') then raise exception 'Invalid reaction'; end if;
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_reactions(user_id,topic_id,emoji) values(v_uid,v_id,v_emoji)
   on conflict(user_id,topic_id) do update set emoji=excluded.emoji;
 elsif p_action='unreact' then
   delete from public.forum_reactions where user_id=v_uid and topic_id=v_id;
 elsif p_action='favorite' then
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_favorites(user_id,topic_id) values(v_uid,v_id) on conflict do nothing;
 elsif p_action='unfavorite' then
   delete from public.forum_favorites where user_id=v_uid and topic_id=v_id;
 elsif p_action='message' then
   v_target:=(p_data->>'recipient_id')::uuid;v_body:=trim(p_data->>'body');
   if v_target=v_uid or length(v_body) not between 1 and 3000 then raise exception 'Invalid message'; end if;
   if not exists(select 1 from public.profiles where id=v_target) then raise exception 'Recipient not found'; end if;
   insert into public.forum_messages(sender_id,recipient_id,body) values(v_uid,v_target,v_body);
   insert into public.forum_notifications(user_id,actor_id,body) values(v_target,v_uid,'Новое личное сообщение');
 elsif p_action='notification_read' then
   update public.forum_notifications set read_at=now() where user_id=v_uid and id::text=v_id;
 elsif p_action='edit_topic' then
   select * into v_topic from public.forum_topics where id::text=v_id for update;
   if not found or (v_topic.author_id<>v_uid and not public.forum_is_admin()) then raise exception 'No permission'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   -- Preserve existing attachment metadata when editing text.
   if position('[[ATTACHMENT]]' in v_topic.body)>0 then
     v_body:=v_body||E'\\n\\n'||substring(v_topic.body from position('[[ATTACHMENT]]' in v_topic.body));
   end if;
   update public.forum_topics set body=v_body,edited_at=now() where id=v_topic.id;
 elsif p_action='edit_reply' then
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   update public.forum_replies set body=v_body,edited_at=now()
   where id::text=v_id and (author_id=v_uid or public.forum_is_admin());
   if not found then raise exception 'No permission'; end if;
 elsif p_action='request' then
   if p_data->>'kind' not in ('vip','unban') then raise exception 'Invalid request type'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 10 and 3000 or length(trim(p_data->>'steam_id')) not between 5 and 80 then raise exception 'Invalid request'; end if;
   insert into public.forum_requests(author_id,kind,steam_id,body) values(v_uid,p_data->>'kind',trim(p_data->>'steam_id'),v_body);
 elsif p_action='map_vote' then
   v_body:=trim(p_data->>'map_name');
   if length(v_body) not between 3 and 80 or v_body !~ '^[a-zA-Z0-9_]+$' then raise exception 'Invalid map name'; end if;
   insert into public.forum_map_votes(user_id,map_name) values(v_uid,lower(v_body)) on conflict do nothing;
 elsif p_action='map_unvote' then
   delete from public.forum_map_votes where user_id=v_uid and map_name=p_data->>'map_name';
 elsif p_action='request_status' then
   if not public.forum_is_admin() then raise exception 'Admin only'; end if;
   if p_data->>'status' not in ('open','approved','rejected') then raise exception 'Invalid status'; end if;
   update public.forum_requests set status=p_data->>'status' where id::text=v_id;
   insert into public.forum_admin_log(actor_id,action,target,details)
   values(v_uid,'request_status',v_id,p_data);
 elsif p_action='profile' then
   v_body:=trim(coalesce(p_data->>'bio',''));
   if length(v_body)>500 then raise exception 'Bio too long'; end if;
   update public.profiles set bio=v_body,avatar_url=nullif(p_data->>'avatar_url',''),
   banner_url=nullif(p_data->>'banner_url',''),updated_at=now() where id=v_uid;
 else raise exception 'Unknown action'; end if;
end;$$;
revoke all on function public.forum_community_action(text,jsonb) from public;
grant execute on function public.forum_community_action(text,jsonb) to authenticated;

-- Mention/reply notifications are created by trusted database triggers.
create or replace function public.forum_notify_reply()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_owner uuid;
begin
 select author_id into v_owner from public.forum_topics where id=new.topic_id;
 if v_owner is not null and v_owner<>new.author_id then
  insert into public.forum_notifications(user_id,actor_id,body,topic_id)
  values(v_owner,new.author_id,'Ответ в вашей теме',new.topic_id::text);
 end if;
 return new;
end;$$;
drop trigger if exists forum_notify_reply_trigger on public.forum_replies;
create trigger forum_notify_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_reply();

-- Mention format: @nickname. Only existing nickname, up to 5 distinct per new post.
create or replace function public.forum_notify_mentions()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_name text;v_target uuid;v_count integer:=0;
begin
 for v_name in select distinct (regexp_matches(new.body,'@([A-Za-z0-9_]{3,40})','g'))[1] limit 5 loop
   select id into v_target from public.profiles where nickname=v_name limit 1;
   if v_target is not null and v_target<>new.author_id then
     insert into public.forum_notifications(user_id,actor_id,body,topic_id)
     values(v_target,new.author_id,'Вас упомянули: @'||v_name,
       case when tg_table_name='forum_topics' then new.id::text else new.topic_id::text end);
   end if;
 end loop;
 return new;
end;$$;
drop trigger if exists forum_mention_topic_trigger on public.forum_topics;
create trigger forum_mention_topic_trigger after insert on public.forum_topics for each row execute function public.forum_notify_mentions();
drop trigger if exists forum_mention_reply_trigger on public.forum_replies;
create trigger forum_mention_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_mentions();
commit;
) then raise exception 'Invalid banner URL'; end if;
   if new.avatar_url is not null and new.avatar_url !~ '^https://[^[:space:]]{1,500}$' then raise exception 'Invalid avatar URL'; end if;
 end if;
 if length(new.bio)>500 then raise exception 'Bio too long'; end if;
 return new;
end;$$;
drop trigger if exists forum_community_profile_guard_trigger on public.profiles;
create trigger forum_community_profile_guard_trigger before update on public.profiles
for each row execute function public.forum_community_profile_guard();

-- XP credited on genuine topic/reply creation; no client-controlled points.
create or replace function public.forum_award_xp()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_points integer; v_event text; v_total integer;
begin
 v_points:=case when tg_table_name='forum_topics' then 10 else 3 end;
 v_event:=case when tg_table_name='forum_topics' then 'topic' else 'reply' end;
 insert into public.forum_xp_events(user_id,event_type,source_id,points)
 values(new.author_id,v_event,new.id::text,v_points) on conflict do nothing;
 if found then
   perform set_config('app.pz_xp_change','allowed',true);
   update public.profiles set xp=xp+v_points where id=new.author_id;
   select xp into v_total from public.profiles where id=new.author_id;
   if v_total>=100 then insert into public.forum_achievements(user_id,code) values(new.author_id,'hundred_xp') on conflict do nothing; end if;
   if v_event='topic' then insert into public.forum_achievements(user_id,code) values(new.author_id,'first_topic') on conflict do nothing;
   else insert into public.forum_achievements(user_id,code) values(new.author_id,'first_reply') on conflict do nothing; end if;
 end if;
 return new;
end;$$;
drop trigger if exists forum_xp_topic_trigger on public.forum_topics;
create trigger forum_xp_topic_trigger after insert on public.forum_topics for each row execute function public.forum_award_xp();
drop trigger if exists forum_xp_reply_trigger on public.forum_replies;
create trigger forum_xp_reply_trigger after insert on public.forum_replies for each row execute function public.forum_award_xp();

-- Explicit allowlist. All mutations authenticated and server-validated.
create or replace function public.forum_community_action(p_action text,p_data jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid:=auth.uid();v_id text:=p_data->>'id';v_target uuid;v_body text;v_topic public.forum_topics%rowtype;v_emoji text;
begin
 if v_uid is null then raise exception 'Sign in required'; end if;
 if exists(select 1 from public.forum_bans where user_id=v_uid and (expires_at is null or expires_at>now())) then raise exception 'Forum account banned'; end if;
 if p_action='reaction' then
   v_emoji:=p_data->>'emoji';
   if v_emoji not in ('👍','❤️','🔥','💀') then raise exception 'Invalid reaction'; end if;
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_reactions(user_id,topic_id,emoji) values(v_uid,v_id,v_emoji)
   on conflict(user_id,topic_id) do update set emoji=excluded.emoji;
 elsif p_action='unreact' then
   delete from public.forum_reactions where user_id=v_uid and topic_id=v_id;
 elsif p_action='favorite' then
   if not exists(select 1 from public.forum_topics where id::text=v_id) then raise exception 'Topic not found'; end if;
   insert into public.forum_favorites(user_id,topic_id) values(v_uid,v_id) on conflict do nothing;
 elsif p_action='unfavorite' then
   delete from public.forum_favorites where user_id=v_uid and topic_id=v_id;
 elsif p_action='message' then
   v_target:=(p_data->>'recipient_id')::uuid;v_body:=trim(p_data->>'body');
   if v_target=v_uid or length(v_body) not between 1 and 3000 then raise exception 'Invalid message'; end if;
   if not exists(select 1 from public.profiles where id=v_target) then raise exception 'Recipient not found'; end if;
   insert into public.forum_messages(sender_id,recipient_id,body) values(v_uid,v_target,v_body);
   insert into public.forum_notifications(user_id,actor_id,body) values(v_target,v_uid,'Новое личное сообщение');
 elsif p_action='notification_read' then
   update public.forum_notifications set read_at=now() where user_id=v_uid and id::text=v_id;
 elsif p_action='edit_topic' then
   select * into v_topic from public.forum_topics where id::text=v_id for update;
   if not found or (v_topic.author_id<>v_uid and not public.forum_is_admin()) then raise exception 'No permission'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   -- Preserve existing attachment metadata when editing text.
   if position('[[ATTACHMENT]]' in v_topic.body)>0 then
     v_body:=v_body||E'\\n\\n'||substring(v_topic.body from position('[[ATTACHMENT]]' in v_topic.body));
   end if;
   update public.forum_topics set body=v_body,edited_at=now() where id=v_topic.id;
 elsif p_action='edit_reply' then
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 1 and 15000 then raise exception 'Invalid text'; end if;
   update public.forum_replies set body=v_body,edited_at=now()
   where id::text=v_id and (author_id=v_uid or public.forum_is_admin());
   if not found then raise exception 'No permission'; end if;
 elsif p_action='request' then
   if p_data->>'kind' not in ('vip','unban') then raise exception 'Invalid request type'; end if;
   v_body:=trim(p_data->>'body');
   if length(v_body) not between 10 and 3000 or length(trim(p_data->>'steam_id')) not between 5 and 80 then raise exception 'Invalid request'; end if;
   insert into public.forum_requests(author_id,kind,steam_id,body) values(v_uid,p_data->>'kind',trim(p_data->>'steam_id'),v_body);
 elsif p_action='map_vote' then
   v_body:=trim(p_data->>'map_name');
   if length(v_body) not between 3 and 80 or v_body !~ '^[a-zA-Z0-9_]+$' then raise exception 'Invalid map name'; end if;
   insert into public.forum_map_votes(user_id,map_name) values(v_uid,lower(v_body)) on conflict do nothing;
 elsif p_action='map_unvote' then
   delete from public.forum_map_votes where user_id=v_uid and map_name=p_data->>'map_name';
 elsif p_action='request_status' then
   if not public.forum_is_admin() then raise exception 'Admin only'; end if;
   if p_data->>'status' not in ('open','approved','rejected') then raise exception 'Invalid status'; end if;
   update public.forum_requests set status=p_data->>'status' where id::text=v_id;
   insert into public.forum_admin_log(actor_id,action,target,details)
   values(v_uid,'request_status',v_id,p_data);
 elsif p_action='profile' then
   v_body:=trim(coalesce(p_data->>'bio',''));
   if length(v_body)>500 then raise exception 'Bio too long'; end if;
   update public.profiles set bio=v_body,avatar_url=nullif(p_data->>'avatar_url',''),
   banner_url=nullif(p_data->>'banner_url',''),updated_at=now() where id=v_uid;
 else raise exception 'Unknown action'; end if;
end;$$;
revoke all on function public.forum_community_action(text,jsonb) from public;
grant execute on function public.forum_community_action(text,jsonb) to authenticated;

-- Mention/reply notifications are created by trusted database triggers.
create or replace function public.forum_notify_reply()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_owner uuid;
begin
 select author_id into v_owner from public.forum_topics where id=new.topic_id;
 if v_owner is not null and v_owner<>new.author_id then
  insert into public.forum_notifications(user_id,actor_id,body,topic_id)
  values(v_owner,new.author_id,'Ответ в вашей теме',new.topic_id::text);
 end if;
 return new;
end;$$;
drop trigger if exists forum_notify_reply_trigger on public.forum_replies;
create trigger forum_notify_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_reply();

-- Mention format: @nickname. Only existing nickname, up to 5 distinct per new post.
create or replace function public.forum_notify_mentions()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_name text;v_target uuid;v_count integer:=0;
begin
 for v_name in select distinct (regexp_matches(new.body,'@([A-Za-z0-9_]{3,40})','g'))[1] limit 5 loop
   select id into v_target from public.profiles where nickname=v_name limit 1;
   if v_target is not null and v_target<>new.author_id then
     insert into public.forum_notifications(user_id,actor_id,body,topic_id)
     values(v_target,new.author_id,'Вас упомянули: @'||v_name,
       case when tg_table_name='forum_topics' then new.id::text else new.topic_id::text end);
   end if;
 end loop;
 return new;
end;$$;
drop trigger if exists forum_mention_topic_trigger on public.forum_topics;
create trigger forum_mention_topic_trigger after insert on public.forum_topics for each row execute function public.forum_notify_mentions();
drop trigger if exists forum_mention_reply_trigger on public.forum_replies;
create trigger forum_mention_reply_trigger after insert on public.forum_replies for each row execute function public.forum_notify_mentions();
commit;
