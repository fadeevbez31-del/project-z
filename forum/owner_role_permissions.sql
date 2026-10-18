-- Run once in Supabase SQL Editor as project owner.
-- Requires admin_migration.sql; preserves existing data.
begin;
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
   -- Only the verified owner may grant/revoke admin privileges.
   if v_role='admin' or exists(select 1 from public.profiles where id=v_uid and role='admin') then
     if not exists (
       select 1 from auth.users owner
       where owner.id=auth.uid()
         and lower(owner.email)='007.s2@mail.ru'
         and owner.email_confirmed_at is not null
     ) then raise exception 'Only the verified forum owner can grant or revoke admin'; end if;
     if exists (
       select 1 from auth.users owner
       where owner.id=v_uid and lower(owner.email)='007.s2@mail.ru'
     ) then raise exception 'The forum owner cannot be demoted'; end if;
   end if;
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
commit;
