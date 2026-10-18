-- PROJECT Z: исправление ошибки invalid repetition count(s) при загрузке аватара.
-- Выполнить в Supabase SQL Editor под владельцем проекта.
-- Без удаления данных или изменения ролей.
begin;
create or replace function public.forum_community_profile_guard()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if new.xp is distinct from old.xp and current_setting('app.pz_xp_change',true) is distinct from 'allowed'
 then raise exception 'XP is server managed'; end if;
 if new.banner_url is distinct from old.banner_url or new.avatar_url is distinct from old.avatar_url then
   if new.banner_url is not null and (length(new.banner_url)>500 or new.banner_url !~ '^https://[^[:space:]]+$') then raise exception 'Invalid banner URL'; end if;
   if new.avatar_url is not null and (length(new.avatar_url)>500 or new.avatar_url !~ '^https://[^[:space:]]+$') then raise exception 'Invalid avatar URL'; end if;
 end if;
 if length(new.bio)>500 then raise exception 'Bio too long'; end if;
 return new;
end;$$;
commit;
