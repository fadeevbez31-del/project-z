-- PROJECT Z: назначить владельца форума по зарегистрированному email.
-- Запускать ТОЛЬКО в Supabase SQL Editor под владельцем проекта.
-- Сначала выполнить forum/admin_migration.sql.
-- Email используется лишь для поиска конкретного auth.users.id.
-- Никакой проверки email в браузере и автоматической выдачи админки нет.
begin;
do $$
declare v_id uuid; v_count integer;
begin
 select count(*), min(id) into v_count,v_id
 from auth.users where lower(email)=lower('007.s2@mail.ru')
   and email_confirmed_at is not null;
 if v_count <> 1 then
   raise exception 'Нужен один зарегистрированный и подтверждённый аккаунт 007.s2@mail.ru; найдено: %',v_count;
 end if;
 if not exists(select 1 from public.profiles where id=v_id) then
   raise exception 'У пользователя нет записи в public.profiles. Войдите на форум и проверьте регистрацию.';
 end if;
 perform set_config('app.forum_role_change','allowed',true);
 update public.profiles set role='admin' where id=v_id;
 insert into public.forum_admin_log(actor_id,action,target,details)
 values(v_id,'owner_bootstrap',v_id::text,jsonb_build_object('method','manual_supabase_sql'));
end $$;
commit;

-- Проверка результата (запустить отдельно):
-- select p.id,p.nickname,p.role from public.profiles p
-- join auth.users u on u.id=p.id where lower(u.email)=lower('007.s2@mail.ru');
