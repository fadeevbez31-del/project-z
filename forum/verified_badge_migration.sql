-- PROJECT Z verified profile badge and applicant confirmation.
-- Run once in Supabase SQL Editor before using the updated forum UI.

begin;

alter table public.profiles
  add column if not exists verified boolean not null default false,
  add column if not exists verified_pending boolean not null default false;

-- When the owner approves a moderation/administration application,
-- show the applicant a pending verification badge and confirmation button.
create or replace function public.forum_mark_verification_pending()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status = 'approved'
     and old.status is distinct from new.status
     and new.steam_id = 'Заявка на модерацию' then
    update public.profiles
       set verified_pending = true
     where id = new.author_id
       and verified = false;
  elsif new.status = 'rejected'
     and old.status is distinct from new.status
     and new.steam_id = 'Заявка на модерацию' then
    update public.profiles
       set verified_pending = false
     where id = new.author_id
       and verified = false;
  end if;
  return new;
end;
$$;

drop trigger if exists forum_request_verification_pending_trigger on public.forum_requests;
create trigger forum_request_verification_pending_trigger
after update of status on public.forum_requests
for each row execute function public.forum_mark_verification_pending();

-- Only the signed-in applicant can confirm their own approved badge.
create or replace function public.forum_confirm_verification()
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'Sign in required';
  end if;

  update public.profiles
     set verified = true,
         verified_pending = false,
         updated_at = now()
   where id = v_uid
     and verified_pending = true
     and verified = false;

  if not found then
    raise exception 'No pending verification to confirm';
  end if;

  insert into public.forum_admin_log(actor_id, action, target, details)
  values (v_uid, 'verification_confirmed', v_uid::text, '{}'::jsonb);
end;
$$;

revoke all on function public.forum_confirm_verification() from public;
grant execute on function public.forum_confirm_verification() to authenticated;

commit;
