-- PROJECT Z: secure archive/unarchive support tickets.
-- Run once in Supabase SQL Editor.
create or replace function public.forum_support_set_archived(
  p_ticket_id bigint,
  p_archived boolean
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_updated integer;
begin
  if auth.uid() is null or not exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  ) then
    raise exception 'Access denied';
  end if;

  update public.forum_support_tickets
     set status = case when p_archived then 'closed' else 'open' end
   where id = p_ticket_id
     and status is distinct from case when p_archived then 'closed' else 'open' end;

  get diagnostics v_updated = row_count;
  return v_updated = 1;
end;
$$;
revoke all on function public.forum_support_set_archived(bigint, boolean) from public, anon;
grant execute on function public.forum_support_set_archived(bigint, boolean) to authenticated;
