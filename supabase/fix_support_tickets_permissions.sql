-- PROJECT Z: fix "permission denied for table forum_support_tickets"
-- Run in Supabase SQL Editor as the project database owner.
-- This does not delete or alter any existing tickets.

GRANT USAGE ON SCHEMA public TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.forum_support_tickets TO authenticated;

ALTER TABLE public.forum_support_tickets ENABLE ROW LEVEL SECURITY;

-- Owner can see archived and active support requests.
DROP POLICY IF EXISTS "projectz_owner_read_support_tickets" ON public.forum_support_tickets;
CREATE POLICY "projectz_owner_read_support_tickets"
ON public.forum_support_tickets FOR SELECT TO authenticated
USING (lower(coalesce(auth.jwt() ->> 'email', '')) = '007.s2@mail.ru');

-- Only owner can permanently delete archived support requests.
DROP POLICY IF EXISTS "projectz_owner_delete_archived_support_tickets" ON public.forum_support_tickets;
CREATE POLICY "projectz_owner_delete_archived_support_tickets"
ON public.forum_support_tickets FOR DELETE TO authenticated
USING (status = 'closed' AND lower(coalesce(auth.jwt() ->> 'email', '')) = '007.s2@mail.ru');

-- Existing policies for ticket owners and other admin actions are preserved.
