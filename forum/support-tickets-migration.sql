-- PROJECT Z private support inbox. Run in Supabase SQL Editor.
BEGIN;
CREATE TABLE IF NOT EXISTS public.forum_support_tickets (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 body text NOT NULL CHECK (char_length(body) BETWEEN 5 AND 3000),
 image_url text,
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS forum_support_tickets_status_idx ON public.forum_support_tickets(status,created_at DESC);
ALTER TABLE public.forum_support_tickets ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.forum_support_tickets FROM anon;
GRANT SELECT,INSERT,UPDATE ON public.forum_support_tickets TO authenticated;
GRANT USAGE,SELECT ON SEQUENCE public.forum_support_tickets_id_seq TO authenticated;
DROP POLICY IF EXISTS "support_insert_own" ON public.forum_support_tickets;
CREATE POLICY "support_insert_own" ON public.forum_support_tickets FOR INSERT TO authenticated
 WITH CHECK (user_id=(select auth.uid()) AND status='open' AND (image_url IS NULL OR (image_url LIKE 'https://%' AND length(image_url)<2048)));
DROP POLICY IF EXISTS "support_admin_read" ON public.forum_support_tickets;
CREATE POLICY "support_admin_read" ON public.forum_support_tickets FOR SELECT TO authenticated
 USING ((select public.forum_is_admin()));
DROP POLICY IF EXISTS "support_admin_update" ON public.forum_support_tickets;
CREATE POLICY "support_admin_update" ON public.forum_support_tickets FOR UPDATE TO authenticated
 USING ((select public.forum_is_admin()))
 WITH CHECK ((select public.forum_is_admin()));
-- Users cannot see each other's tickets. Only admins can read and update them.
-- Prevent even admins from rewriting the original report or its author.
CREATE OR REPLACE FUNCTION public.forum_support_immutable_fields()
RETURNS trigger LANGUAGE plpgsql SET search_path='' AS $$
BEGIN
 IF NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.body IS DISTINCT FROM OLD.body
 OR NEW.image_url IS DISTINCT FROM OLD.image_url OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
  RAISE EXCEPTION 'Only status may be changed' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END;$$;
DROP TRIGGER IF EXISTS forum_support_immutable_fields_trigger ON public.forum_support_tickets;
CREATE TRIGGER forum_support_immutable_fields_trigger BEFORE UPDATE ON public.forum_support_tickets
FOR EACH ROW EXECUTE FUNCTION public.forum_support_immutable_fields();
REVOKE ALL ON FUNCTION public.forum_support_immutable_fields() FROM PUBLIC;
CREATE OR REPLACE FUNCTION public.forum_support_reply(p_ticket_id bigint,p_body text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE recipient uuid;
BEGIN
 IF (select auth.uid()) IS NULL OR NOT (select public.forum_is_admin()) THEN
  RAISE EXCEPTION 'Admins only' USING ERRCODE='42501';
 END IF;
 IF length(btrim(p_body)) NOT BETWEEN 1 AND 2000 THEN RAISE EXCEPTION 'Invalid message length'; END IF;
 SELECT user_id INTO recipient FROM public.forum_support_tickets WHERE id=p_ticket_id;
 IF recipient IS NULL THEN RAISE EXCEPTION 'Ticket not found'; END IF;
 INSERT INTO public.forum_notifications(user_id,body)
 VALUES(recipient,'📨 Ответ администрации на вопрос/жалобу №'||p_ticket_id||': '||btrim(p_body));
 UPDATE public.forum_support_tickets SET status='closed' WHERE id=p_ticket_id;
END;$$;
REVOKE ALL ON FUNCTION public.forum_support_reply(bigint,text) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.forum_support_reply(bigint,text) TO authenticated;
COMMIT;
-- This migration assumes existing public.forum_is_admin() and forum_notifications(user_id,body).
-- Confirm those names match your existing forum migration before running.
