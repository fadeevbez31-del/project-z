-- PROJECT Z: allow users to permanently delete messages they sent or received.
-- Run this script once in Supabase SQL Editor (Production project).
CREATE OR REPLACE FUNCTION public.forum_delete_message(p_message_id text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_deleted boolean := false;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Authentication required';
  END IF;

  DELETE FROM public.forum_messages
   WHERE id::text = p_message_id
     AND (
       sender_id::text = auth.uid()::text
       OR recipient_id::text = auth.uid()::text
     )
  RETURNING true INTO v_deleted;

  RETURN COALESCE(v_deleted, false);
END;
$$;

REVOKE ALL ON FUNCTION public.forum_delete_message(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.forum_delete_message(text) TO authenticated;
