-- PROJECT Z: only the verified owner may grant or revoke forum admin.
-- Execute once in Supabase SQL Editor as the project database owner.
-- This trigger protects role changes even when made outside the forum UI.
-- It does not change existing user roles or remove existing forum functions.
BEGIN;
CREATE OR REPLACE FUNCTION public.forum_protect_admin_role()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  actor uuid := (select auth.uid());
  owner_id uuid;
BEGIN
  -- SQL Editor / trusted backend maintenance without a signed-in user.
  -- Normal browser requests have auth.uid() set.
  IF actor IS NULL AND current_setting('request.jwt.claim.role', true) IS DISTINCT FROM 'authenticated' THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'UPDATE' AND NEW.role IS NOT DISTINCT FROM OLD.role THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'INSERT' AND NEW.role IS DISTINCT FROM 'admin' THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.role IS DISTINCT FROM 'admin'
     AND OLD.role IS DISTINCT FROM 'admin' THEN
    RETURN NEW;
  END IF;

  SELECT id INTO owner_id
  FROM auth.users
  WHERE lower(email) = '007.s2@mail.ru'
    AND email_confirmed_at IS NOT NULL;

  IF owner_id IS NULL OR actor IS DISTINCT FROM owner_id THEN
    RAISE EXCEPTION 'Only the PROJECT Z owner may grant or revoke the admin role'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS forum_protect_admin_role_update ON public.profiles;
CREATE TRIGGER forum_protect_admin_role_update
BEFORE UPDATE OF role ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.forum_protect_admin_role();
DROP TRIGGER IF EXISTS forum_protect_admin_role_insert ON public.profiles;
CREATE TRIGGER forum_protect_admin_role_insert
BEFORE INSERT ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.forum_protect_admin_role();
REVOKE ALL ON FUNCTION public.forum_protect_admin_role() FROM PUBLIC;
COMMIT;

-- IMPORTANT: This trigger is an additional safeguard, not a replacement
-- for existing RLS or checks inside public.forum_admin_action.
-- In forum_admin_action's user_role branch, explicitly verify the same owner
-- before setting role='admin' OR changing an existing admin to another role.
