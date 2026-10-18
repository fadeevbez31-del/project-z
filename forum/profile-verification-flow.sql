-- PROJECT Z: route moderation applications through the profile-confirmation queue.
-- Run once in Supabase SQL Editor. Existing accounts and forum posts are preserved.
BEGIN;

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS verified boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS verified_pending boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION public.forum_owner_review_moderation_request(
  p_request_id bigint,
  p_approve boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_owner uuid;
  v_actor uuid := (SELECT auth.uid());
  v_user uuid;
  v_nickname text;
BEGIN
  SELECT id INTO v_owner
  FROM auth.users
  WHERE lower(email) = '007.s2@mail.ru'
    AND email_confirmed_at IS NOT NULL
  LIMIT 1;

  IF v_actor IS NULL OR v_actor IS DISTINCT FROM v_owner THEN
    RAISE EXCEPTION 'Only the PROJECT Z owner can review verification applications'
      USING ERRCODE = '42501';
  END IF;

  SELECT author_id INTO v_user
  FROM public.forum_requests
  WHERE id = p_request_id
    AND kind = 'vip'
    AND lower(steam_id) = lower('Заявка на модерацию')
    AND status = 'open'
  FOR UPDATE;

  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Application not found or already reviewed';
  END IF;

  UPDATE public.forum_requests
  SET status = CASE WHEN p_approve THEN 'approved' ELSE 'rejected' END
  WHERE id = p_request_id;

  IF p_approve THEN
    UPDATE public.profiles
    SET verified_pending = true, verified = false
    WHERE id = v_user;
    INSERT INTO public.forum_notifications(user_id, actor_id, body)
    VALUES (v_user, v_actor, 'Ваша заявка одобрена. Откройте «Мой профиль» и нажмите «Подтвердить» рядом с ником, чтобы активировать галочку.');
  ELSE
    UPDATE public.profiles
    SET verified_pending = false
    WHERE id = v_user;
    INSERT INTO public.forum_notifications(user_id, actor_id, body)
    VALUES (v_user, v_actor, 'Ваша заявка на подтверждение профиля отклонена администрацией проекта.');
  END IF;

  SELECT nickname INTO v_nickname FROM public.profiles WHERE id = v_user;
  INSERT INTO public.forum_admin_log(actor_id, action, target, details)
  VALUES (v_actor, 'moderation_verification_review', v_user::text,
          jsonb_build_object('request_id', p_request_id, 'approved', p_approve, 'nickname', v_nickname));
END;
$$;

REVOKE ALL ON FUNCTION public.forum_owner_review_moderation_request(bigint, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.forum_owner_review_moderation_request(bigint, boolean) TO authenticated;

-- Only the signed-in profile owner can finish the second step after the owner approves.
CREATE OR REPLACE FUNCTION public.forum_confirm_verification()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid := (SELECT auth.uid());
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'Sign in first' USING ERRCODE = '42501';
  END IF;
  UPDATE public.profiles
  SET verified = true, verified_pending = false
  WHERE id = v_uid AND verified_pending = true;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'There is no approved verification waiting for confirmation';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.forum_confirm_verification() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.forum_confirm_verification() TO authenticated;

COMMIT;
