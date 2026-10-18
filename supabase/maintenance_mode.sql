-- PROJECT Z: global maintenance-mode setting
-- Run this script once in Supabase SQL Editor.
CREATE TABLE IF NOT EXISTS public.forum_site_settings (
  id integer PRIMARY KEY CHECK (id = 1),
  maintenance_enabled boolean NOT NULL DEFAULT false,
  maintenance_message text NOT NULL DEFAULT 'На сайте проводятся технические работы. Пожалуйста, зайдите позже.',
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.forum_site_settings (id, maintenance_enabled, maintenance_message)
VALUES (1, false, 'На сайте проводятся технические работы. Пожалуйста, зайдите позже.')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE public.forum_site_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Public can read site maintenance setting" ON public.forum_site_settings;
CREATE POLICY "Public can read site maintenance setting"
  ON public.forum_site_settings FOR SELECT
  USING (true);

DROP POLICY IF EXISTS "Project owner can update site maintenance setting" ON public.forum_site_settings;
CREATE POLICY "Project owner can update site maintenance setting"
  ON public.forum_site_settings FOR UPDATE TO authenticated
  USING (lower(coalesce(auth.jwt() ->> 'email', '')) = '007.s2@mail.ru')
  WITH CHECK (lower(coalesce(auth.jwt() ->> 'email', '')) = '007.s2@mail.ru');

GRANT SELECT ON public.forum_site_settings TO anon, authenticated;
GRANT UPDATE ON public.forum_site_settings TO authenticated;
