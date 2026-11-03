# Supabase setup

The site stays static on GitHub Pages. Supabase provides the server-side shared-password check and durable poll storage. The publishable key in `index.html` is intended to be public; never put the trip password or the service-role key in the site files.

## One-time setup

1. In the Supabase project `eqvmdhmlgvkyhthoeyvt`, open **SQL Editor**, run the migration in `migrations/20261103200000_create_site_poll.sql`, and confirm it succeeds.
2. In **Project Settings → Edge Functions → Secrets**, set:
   - `SITE_PASSWORD` to the trip password you want guests to use.
   - `SESSION_SECRET` to a separate, randomly generated secret (at least 32 random bytes). For example, generate one locally with `openssl rand -hex 32`.
3. Install the Supabase CLI, log in, link the project, and deploy the function:

   ```sh
   npx supabase login
   npx supabase link --project-ref eqvmdhmlgvkyhthoeyvt
   npx supabase functions deploy site-api --no-verify-jwt
   ```

4. Open **Authentication → URL Configuration** and allow the site origin `https://sottyon.github.io` if your project's function or network restrictions require explicit origins.
5. Reload `https://sottyon.github.io/carol/`, enter a name and the trip password, and submit a test vote. Use the Results tab to confirm it persists after reload.

The function accepts requests only from the published site and localhost for development. It rate-limits sign-in attempts and keeps the password, session signing key, and database service-role key on the server. Each normalized name has one saved vote; submitting again updates that vote.

The new poll table starts empty. Existing votes stored by the former Claude-only integration are not automatically transferred.
