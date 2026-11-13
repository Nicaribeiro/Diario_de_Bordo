/**
 * Cloudflare Pages Function — /api/auth/discord/callback
 * Confere o state, troca o code pelo token, busca o perfil (@me),
 * grava no D1 e cria um cookie de sessão ASSINADO.
 */
import { signSession, getCookie } from "../../../../lib/session.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const error = url.searchParams.get("error");
  const fail = (motivo) =>
    Response.redirect(new URL("/?auth_error=" + encodeURIComponent(motivo), url.origin).href, 302);

  if (error || !code) return fail(error || "missing_code");

  // Confere o state: o que voltou do Discord precisa ser igual ao do cookie.
  const stateUrl = url.searchParams.get("state");
  const stateCookie = getCookie(request, "oauth_state");
  if (!stateUrl || !stateCookie || stateUrl !== stateCookie) return fail("invalid_state");

  if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET || !env.SESSION_SECRET) {
    return Response.json({ ok: false, error: "missing_credentials" }, { status: 500 });
  }

  const redirectUri = new URL("/api/auth/discord/callback", url.origin).href;

  try {
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
      }),
    });
    if (!tokenRes.ok) return fail("token_exchange_failed");

    const tokenData = await tokenRes.json();
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userRes.ok) return fail("fetch_user_failed");

    const discordUser = await userRes.json();
    const userId = discordUser.id;
    const username = discordUser.global_name || discordUser.username;
    const avatar = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${userId}/${discordUser.avatar}.png`
      : "https://cdn.discordapp.com/embed/avatars/0.png";

    if (env.DB) {
      try {
        await env.DB.prepare(
          "CREATE TABLE IF NOT EXISTS discord_users (user_id TEXT PRIMARY KEY, username TEXT NOT NULL, avatar TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        ).run();
        await env.DB.prepare(
          "INSERT INTO discord_users (user_id, username, avatar, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET username = excluded.username, avatar = excluded.avatar, updated_at = CURRENT_TIMESTAMP"
        ).bind(userId, username, avatar).run();
      } catch (e) {
        console.error("Falha ao gravar usuário:", e);
      }
    }

    // Sessão assinada, válida por 24 horas.
    const exp = Math.floor(Date.now() / 1000) + 86400;
    const session = await signSession({ userId, username, avatar, exp }, env.SESSION_SECRET);

    // Dois Set-Cookie: grava a sessão e apaga o oauth_state (uso único).
    const headers = new Headers();
    headers.append("Location", "/?login=success");
    headers.append("Set-Cookie", `discord_session=${session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400; Secure`);
    headers.append("Set-Cookie", "oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure");
    return new Response(null, { status: 302, headers });
  } catch (err) {
    console.error("Erro no callback:", err);
    return fail("exception");
  }
}