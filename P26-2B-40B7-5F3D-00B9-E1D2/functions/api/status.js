import { getCookie, verifySession } from "../../lib/session.js";

/**
 * GET /api/status — diagnóstico e sessão atual.
 * Não lista dados de ninguém e não grava nada.
 */
export async function onRequestGet({ request, env }) {
  let sessionUser = null;
  const token = getCookie(request, "discord_session");
  if (token && env.SESSION_SECRET) {
    sessionUser = await verifySession(token, env.SESSION_SECRET);
  }

  let d1Connected = false;
  if (env.DB) {
    try {
      await env.DB.prepare("SELECT 1").first();
      d1Connected = true;
    } catch {
      d1Connected = false;
    }
  }

  return Response.json({
    ok: true,
    chave: "P26-2B-40B7-5F3D-00B9-E1D2",
    projectId: 14,
    projectTitle: "Diário de Bordo de Projetos",
    d1Connected,
    discordOAuthConfigured: Boolean(env.DISCORD_CLIENT_ID),
    sessionUser,
    serverTimestamp: new Date().toISOString(),
  });
}

// Qualquer outro método (POST, PUT, DELETE...) é recusado.
export async function onRequest() {
  return Response.json({ ok: false, error: "Method not allowed" }, { status: 405 });
}