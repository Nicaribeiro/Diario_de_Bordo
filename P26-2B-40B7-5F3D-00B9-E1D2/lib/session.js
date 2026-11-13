// Utilitários de sessão: cookie assinado com HMAC-SHA256.
// O "lib" fica fora de /functions de propósito, para não virar uma rota.
const enc = new TextEncoder();

function toB64Url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64Url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

function hmacKey(secret, usage) {
  return crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]
  );
}

// Cria "conteudo.assinatura". Sem o segredo, ninguém consegue forjar a assinatura.
export async function signSession(payload, secret) {
  const body = toB64Url(enc.encode(JSON.stringify(payload)));
  const key = await hmacKey(secret, "sign");
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return `${body}.${toB64Url(new Uint8Array(sig))}`;
}

// Devolve o conteúdo se a assinatura e a validade estiverem corretas; senão, null.
export async function verifySession(token, secret) {
  try {
    const [body, sig] = String(token).split(".");
    if (!body || !sig) return null;
    const key = await hmacKey(secret, "verify");
    const ok = await crypto.subtle.verify("HMAC", key, fromB64Url(sig), enc.encode(body));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromB64Url(body)));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

export function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const m = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}