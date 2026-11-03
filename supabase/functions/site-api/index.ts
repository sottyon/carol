const allowedOrigins = new Set([
  "https://sottyon.github.io",
  "http://localhost:8000",
  "http://127.0.0.1:8000"
]);
const encoder = new TextEncoder();
const destinationIds = new Set([
  "cancun", "puntacana", "pr", "aruba", "belize", "tci", "fl", "vegas"
]);
const sessionLifetimeMs = 12 * 60 * 60 * 1000;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function jsonResponse(
  body: Record<string, unknown>,
  status: number,
  origin: string
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Headers": "apikey, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin"
    }
  });
}

function requireSecret(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing server secret: ${name}`);
  return value;
}

async function hmac(value: string, secret: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)));
}

async function passwordMatches(password: string, expectedPassword: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(requireSecret("SESSION_SECRET")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const expectedSignature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(expectedPassword)
  );
  return await crypto.subtle.verify(
    "HMAC",
    key,
    expectedSignature,
    encoder.encode(password)
  );
}

async function createToken(name: string, nameKey: string): Promise<string> {
  const payload = base64Url(encoder.encode(JSON.stringify({
    name,
    nameKey,
    expiresAt: Date.now() + sessionLifetimeMs
  })));
  const signature = base64Url(await hmac(payload, requireSecret("SESSION_SECRET")));
  return `${payload}.${signature}`;
}

async function verifyToken(token: unknown): Promise<{ name: string; nameKey: string }> {
  if (typeof token !== "string") throw new Error("Please sign in again.");
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra) throw new Error("Please sign in again.");
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(requireSecret("SESSION_SECRET")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    fromBase64Url(signature),
    encoder.encode(payload)
  );
  if (!valid) throw new Error("Please sign in again.");

  const session = JSON.parse(new TextDecoder().decode(fromBase64Url(payload)));
  if (
    typeof session.name !== "string"
    || typeof session.nameKey !== "string"
    || typeof session.expiresAt !== "number"
    || session.expiresAt <= Date.now()
  ) {
    throw new Error("Your sign-in expired. Please enter the trip password again.");
  }
  return { name: session.name, nameKey: session.nameKey };
}

async function serviceRequest(path: string, init: RequestInit = {}): Promise<Response> {
  const projectUrl = requireSecret("SUPABASE_URL");
  const serviceKey = requireSecret("SUPABASE_SERVICE_ROLE_KEY");
  return await fetch(`${projectUrl}/rest/v1/${path}`, {
    ...init,
    headers: {
      "apikey": serviceKey,
      "Authorization": `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
      ...init.headers
    }
  });
}

async function checkLoginRateLimit(request: Request): Promise<boolean> {
  const forwardedIp = request.headers.get("x-forwarded-for")?.split(",")[0].trim();
  const ip = request.headers.get("cf-connecting-ip") || forwardedIp || "unknown";
  const ipHash = base64Url(await hmac(ip, requireSecret("SESSION_SECRET")));
  const response = await serviceRequest("rpc/consume_site_login_attempt", {
    method: "POST",
    body: JSON.stringify({ p_ip_hash: ipHash })
  });
  if (!response.ok) {
    console.error("Login rate-limit check failed:", response.status);
    throw new Error("The sign-in service is temporarily unavailable.");
  }
  return await response.json() === true;
}

async function login(body: Record<string, unknown>, request: Request): Promise<Response> {
  const name = typeof body.name === "string" ? body.name.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (!name || name.length > 40 || !password || password.length > 256) {
    return jsonResponse({ error: "Enter your name and the trip password." }, 400, request.headers.get("origin")!);
  }
  if (!(await checkLoginRateLimit(request))) {
    return jsonResponse({ error: "Too many sign-in attempts. Please wait 15 minutes and try again." }, 429, request.headers.get("origin")!);
  }

  const expectedPassword = requireSecret("SITE_PASSWORD");
  if (!(await passwordMatches(password, expectedPassword))) {
    return jsonResponse({ error: "That trip password didn’t match. Please try again." }, 401, request.headers.get("origin")!);
  }

  const nameKey = name.normalize("NFKC").toLowerCase();
  return jsonResponse({
    name,
    token: await createToken(name, nameKey)
  }, 200, request.headers.get("origin")!);
}

async function listVotes(body: Record<string, unknown>, request: Request): Promise<Response> {
  await verifyToken(body.token);
  const response = await serviceRequest("trip_votes?select=name_key,display_name,picks&order=updated_at.asc");
  if (!response.ok) {
    console.error("Vote list request failed:", response.status);
    throw new Error("Poll results are temporarily unavailable.");
  }
  const rows = await response.json();
  return jsonResponse({
    votes: rows.map((row: { name_key: string; display_name: string; picks: string[] }) => ({
      name_key: row.name_key,
      name: row.display_name,
      picks: row.picks
    }))
  }, 200, request.headers.get("origin")!);
}

async function saveVote(body: Record<string, unknown>, request: Request): Promise<Response> {
  const session = await verifyToken(body.token);
  const picks = body.picks;
  if (
    !Array.isArray(picks)
    || picks.length !== 3
    || new Set(picks).size !== 3
    || picks.some((id) => typeof id !== "string" || !destinationIds.has(id))
  ) {
    return jsonResponse({ error: "Choose exactly three valid destinations." }, 400, request.headers.get("origin")!);
  }

  const response = await serviceRequest("trip_votes?on_conflict=name_key", {
    method: "POST",
    headers: { "Prefer": "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({
      name_key: session.nameKey,
      display_name: session.name,
      picks,
      updated_at: new Date().toISOString()
    })
  });
  if (!response.ok) {
    console.error("Vote save request failed:", response.status);
    throw new Error("Your vote could not be saved. Please try again.");
  }
  return jsonResponse({ saved: true }, 200, request.headers.get("origin")!);
}

Deno.serve(async (request: Request): Promise<Response> => {
  const origin = request.headers.get("origin") || "";
  if (!allowedOrigins.has(origin)) {
    return new Response("Origin not allowed", { status: 403 });
  }
  if (request.method === "OPTIONS") {
    return new Response("ok", {
      headers: {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "apikey, content-type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Vary": "Origin"
      }
    });
  }
  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed." }, 405, origin);
  }
  if (Number(request.headers.get("content-length") || "0") > 4096) {
    return jsonResponse({ error: "Request is too large." }, 413, origin);
  }

  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return jsonResponse({ error: "Invalid request." }, 400, origin);
    }
    switch (body.action) {
      case "login":
        return await login(body, request);
      case "list":
        return await listVotes(body, request);
      case "vote":
        return await saveVote(body, request);
      default:
        return jsonResponse({ error: "Unknown request." }, 400, origin);
    }
  } catch (error) {
    console.error("Site API request failed:", error);
    const message = error instanceof Error ? error.message : "The site service is unavailable.";
    const status = message.includes("sign in") || message.includes("expired") ? 401 : 500;
    return jsonResponse({ error: message }, status, origin);
  }
});
