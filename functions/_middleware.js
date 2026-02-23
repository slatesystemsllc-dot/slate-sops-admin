// Basic Auth middleware for Cloudflare Pages
// Credentials: admin / slate2026

const CREDENTIALS = {
  admin: "admin:slate2026admin",
  sales: "sales:slate2026sales",
  fulfillment: "fulfillment:slate2026fulfill",
  support: "support:slate2026support"
};

const REALM = "Slate Systems SOP Portal";

function parseBasicAuth(request) {
  const authorization = request.headers.get("Authorization");
  if (!authorization) return null;

  const [scheme, encoded] = authorization.split(" ");
  if (scheme !== "Basic") return null;

  const decoded = atob(encoded);
  const [username, password] = decoded.split(":");
  return { username, password };
}

function unauthorized() {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"`,
    },
  });
}

export async function onRequest(context) {
  const credentials = parseBasicAuth(context.request);

  if (!credentials) {
    return unauthorized();
  }

  const { username, password } = credentials;
  const validCredential = `${username}:${password}`;

  // Check against all valid credentials
  const isValid = Object.values(CREDENTIALS).includes(validCredential);

  if (!isValid) {
    return unauthorized();
  }

  return context.next();
}
