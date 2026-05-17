const http = require("http");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const crypto = require("crypto");

const root = __dirname;
const dataDir = path.join(root, "data");
const dbPath = path.join(dataDir, "db.json");
const port = Number(process.env.PORT || 3000);
const sessionDays = 7;

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".png": "image/png"
};

const loginAttempts = new Map();

async function ensureDb() {
  await fsp.mkdir(dataDir, { recursive: true });
  try {
    await fsp.access(dbPath);
  } catch {
    await writeDb({ users: [], sessions: [], orders: [] });
  }
}

async function readDb() {
  await ensureDb();
  return JSON.parse(await fsp.readFile(dbPath, "utf8"));
}

async function writeDb(db) {
  await fsp.writeFile(dbPath, JSON.stringify(db, null, 2));
}

function json(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers
  });
  res.end(JSON.stringify(body));
}

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([key, value]) => key && value)
  );
}

async function readBody(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 100_000) throw new Error("Request body too large");
  }
  return raw ? JSON.parse(raw) : {};
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 32, "sha256").toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const actual = hashPassword(password, salt).hash;
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expectedHash, "hex"));
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function publicUser(user) {
  return { id: user.id, name: user.name, phone: user.phone };
}

function cleanPhone(phone) {
  return String(phone || "").replace(/\D/g, "");
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 8;
}

function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  return origin === `http://127.0.0.1:${port}` || origin === `http://localhost:${port}`;
}

function tooManyAttempts(ip) {
  const now = Date.now();
  const item = loginAttempts.get(ip) || { count: 0, resetAt: now + 10 * 60 * 1000 };
  if (now > item.resetAt) {
    item.count = 0;
    item.resetAt = now + 10 * 60 * 1000;
  }
  item.count += 1;
  loginAttempts.set(ip, item);
  return item.count > 20;
}

async function getSessionUser(req, db) {
  const token = parseCookies(req).citi_session;
  if (!token) return null;

  const tokenHash = hashToken(token);
  const now = new Date();
  db.sessions = db.sessions.filter((session) => new Date(session.expiresAt) > now);
  const session = db.sessions.find((item) => item.tokenHash === tokenHash);
  if (!session) return null;
  return db.users.find((user) => user.id === session.userId) || null;
}

function sessionCookie(token) {
  const maxAge = sessionDays * 24 * 60 * 60;
  return `citi_session=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax`;
}

function clearSessionCookie() {
  return "citi_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax";
}

async function handleApi(req, res, pathname) {
  if (!checkOrigin(req)) return json(res, 403, { error: "Blocked request origin" });

  const db = await readDb();

  if (req.method === "GET" && pathname === "/api/me") {
    const user = await getSessionUser(req, db);
    await writeDb(db);
    return json(res, 200, { user: user ? publicUser(user) : null });
  }

  if (req.method === "POST" && pathname === "/api/register") {
    const body = await readBody(req);
    const name = String(body.name || "").trim();
    const phone = cleanPhone(body.phone);
    const password = String(body.password || "");

    if (name.length < 2) return json(res, 400, { error: "Enter your name" });
    if (phone.length < 10) return json(res, 400, { error: "Enter a valid phone number" });
    if (!validatePassword(password)) return json(res, 400, { error: "Password must be at least 8 characters" });
    if (db.users.some((user) => user.phone === phone)) return json(res, 409, { error: "Phone number already registered" });

    const passwordHash = hashPassword(password);
    const user = {
      id: crypto.randomUUID(),
      name,
      phone,
      passwordSalt: passwordHash.salt,
      passwordHash: passwordHash.hash,
      createdAt: new Date().toISOString()
    };
    const token = crypto.randomBytes(32).toString("hex");
    db.users.push(user);
    db.sessions.push({
      tokenHash: hashToken(token),
      userId: user.id,
      expiresAt: new Date(Date.now() + sessionDays * 24 * 60 * 60 * 1000).toISOString()
    });
    await writeDb(db);
    return json(res, 201, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(token) });
  }

  if (req.method === "POST" && pathname === "/api/login") {
    const ip = req.socket.remoteAddress || "unknown";
    if (tooManyAttempts(ip)) return json(res, 429, { error: "Too many attempts. Try again later." });

    const body = await readBody(req);
    const phone = cleanPhone(body.phone);
    const password = String(body.password || "");
    const user = db.users.find((item) => item.phone === phone);

    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      return json(res, 401, { error: "Wrong phone number or password" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    db.sessions.push({
      tokenHash: hashToken(token),
      userId: user.id,
      expiresAt: new Date(Date.now() + sessionDays * 24 * 60 * 60 * 1000).toISOString()
    });
    await writeDb(db);
    return json(res, 200, { user: publicUser(user) }, { "Set-Cookie": sessionCookie(token) });
  }

  if (req.method === "POST" && pathname === "/api/logout") {
    const token = parseCookies(req).citi_session;
    if (token) {
      const tokenHash = hashToken(token);
      db.sessions = db.sessions.filter((session) => session.tokenHash !== tokenHash);
      await writeDb(db);
    }
    return json(res, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
  }

  if (req.method === "POST" && pathname === "/api/orders") {
    const user = await getSessionUser(req, db);
    if (!user) return json(res, 401, { error: "Please login before buying" });

    const body = await readBody(req);
    const items = Array.isArray(body.items) ? body.items : [];
    const cleanItems = items
      .map((item) => ({
        name: String(item.name || "").slice(0, 80),
        size: String(item.size || "").slice(0, 20),
        quantity: Math.max(1, Number(item.quantity) || 1),
        price: Math.max(0, Number(item.price) || 0)
      }))
      .filter((item) => item.name && item.size && item.price);

    if (cleanItems.length === 0) return json(res, 400, { error: "Cart is empty" });

    const total = cleanItems.reduce((sum, item) => sum + item.price * item.quantity, 0);
    const order = {
      id: crypto.randomUUID(),
      userId: user.id,
      customer: publicUser(user),
      items: cleanItems,
      total,
      status: "new",
      createdAt: new Date().toISOString()
    };
    db.orders.push(order);
    await writeDb(db);
    return json(res, 201, { order });
  }

  return json(res, 404, { error: "API not found" });
}

async function serveStatic(req, res, pathname) {
  let safePath = pathname === "/" ? "/index.html" : decodeURIComponent(pathname);
  const filePath = path.normalize(path.join(root, safePath));

  if (!filePath.startsWith(root) || filePath.startsWith(dataDir)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }
    res.writeHead(200, {
      "Content-Type": types[path.extname(filePath)] || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "same-origin",
      "X-Frame-Options": "DENY"
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    if (url.pathname.startsWith("/api/")) {
      await handleApi(req, res, url.pathname);
    } else {
      await serveStatic(req, res, url.pathname);
    }
  } catch (error) {
    json(res, 500, { error: "Server error" });
  }
});

server.listen(port, "127.0.0.1", () => {
  console.log(`CITI Pickles backend running at http://127.0.0.1:${port}`);
});
