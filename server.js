require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const compression = require("compression");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const Busboy = require("busboy");
const { spawn } = require("child_process");
const ffmpegPath = require("ffmpeg-static");
const Database = require("better-sqlite3");
const envalid = require("envalid");
const pLimit = require("p-limit");

// ---------- Environment ----------
const env = envalid.cleanEnv(process.env, {
  PORT: envalid.port({ default: 3010 }),
  BASE_URL: envalid.str({ desc: "Public base URL for file links (no trailing slash)" }),
  OWNER_API_KEY: envalid.str({ desc: "Owner key for admin endpoints" }),
  RETENTION_CHECK_INTERVAL_HOURS: envalid.num({ default: 1, min: 1 }),
  MAX_UPLOAD_SIZE_GB: envalid.num({ default: 25, min: 1 }),
  FFMPEG_CONCURRENCY: envalid.num({ default: 1, min: 1 }),
  FFMPEG_TIMEOUT_MS: envalid.num({ default: 300_000, min: 30_000 }),
});

const {
  PORT,
  BASE_URL,
  OWNER_API_KEY,
  RETENTION_CHECK_INTERVAL_HOURS,
  MAX_UPLOAD_SIZE_GB,
  FFMPEG_CONCURRENCY,
  FFMPEG_TIMEOUT_MS,
} = env;

const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_GB * 1024 * 1024 * 1024;
const UPLOAD_DIR = path.join(__dirname, "uploads");
const TEMP_DIR = path.join(__dirname, "temp");
const KEYS_FILE = path.join(__dirname, "keys.json");
const DB_PATH = path.join(__dirname, "cdn.db");

// ---------- Directories ----------
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(TEMP_DIR, { recursive: true });

if (!fs.existsSync(KEYS_FILE)) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify({ keys: [] }, null, 2));
}

// ---------- Database ----------
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

const userVersion = db.pragma("user_version", { simple: true });
if (userVersion === 0) {
  db.exec(`
    CREATE TABLE files (
      id TEXT PRIMARY KEY,
      originalName TEXT NOT NULL,
      size INTEGER NOT NULL,
      mime TEXT,
      uploadedAt INTEGER NOT NULL,
      retentionOverride INTEGER DEFAULT NULL, -- 1 = force retention, 0 = force no retention, NULL = default
      retentionDays INTEGER DEFAULT NULL
    );
    CREATE INDEX idx_retention ON files(retentionDays, uploadedAt);
  `);
  db.pragma("user_version = 1");
}

// ---------- Logger ----------
const log = {
  info: (...args) => console.log(`[${new Date().toISOString()}] INFO:`, ...args),
  warn: (...args) => console.warn(`[${new Date().toISOString()}] WARN:`, ...args),
  error: (...args) => console.error(`[${new Date().toISOString()}] ERROR:`, ...args),
};

// ---------- FFmpeg helpers ----------
const ffmpegLimit = pLimit(FFMPEG_CONCURRENCY);

function runFFmpeg(args, timeoutMs = FFMPEG_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const proc = spawn(ffmpegPath, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";

    proc.stderr.on("data", (d) => {
      stderr += d.toString();
      if (stderr.length > 64 * 1024) stderr = stderr.slice(-32 * 1024); // keep last 32 KB
    });

    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error("FFmpeg timeout"));
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(stderr.trim() || `FFmpeg exited with code ${code}`));
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function convertVideoToMp4(input, output) {
  const tempOut = output + ".tmp.mp4";
  try {
    // Fast path: stream copy
    await runFFmpeg([
      "-y", "-i", input,
      "-c", "copy",
      "-movflags", "+faststart",
      tempOut,
    ]);
  } catch {
    // Fallback: re-encode
    await runFFmpeg([
      "-y", "-i", input,
      "-c:v", "libx264", "-preset", "medium", "-crf", "20",
      "-c:a", "aac", "-b:a", "192k",
      "-movflags", "+faststart",
      tempOut,
    ]);
  }
  await fsp.rename(tempOut, output);
}

async function convertAudioToMp3(input, output) {
  await runFFmpeg([
    "-y", "-i", input,
    "-vn", "-c:a", "libmp3lame", "-b:a", "192k",
    output,
  ]);
}

// ---------- Auth helpers ----------
function generateId() {
  return crypto.randomUUID();
}

function getToken(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;
  return auth.replace(/^Bearer\s+/i, "").trim() || null;
}

function getKeyData(token) {
  if (!token) return null;
  if (token === OWNER_API_KEY) return { owner: true, key: token };

  try {
    const data = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
    const found = data.keys?.find((k) => k.key === token);
    return found ? { ...found, owner: false } : null;
  } catch {
    return null;
  }
}

function authenticate(req, res, next) {
  const key = getKeyData(getToken(req));
  if (!key) {
    return res.status(401).json({ error: "unauthorized" });
  }
  req.key = key;
  next();
}

function requireOwner(req, res, next) {
  if (!req.key?.owner) {
    return res.status(403).json({ error: "owner authorization required" });
  }
  next();
}

function parseRetentionHeaders(req) {
  const raw = req.headers["x-retention-days"];
  if (raw === undefined || raw === "") {
    // No override → use default (no forced retention)
    return { override: false, enabled: false, days: null };
  }

  const days = Number(raw);
  if (!Number.isInteger(days) || days < 1) {
    throw new Error("X-Retention-Days must be a positive whole number");
  }
  return { override: true, enabled: true, days };
}

function isSafePath(requestedPath) {
  const resolved = path.resolve(requestedPath);
  const base = path.resolve(UPLOAD_DIR);
  return resolved === base || resolved.startsWith(base + path.sep);
}

// ---------- MIME map ----------
const MIME_MAP = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
  ".mp3": "audio/mpeg",
  ".wav": "audio/wav",
  ".pdf": "application/pdf",
};

const VIDEO_EXTS = new Set([".mov", ".mkv", ".avi", ".wmv"]);
const AUDIO_EXTS = new Set([".wav", ".aac", ".m4a", ".flac", ".ogg", ".wma"]);

// ---------- Express app ----------
const app = express();

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(compression());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Range, X-Retention-Days"
  );
  res.setHeader("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---------- Routes ----------

// Health
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: Date.now(),
  });
});

app.get("/health/ready", async (req, res, next) => {
  try {
    db.prepare("SELECT 1").get();
    await fsp.access(UPLOAD_DIR, fs.constants.R_OK | fs.constants.W_OK);
    res.json({ status: "ready", database: "ok", storage: "ok" });
  } catch (err) {
    next(err);
  }
});

// Upload
app.post("/upload", authenticate, (req, res) => {
  let retention;
  try {
    retention = parseRetentionHeaders(req);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  if (retention.override && !req.key.owner) {
    return res.status(403).json({ error: "only the owner can override retention" });
  }

  const busboy = Busboy({
    headers: req.headers,
    limits: {
      files: 1,
      parts: 5,
      fileSize: MAX_UPLOAD_SIZE_BYTES,
    },
  });

  let tempPath = null;
  let responded = false;
  let bytesReceived = 0;
  let originalName = null;
  let mimeType = null;

  const cleanup = async () => {
    if (tempPath) {
      await fsp.unlink(tempPath).catch(() => {});
      tempPath = null;
    }
  };

  const fail = async (status, message, err) => {
    if (responded) return;
    responded = true;
    await cleanup();
    if (err) log.error("Upload failed:", err);
    res.status(status).json({ error: message });
  };

  busboy.on("file", (field, file, info) => {
    originalName = info.filename || "unnamed";
    mimeType = info.mimeType || "application/octet-stream";

    const ext = path.extname(originalName).toLowerCase() || "";
    const baseId = generateId();
    tempPath = path.join(TEMP_DIR, baseId + (ext || ".bin"));

    const writeStream = fs.createWriteStream(tempPath);

    file.on("data", (chunk) => {
      bytesReceived += chunk.length;
    });

    file.on("limit", () => {
      file.resume(); // drain
      fail(413, `File exceeds maximum size of ${MAX_UPLOAD_SIZE_GB} GB`);
    });

    file.pipe(writeStream);

    writeStream.on("finish", async () => {
      if (responded) return;

      try {
        let finalExt = ext;
        if (VIDEO_EXTS.has(ext)) finalExt = ".mp4";
        else if (AUDIO_EXTS.has(ext)) finalExt = ".mp3";

        const finalPath = path.join(UPLOAD_DIR, baseId + finalExt);

        if (VIDEO_EXTS.has(ext)) {
          await ffmpegLimit(() => convertVideoToMp4(tempPath, finalPath));
        } else if (AUDIO_EXTS.has(ext)) {
          await ffmpegLimit(() => convertAudioToMp3(tempPath, finalPath));
        } else {
          await fsp.rename(tempPath, finalPath);
          tempPath = null; // already moved
        }

        await cleanup(); // remove any leftover temp

        const retentionOverride = retention.override ? (retention.enabled ? 1 : 0) : null;
        const retentionDays = retention.override && retention.enabled ? retention.days : null;

        db.prepare(`
          INSERT INTO files (id, originalName, size, mime, uploadedAt, retentionOverride, retentionDays)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          baseId,
          originalName,
          bytesReceived,
          mimeType,
          Date.now(),
          retentionOverride,
          retentionDays
        );

        if (!responded) {
          responded = true;
          res.json({
            success: true,
            id: baseId,
            filename: baseId + finalExt,
            url: `${BASE_URL}/${baseId}${finalExt}`,
            size: bytesReceived,
            originalName,
          });
        }
      } catch (err) {
        await fail(500, "upload processing failed", err);
      }
    });

    writeStream.on("error", (err) => fail(500, "upload write failed", err));
    file.on("error", (err) => fail(500, "upload stream error", err));
  });

  busboy.on("error", (err) => fail(400, "invalid multipart data", err));
  busboy.on("filesLimit", () => fail(400, "only one file allowed"));
  busboy.on("partsLimit", () => fail(400, "too many parts"));

  req.pipe(busboy);
});

// Delete
app.delete("/delete/:file", authenticate, async (req, res, next) => {
  const filename = path.basename(req.params.file); // prevent path tricks
  const filePath = path.join(UPLOAD_DIR, filename);

  if (!isSafePath(filePath)) {
    return res.status(403).json({ error: "forbidden" });
  }

  try {
    await fsp.access(filePath);
  } catch {
    return res.status(404).json({ error: "file not found" });
  }

  try {
    await fsp.unlink(filePath);
    const id = path.parse(filename).name;
    db.prepare("DELETE FROM files WHERE id = ?").run(id);
    res.json({ success: true, message: `File ${filename} deleted` });
  } catch (err) {
    next(err);
  }
});

// Retention override (owner only)
app.post("/retention/:file", authenticate, requireOwner, (req, res) => {
  const fileId = path.parse(req.params.file).name;
  const file = db.prepare("SELECT id FROM files WHERE id = ?").get(fileId);

  if (!file) {
    return res.status(404).json({ error: "file not found" });
  }

  const enabled = req.body?.enabled;
  if (typeof enabled !== "boolean") {
    return res.status(400).json({ error: "enabled must be true or false" });
  }

  let days = null;
  if (enabled) {
    days = Number(req.body.days);
    if (!Number.isInteger(days) || days < 1) {
      return res.status(400).json({ error: "days must be a positive whole number" });
    }
  }

  db.prepare(
    `UPDATE files SET retentionOverride = ?, retentionDays = ? WHERE id = ?`
  ).run(enabled ? 1 : 0, days, fileId);

  res.json({
    success: true,
    file: fileId,
    retention: { enabled, days },
  });
});

// Serve files (with Range support)
app.get("/:file", async (req, res, next) => {
  const filename = path.basename(req.params.file);
  const filePath = path.join(UPLOAD_DIR, filename);

  if (!isSafePath(filePath)) {
    return res.status(403).end();
  }

  let stat;
  try {
    stat = await fsp.stat(filePath);
    if (!stat.isFile()) return res.status(404).end();
  } catch {
    return res.status(404).end();
  }

  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_MAP[ext] || "application/octet-stream";

  res.setHeader("Content-Type", mime);
  res.setHeader("Content-Disposition", "inline");
  res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  res.setHeader("Accept-Ranges", "bytes");
  res.setHeader("X-Content-Type-Options", "nosniff");

  const range = req.headers.range;
  if (range) {
    const match = range.match(/bytes=(\d*)-(\d*)/);
    if (!match) return res.status(416).end();

    let start = match[1] ? parseInt(match[1], 10) : 0;
    let end = match[2] ? parseInt(match[2], 10) : stat.size - 1;

    if (isNaN(start) || isNaN(end) || start > end || start >= stat.size) {
      return res.status(416).end();
    }
    end = Math.min(end, stat.size - 1);

    res.writeHead(206, {
      "Content-Range": `bytes ${start}-${end}/${stat.size}`,
      "Content-Length": end - start + 1,
    });
    fs.createReadStream(filePath, { start, end }).pipe(res);
  } else {
    res.setHeader("Content-Length", stat.size);
    fs.createReadStream(filePath).pipe(res);
  }
});

// ---------- Error handler ----------
app.use((err, req, res, next) => {
  log.error("Unhandled error:", err);
  const status = err.status || 500;
  res.status(status).json({
    error: status === 500 ? "Internal server error" : err.message,
  });
});

// ---------- Retention cleanup ----------
async function runRetentionCleanup() {
  log.info("Running retention cleanup…");
  const now = Date.now();
  const rows = db
    .prepare(
      `SELECT id, originalName, uploadedAt, retentionDays
       FROM files
       WHERE retentionDays IS NOT NULL`
    )
    .all();

  let deleted = 0;
  let skipped = 0;

  for (const row of rows) {
    const expiry = row.uploadedAt + row.retentionDays * 24 * 60 * 60 * 1000;
    if (now < expiry) {
      skipped++;
      continue;
    }

    try {
      const entries = await fsp.readdir(UPLOAD_DIR);
      const toDelete = entries.filter((f) => path.parse(f).name === row.id);

      for (const f of toDelete) {
        await fsp.unlink(path.join(UPLOAD_DIR, f));
      }

      db.prepare("DELETE FROM files WHERE id = ?").run(row.id);
      deleted++;
      log.info(`Retention deleted ${row.id} (${row.originalName})`);
    } catch (err) {
      log.error(`Failed to delete ${row.id}:`, err);
    }
  }

  log.info(`Cleanup finished. Deleted: ${deleted}, still valid: ${skipped}`);
}

// Schedule
setTimeout(() => runRetentionCleanup().catch(log.error), 10_000);
setInterval(
  () => runRetentionCleanup().catch(log.error),
  RETENTION_CHECK_INTERVAL_HOURS * 3_600_000
);

// ---------- Start ----------
const server = app.listen(PORT, () => {
  log.info(`CDN listening on port ${PORT}`);
  log.info(`Max upload size: ${MAX_UPLOAD_SIZE_GB} GB`);
  log.info(`FFmpeg concurrency: ${FFMPEG_CONCURRENCY}`);
  log.info(`Retention check every ${RETENTION_CHECK_INTERVAL_HOURS} h`);
});

// Graceful shutdown
function shutdown(signal) {
  log.info(`${signal} received – shutting down`);
  server.close(() => {
    try {
      db.close();
    } catch {}
    process.exit(0);
  });

  // Force exit after 10 s
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
