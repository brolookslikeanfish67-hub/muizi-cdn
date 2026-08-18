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

// ---------- Environment Validation ----------
const env = envalid.cleanEnv(process.env, {
  PORT: envalid.port({ default: 3010 }),
  BASE_URL: envalid.str({ desc: "Base URL for file links" }),
  OWNER_API_KEY: envalid.str({ desc: "Owner key for admin endpoints" }),
  RETENTION_CHECK_INTERVAL_HOURS: envalid.num({ default: 1, min: 1 }),
  MAX_UPLOAD_SIZE_GB: envalid.num({ default: 25, min: 1 }),
});

const {
  PORT,
  BASE_URL,
  OWNER_API_KEY,
  RETENTION_CHECK_INTERVAL_HOURS,
  MAX_UPLOAD_SIZE_GB,
} = env;

const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_GB * 1024 * 1024 * 1024;
const UPLOAD_DIR = path.join(__dirname, "uploads");
const TEMP_DIR = path.join(__dirname, "temp");
const KEYS_FILE = path.join(__dirname, "keys.json");

// ---------- Directories & Keys ----------
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(TEMP_DIR, { recursive: true });
if (!fs.existsSync(KEYS_FILE)) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify({ keys: [] }, null, 2));
}

// ---------- Database ----------
const db = new Database(path.join(__dirname, "cdn.db"));
db.pragma("journal_mode = WAL");

// Simple migration: add tables and indexes
const userVersion = db.pragma("user_version", { simple: true });
if (userVersion === 0) {
  db.exec(`
    CREATE TABLE files (
      id TEXT PRIMARY KEY,
      originalName TEXT,
      size INTEGER,
      mime TEXT,
      uploadedAt INTEGER,
      retentionOverride INTEGER DEFAULT NULL,
      retentionDays INTEGER DEFAULT NULL
    );
    CREATE INDEX idx_retention ON files(uploadedAt, retentionDays);
  `);
  db.pragma("user_version = 1");
}

// ---------- Logger (simple) ----------
const log = {
  info: (...args) => console.log(`[${new Date().toISOString()}] INFO:`, ...args),
  error: (...args) => console.error(`[${new Date().toISOString()}] ERROR:`, ...args),
};

// ---------- FFmpeg Queue with Concurrency & Timeout ----------
const ffmpegLimit = pLimit(1); // only one conversion at a time

async function runFFmpeg(args, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const proc = spawn(ffmpegPath, args);
    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d.toString()));

    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error("FFmpeg timeout"));
    }, timeoutMs);

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(stderr || `FFmpeg exited with code ${code}`));
    });
    proc.on("error", reject);
  });
}

async function convertVideoToMp4(input, output) {
  const tempOut = output + ".tmp.mp4";
  try {
    // Try stream copy first
    await runFFmpeg([
      "-y", "-i", input,
      "-c", "copy",
      "-movflags", "+faststart",
      tempOut,
    ]);
    await fsp.rename(tempOut, output);
  } catch (err) {
    // Fallback to re-encode
    await runFFmpeg([
      "-y", "-i", input,
      "-c:v", "libx264", "-preset", "medium", "-crf", "20",
      "-c:a", "aac", "-b:a", "192k",
      "-movflags", "+faststart",
      tempOut,
    ]);
    await fsp.rename(tempOut, output);
  }
}

async function convertAudioToMp3(input, output) {
  await runFFmpeg([
    "-y", "-i", input,
    "-vn", "-c:a", "libmp3lame", "-b:a", "192k",
    output,
  ]);
}

// ---------- Express App ----------
const app = express();

// Middleware
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(compression());

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, Range, X-Retention-Enabled, X-Retention-Days"
  );
  res.setHeader("Access-Control-Expose-Headers", "Content-Length, Content-Range");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---------- Helper Functions ----------
function generateId() {
  return crypto.randomUUID();
}

function getToken(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;
  return auth.replace(/^Bearer\s+/i, "");
}

function getKeyData(token) {
  if (token && token === OWNER_API_KEY) {
    return { owner: true };
  }
  try {
    const keys = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
    return keys.keys.find((k) => k.key === token) || null;
  } catch {
    return null;
  }
}

function authenticate(req, res, next) {
  const token = getToken(req);
  const key = getKeyData(token);
  if (!key) {
    return res.status(401).json({ error: "unauthorized" });
  }
  req.key = key;
  next();
}

function requireOwner(req, res, next) {
  if (!req.key || !req.key.owner) {
    return res.status(403).json({ error: "owner authorization required" });
  }
  next();
}

function parseRetentionHeaders(req) {
  const daysHeader = req.headers["x-retention-days"];
  if (daysHeader === undefined || daysHeader === "") {
    return { override: true, enabled: false, days: null };
  }
  const days = Number(daysHeader);
  if (!Number.isInteger(days) || days < 1) {
    throw new Error("X-Retention-Days must be a positive whole number");
  }
  return { override: true, enabled: true, days };
}

function isSafePath(requestedPath) {
  const relative = path.relative(UPLOAD_DIR, requestedPath);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative);
}

// ---------- Routes ----------
// Health
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: Date.now(),
  });
});

app.get("/health/ready", async (req, res, next) => {
  try {
    db.prepare("SELECT 1").get();
    await fsp.access(UPLOAD_DIR, fs.constants.R_OK | fs.constants.W_OK);
    res.status(200).json({ status: "ready", database: "ok", storage: "ok" });
  } catch (err) {
    next(err);
  }
});

// Upload
app.post("/upload", authenticate, (req, res, next) => {
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
      parts: 2,
      fileSize: MAX_UPLOAD_SIZE_BYTES,
    },
  });

  let tempPath = null;
  let responded = false;

  const fail = (err) => {
    if (responded) return;
    responded = true;
    log.error("Upload error:", err);
    if (tempPath) {
      fsp.unlink(tempPath).catch(() => {});
    }
    res.status(500).json({ error: "upload failed" });
  };

  busboy.on("file", (field, file, info) => {
    const originalName = info.filename;
    const mimeType = info.mimeType;
    let bytesReceived = 0;

    file.on("data", (chunk) => {
      bytesReceived += chunk.length;
    });

    const ext = path.extname(originalName).toLowerCase();
    const baseId = generateId();
    tempPath = path.join(TEMP_DIR, baseId + ext);
    const writeStream = fs.createWriteStream(tempPath);

    file.pipe(writeStream);

    writeStream.on("finish", async () => {
      try {
        const videoExts = [".mov", ".mkv"];
        const audioExts = [".wav", ".aac", ".m4a", ".flac", ".ogg", ".wma"];
        let finalExt = ext;
        if (videoExts.includes(ext)) finalExt = ".mp4";
        else if (audioExts.includes(ext)) finalExt = ".mp3";

        const finalPath = path.join(UPLOAD_DIR, baseId + finalExt);

        // Convert with concurrency limit
        if (videoExts.includes(ext)) {
          await ffmpegLimit(() => convertVideoToMp4(tempPath, finalPath));
        } else if (audioExts.includes(ext)) {
          await ffmpegLimit(() => convertAudioToMp3(tempPath, finalPath));
        } else {
          await fsp.rename(tempPath, finalPath);
        }

        // Clean up temp
        if (tempPath) {
          await fsp.unlink(tempPath).catch(() => {});
          tempPath = null;
        }

        // Save metadata
        const retentionOverride = retention.override ? (retention.enabled ? 1 : 0) : null;
        const retentionDays = retention.override && retention.enabled ? retention.days : null;

        db.prepare(`
          INSERT INTO files (id, originalName, size, mime, uploadedAt, retentionOverride, retentionDays)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(baseId, originalName, bytesReceived, mimeType, Date.now(), retentionOverride, retentionDays);

        if (!responded) {
          responded = true;
          res.json({
            success: true,
            filename: baseId,
            url: `${BASE_URL}/${baseId}${finalExt}`,
          });
        }
      } catch (err) {
        fail(err);
      }
    });

    writeStream.on("error", fail);
    file.on("error", fail);
  });

  busboy.on("error", fail);
  req.pipe(busboy);
});

// Delete
app.delete("/delete/:file", authenticate, async (req, res, next) => {
  const filename = req.params.file;
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!isSafePath(filePath)) {
    return res.sendStatus(403);
  }

  try {
    await fsp.access(filePath);
  } catch {
    return res.status(404).json({ error: "file not found" });
  }

  try {
    await fsp.unlink(filePath);
    db.prepare("DELETE FROM files WHERE id = ?").run(path.parse(filename).name);
    res.json({ success: true, message: `File ${filename} deleted.` });
  } catch (err) {
    next(err);
  }
});

// Retention override (owner only)
app.post("/retention/:file", authenticate, requireOwner, async (req, res, next) => {
  const fileId = path.parse(req.params.file).name;
  const file = db.prepare("SELECT * FROM files WHERE id = ?").get(fileId);
  if (!file) {
    return res.status(404).json({ error: "file not found" });
  }

  const enabled = req.body.enabled;
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

  db.prepare(`UPDATE files SET retentionOverride = ?, retentionDays = ? WHERE id = ?`).run(
    enabled ? 1 : 0,
    days,
    fileId
  );

  res.json({ success: true, file: fileId, retention: { enabled, days } });
});

// Serve files
app.get("/:file", async (req, res, next) => {
  const filePath = path.join(UPLOAD_DIR, req.params.file);
  if (!isSafePath(filePath)) {
    return res.sendStatus(403);
  }

  let stat;
  try {
    stat = await fsp.stat(filePath);
  } catch {
    return res.status(404).send("Not found");
  }

  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mp3": "audio/mpeg",
  };
  const mime = mimeTypes[ext] || "application/octet-stream";

  res.setHeader("Content-Type", mime);
  res.setHeader("Content-Disposition", "inline");
  res.setHeader("Cache-Control", "public,max-age=31536000,immutable");
  res.setHeader("Accept-Ranges", "bytes");

  const range = req.headers.range;
  if (range) {
    const parts = range.replace(/bytes=/, "").split("-");
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
    if (isNaN(start) || isNaN(end) || start > end || end >= stat.size) {
      return res.status(416).end();
    }
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

// ---------- Error Handler ----------
app.use((err, req, res, next) => {
  log.error("Unhandled error:", err);
  res.status(err.status || 500).json({
    error: err.message || "Internal server error",
  });
});

// ---------- Retention Cleanup ----------
async function runRetentionCleanup() {
  log.info("Running retention cleanup");
  const now = Date.now();
  const files = db
    .prepare(
      `SELECT id, originalName, uploadedAt, retentionDays FROM files WHERE retentionDays IS NOT NULL`
    )
    .all();

  let deleted = 0,
    skipped = 0;
  for (const file of files) {
    const expiry = file.uploadedAt + file.retentionDays * 24 * 60 * 60 * 1000;
    if (now < expiry) {
      skipped++;
      continue;
    }

    try {
      const entries = await fsp.readdir(UPLOAD_DIR);
      const toDelete = entries.filter((f) => path.parse(f).name === file.id);
      for (const f of toDelete) {
        await fsp.unlink(path.join(UPLOAD_DIR, f));
      }
      db.prepare("DELETE FROM files WHERE id = ?").run(file.id);
      deleted++;
      log.info(`Retention deleted ${file.id} (${file.originalName})`);
    } catch (err) {
      log.error(`Failed to delete ${file.id}:`, err);
    }
  }
  log.info(`Cleanup complete. Deleted: ${deleted}, skipped: ${skipped}`);
}

// Schedule retention
setTimeout(() => runRetentionCleanup().catch(log.error), 10000);
setInterval(
  () => runRetentionCleanup().catch(log.error),
  RETENTION_CHECK_INTERVAL_HOURS * 3600000
);

// ---------- Start Server ----------
const server = app.listen(PORT, () => {
  log.info(`CDN running on port ${PORT}`);
  log.info(`Max upload: ${MAX_UPLOAD_SIZE_GB} GB`);
  log.info(`Retention interval: ${RETENTION_CHECK_INTERVAL_HOURS} hour(s)`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  log.info("SIGTERM received, shutting down");
  server.close(() => process.exit(0));
});
process.on("SIGINT", () => {
  log.info("SIGINT received, shutting down");
  server.close(() => process.exit(0));
});
