const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const mime = require("mime-types");
require("dotenv").config({ path: path.join(__dirname, "config/dev/.env") });
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);


/*
SETTINGS
*/
const adminUsername = "bobbotheking";
const adminPassword = "supersecretadmin12345";

const gameServer = express();
const serverPort = 3333;
const MASTER_KEY = process.env.JWT_SECRET;

gameServer.use(bodyParser.urlencoded({ extended: false }));
gameServer.use(bodyParser.json());

// whitelist for upload
const allowedLootTypes = [".png", ".jpg", ".jpeg", ".gif", ".svg", ".js"];

// multer settings
const lootStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const lootPath = path.join(__dirname, "uploads");
    if (!fs.existsSync(lootPath)) {
      fs.mkdirSync(lootPath);
    }
    cb(null, lootPath);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const lootName = req.user.username + "_" + Date.now() + ext;
    cb(null, lootName);
  },
});

const lootFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname || "").toLowerCase();
  if (!ext) {
    return cb(new Error("File is missing an extension."));
  }
  if (allowedLootTypes.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error("Invalid file type: " + ext));
  }
};

const lootUploader = multer({
  storage: lootStorage,
  fileFilter: lootFilter,
  limits: {
    fileSize: 500 * 1024
  },
});

// last-minute rate-limiting
const cooldownTracker = {};
const COOLDOWN_WINDOW = 15 * 1000; 
const COOLDOWN_LIMIT = 3;

// SQLite init
const questLogFile = path.join(__dirname, "gameverse.db");
const questLog = new sqlite3.Database(questLogFile);

questLog.serialize(() => {
  questLog.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )`);

  questLog.run(`CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    content TEXT,
    username TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  questLog.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT,
    to_user TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  questLog.run(`CREATE TABLE IF NOT EXISTS avatars (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    filepath TEXT
  )`);


  questLog.run(
    "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
    [adminUsername, adminPassword, "admin"]
  );
});

// jwt verify
function verifyPlayerToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });
  jwt.verify(token, MASTER_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// register endpoint
gameServer.post("/register", (req, res) => {
  let { username, password } = req.body;

  
  username = DOMPurify.sanitize(username, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim();
  password = DOMPurify.sanitize(password, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim();

  
  if (username.length > 15 || password.length > 15) {
    return res.status(400).json({ message: "Username and password can be max 15 characters." });
  }

  
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }

  // no mass assignment for u
  const userRole = req.body.role ? "cheater" : "user";

  questLog.run(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    [username, password, userRole],
    function (err) {
      if (err) return res.status(400).json({ message: "Username is taken or invalid." });
      res.json({ message: `Registered as ${userRole}` });
    }
  );
});

// login route
gameServer.post("/login", (req, res) => {
  const { username, password } = req.body;

  const sql = "SELECT * FROM users WHERE username = ? AND password = ?";
  questLog.get(sql, [username, password], (err, row) => {
    if (err) return res.status(500).json({ message: "Login error" });
    if (!row) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(row, MASTER_KEY, { expiresIn: "1h" });
    res.json({ message: "Logged in", token });
  });
});

gameServer.get("/me", verifyPlayerToken, (req, res) => {
  res.json({ loggedIn: true, user: req.user });
});

gameServer.get("/threads", (req, res) => {
  const sql = `
    SELECT threads.*, users.role, avatars.filepath as avatar
    FROM threads
    LEFT JOIN users ON threads.username = users.username
    LEFT JOIN avatars ON threads.username = avatars.username
    ORDER BY threads.created_at DESC
  `;
  questLog.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ threads: rows });
  });
});


gameServer.post("/threads", verifyPlayerToken, (req, res) => {
  let { title, content } = req.body;

  title = DOMPurify.sanitize(title, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }).trim();
  if (!title || title.length > 20 || !/^[a-zA-Z0-9åäöÅÄÖ .,!?:'"()\[\]\-_\n\r]+$/.test(title)) {
    return res.status(400).json({ error: "Title is invalid or too long. Max 20 characters" });
  }

  if (!content || content.length > 300) {
    return res.status(400).json({ error: "Content is too long (max 300 characters)." });
  }
  // xxs maybe
  const purifyOptions = {
    ALLOWED_TAGS: ["b", "i", "u", "strong", "em", "br", "p", "a", "h1", "h2", "h3", "svg", "animate", "button", "img"],
    ALLOWED_ATTR: ["href", "onend", "attributeName", "dur", "target"]
  };
  title = DOMPurify.sanitize(title, purifyOptions);
  content = DOMPurify.sanitize(content, purifyOptions);

  questLog.run(
    "INSERT INTO threads (title, content, username) VALUES (?, ?, ?)",
    [title, content, req.user.username],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Thread created", threadId: this.lastID });
    }
  );
});

gameServer.delete("/threads", verifyPlayerToken, (req, res) => {
  if (req.user.username !== adminUsername) return res.status(403).json({ message: "Denied" });
  questLog.run("DELETE FROM threads", (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "All threads have been removed" });
  });
});

// idor
gameServer.delete("/threads/:id", verifyPlayerToken, (req, res) => {
  const id = req.params.id;
  questLog.run("DELETE FROM threads WHERE id = ?", [id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Thread deleted" });
  });
});

// sqli
gameServer.get("/users", verifyPlayerToken, (req, res) => {
  const search = req.query.q || "";

  const sql = `
    SELECT users.username, users.role, avatars.filepath
    FROM users
    LEFT JOIN avatars ON users.username = avatars.username
    WHERE users.username LIKE '%${search}%'
      AND users.username != '${adminUsername}'
  `;

  questLog.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: rows });
  });
});


gameServer.post("/message", verifyPlayerToken, (req, res) => {
  const { to_user, content } = req.body;

  if (!to_user || !content) {
    return res.status(400).json({ error: "Both recipient and content are required." });
  }

  if (to_user === req.user.username) {
    return res.status(400).json({ error: "You cannot send messages to yourself." });
  }

  // Rate limiting
  const sender = req.user.username;
  const now = Date.now();
  if (!cooldownTracker[sender]) {
    cooldownTracker[sender] = [];
  }

  // Remove old timestamps
  cooldownTracker[sender] = cooldownTracker[sender].filter(ts => now - ts < COOLDOWN_WINDOW);

  if (cooldownTracker[sender].length >= COOLDOWN_LIMIT) {
    return res.status(429).json({ error: "You are sending messages too quickly. Please try again soon." });
  }

  cooldownTracker[sender].push(now);
  fs.appendFileSync("logs/xss_messages.log", `${new Date().toISOString()} - From ${sender} to ${to_user}: ${content}\n`);
  // Sanitize content - But allow for svg by object
  const sanitizedContent = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ["b", "i", "u", "em", "strong", "br", "p", "a", "object"],
    ALLOWED_ATTR: ["href", "data", "type"],
  });

  questLog.get("SELECT username FROM users WHERE username = ?", [to_user], (err, row) => {
    if (err) return res.status(500).json({ error: "Database error." });
    if (!row) return res.status(404).json({ error: "Recipient does not exist." });

    questLog.run(
      "INSERT INTO messages (from_user, to_user, content) VALUES (?, ?, ?)",
      [sender, to_user, sanitizedContent],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Message sent" });
      }
    );
  });
});


gameServer.get("/messages", verifyPlayerToken, (req, res) => {
  questLog.all("SELECT * FROM messages WHERE to_user = ? ORDER BY created_at DESC", [req.user.username], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ messages: rows });
  });
});

// LFI
gameServer.get("/images", (req, res) => {
  const requestedPath = req.query.path;
  if (!requestedPath) return res.status(400).send("No file specified.");

  // Log potential LFI attempts
  if (/%2e|%2f|\.\./i.test(requestedPath)) {
    fs.appendFileSync("logs/lfi.log", `${new Date().toISOString()} - ${requestedPath}\n`);
  }

  // Forbid sensitive files
  const forbidden = ["server.js", "package.json", "gameverse.db"];
  if (forbidden.some(f => requestedPath.includes(f))) {
    return res.status(404).send("404 - File not found.");
  }

  // Decode and remove simple path traversal
  const safePath = requestedPath.replace(/\.\.(\/|\\)/g, "");
  const decoded = decodeURIComponent(safePath);
  const filePath = path.join(__dirname, "public", decoded);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      return res.status(404).send("404 - File not found.");
    }

    const type = mime.lookup(filePath) || "application/octet-stream";
    res.setHeader("Content-Type", type);

    const stream = fs.createReadStream(filePath);
    stream.on("error", () => {
      res.status(500).send("Error reading file.");
    });

    stream.pipe(res);
  });
});


// SSRF
gameServer.post("/admin/execute-plugin", verifyPlayerToken, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied." });
  }

  const { filename } = req.body;
  fs.appendFileSync("logs/ssrf.log", `${new Date().toISOString()} - ${req.user.username} tried to execute ${filename}\n`);
  if (!filename || typeof filename !== "string") {
    return res.status(400).json({ message: "No plugin specified." });
  }

  const fullPath = path.join(__dirname, "plugins", filename);

  fs.readFile(fullPath, "utf8", (err, code) => {
    if (err) {
      return res.status(404).json({ message: "Could not read plugin file." });
    }

    try {
      const result = eval(code);
      res.json({ result: result || "Plugin executed without error." });
    } catch (e) {
      res.status(500).json({ message: "Error executing plugin.", error: e.toString() });
    }
  });
});



// xss with svg
gameServer.post("/avatar", verifyPlayerToken, lootUploader.single("avatar"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file received or invalid file type." });
  }

  const newFilepath = "/uploads/" + req.file.filename;

  questLog.get("SELECT filepath FROM avatars WHERE username = ?", [req.user.username], (err, row) => {
    if (err) {
      console.error("Error fetching previous avatar:", err);
      return res.status(500).json({ error: "Internal server error." });
    }

    if (row && row.filepath) {
      const oldFile = path.join(__dirname, row.filepath);
      fs.unlink(oldFile, (err) => {
        if (err && err.code !== "ENOENT") {
          console.warn("Could not remove old avatar:", err.message);
        }
      });
    }

    questLog.run(
      "REPLACE INTO avatars (username, filepath) VALUES (?, ?)",
      [req.user.username, newFilepath],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Avatar saved", filepath: newFilepath });
      }
    );
  });
});


gameServer.get("/avatar/:username", (req, res) => {
  const username = req.params.username;
  questLog.get("SELECT filepath FROM avatars WHERE username = ?", [username], (err, row) => {
    if (err || !row) return res.status(404).json({ error: "No avatar found" });
    res.json({ filepath: row.filepath }); 
  });
});





gameServer.use(express.static(path.join(__dirname, "public")));
gameServer.use("/uploads", express.static(path.join(__dirname, "uploads")));


gameServer.use((req, res, next) => {
  res.status(404);

  if (req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "404.html"));
  }
  if (req.accepts("json")) {
    return res.json({ error: "404 - Page not found" });
  }

  res.type("txt").send("404 - Page not found");
});

gameServer.use((err, req, res, next) => {
  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ error: "File is too large. Max 500 KB allowed." });
  }

  if (err.name === "MulterError") {
    return res.status(400).json({ error: "File upload error: " + err.message });
  }

  
  if (err instanceof Error && err.message.startsWith("Invalid file type")) {
    return res.status(400).json({ error: err.message });
  }


  console.error("Unexpected error:", err);
  res.status(500).json({ error: "An unexpected error occurred." });
});


gameServer.listen(serverPort, () => {
  console.log(`Game on @ http://localhost:${serverPort}`);
});

