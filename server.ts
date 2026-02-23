import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("scam_shield.db");

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_title TEXT,
    company_name TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_title TEXT,
    company_name TEXT,
    description TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '10mb' }));

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };

  // API Routes
  app.post("/api/admin/login", (req, res) => {
    const { password } = req.body;
    const adminPassword = process.env.ADMIN_PASSWORD || "admin123";

    if (password === adminPassword) {
      const token = jwt.sign({ role: 'admin' }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '24h' });
      return res.json({ token });
    }
    res.status(401).json({ error: "Invalid password" });
  });

  app.post("/api/analyze/save", (req, res) => {
    const { jobTitle, companyName, riskScore, riskLevel } = req.body;
    const stmt = db.prepare("INSERT INTO analyses (job_title, company_name, risk_score, risk_level) VALUES (?, ?, ?, ?)");
    stmt.run(jobTitle, companyName, riskScore, riskLevel);
    res.json({ success: true });
  });

  app.get("/api/stats", (req, res) => {
    const totalAnalyses = db.prepare("SELECT COUNT(*) as count FROM analyses").get() as any;
    const flaggedScams = db.prepare("SELECT COUNT(*) as count FROM analyses WHERE risk_level = 'High Risk'").get() as any;
    const riskDistribution = db.prepare("SELECT risk_level, COUNT(*) as count FROM analyses GROUP BY risk_level").all();
    
    res.json({
      totalAnalyses: totalAnalyses.count,
      flaggedScams: flaggedScams.count,
      riskDistribution
    });
  });

  app.post("/api/reports", (req, res) => {
    const { jobTitle, companyName, description } = req.body;
    const stmt = db.prepare("INSERT INTO reports (job_title, company_name, description) VALUES (?, ?, ?)");
    stmt.run(jobTitle, companyName, description);
    res.json({ success: true });
  });

  app.get("/api/admin/reports", authenticateToken, (req, res) => {
    const reports = db.prepare("SELECT * FROM reports ORDER BY created_at DESC").all();
    res.json(reports);
  });

  app.patch("/api/admin/reports/:id", authenticateToken, (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const stmt = db.prepare("UPDATE reports SET status = ? WHERE id = ?");
    stmt.run(status, id);
    res.json({ success: true });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
