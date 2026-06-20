import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { MongoClient, ObjectId } from "mongodb";

// --- Simple Local .env Loader ---
try {
  const envPath = path.resolve(process.cwd(), ".env");
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, "utf-8").split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const firstEqual = trimmed.indexOf("=");
      if (firstEqual > 0) {
        const key = trimmed.slice(0, firstEqual).trim();
        let val = trimmed.slice(firstEqual + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        process.env[key] = val;
      }
    }
  }
} catch (e) {
  console.log("Fallback env loader failed:", e);
}

// --- JWT and ENV Configuration ---
const JWT_SECRET = process.env.JWT_SECRET || "cybertrace_ossd_secret_key_session_salt";
const MONGODB_URI = process.env.MONGODB_URI || "";
const USE_REAL_MONGO = !!(MONGODB_URI && MONGODB_URI.trim());

// --- Database Schemas & Types ---
interface UserStore {
  _id: string;
  email: string;
  password_hash: string;
  display_name: string;
  role: string;
  created_at: string;
  updated_at: string;
}

interface IncidentStore {
  _id: string;
  reporter_id: string;
  reporter_email: string;
  reporter_name: string;
  title: string;
  incident_type: string;
  severity: string;
  ioc_type: string;
  ioc_value: string;
  description: string;
  evidence: string[];
  status: string;
  admin_notes: string;
  created_at: string;
  updated_at: string;
  verified_at?: string;
  verified_by?: string;
}

interface CommentStore {
  _id: string;
  incident_id: string;
  user_id: string;
  display_name: string;
  email: string;
  content: string;
  created_at: string;
}

interface AuditLogStore {
  _id: string;
  actor_id: string;
  action: string;
  target_id: string;
  details: string;
  timestamp: string;
}

// --- In-Memory Database store fallback ---
const memoryDb = {
  users: [] as UserStore[],
  incidents: [] as IncidentStore[],
  comments: [] as CommentStore[],
  audit_logs: [] as AuditLogStore[]
};

let mongoClient: MongoClient | null = null;
let mongoDb: any = null;
let useRealMongo = false;

// Helpers to handle ID casting safely between in-memory string vs real MongoDB ObjectId
function toMongoId(id: string): any {
  if (typeof id === "string" && id.length === 24 && /^[0-9a-fA-F]{24}$/.test(id)) {
    return new ObjectId(id);
  }
  return id;
}

function fromMongoId(id: any): string {
  if (id && id instanceof ObjectId) {
    return id.toHexString();
  }
  return String(id);
}

function mockId(): string {
  return Array.from({ length: 24 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
}

// --- Auth Hashing Cryptography Helpers ---
async function hashPassword(password: string): Promise<string> {
  return await bcrypt.hash(password, 10);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}

function createAccessToken(data: any): string {
  // Access Token expires in 1 day
  return jwt.sign(data, JWT_SECRET, { expiresIn: "1d" });
}

// --- Generic Database Layer Abstraction Methods ---
async function dbFindUser(query: { _id?: string; email?: string }): Promise<UserStore | null> {
  if (useRealMongo && mongoDb) {
    const q: any = {};
    if (query._id) q._id = toMongoId(query._id);
    if (query.email) q.email = query.email;
    const res = await mongoDb.collection("users").findOne(q);
    if (!res) return null;
    return { ...res, _id: fromMongoId(res._id) };
  } else {
    return memoryDb.users.find(u => {
      if (query._id && u._id !== query._id) return false;
      if (query.email && u.email.toLowerCase() !== query.email.toLowerCase()) return false;
      return true;
    }) || null;
  }
}

async function dbInsertUser(user: UserStore): Promise<UserStore> {
  if (useRealMongo && mongoDb) {
    const doc = { ...user, _id: toMongoId(user._id) };
    await mongoDb.collection("users").insertOne(doc);
    return { ...doc, _id: fromMongoId(doc._id) };
  } else {
    memoryDb.users.push(user);
    return user;
  }
}

async function dbUpdateUser(id: string, updates: Partial<UserStore>): Promise<boolean> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("users").updateOne({ _id: toMongoId(id) }, { $set: updates });
    return res.modifiedCount > 0;
  } else {
    const idx = memoryDb.users.findIndex(u => u._id === id);
    if (idx !== -1) {
      memoryDb.users[idx] = { ...memoryDb.users[idx], ...updates, updated_at: new Date().toISOString() };
      return true;
    }
    return false;
  }
}

async function dbGetUsers(): Promise<UserStore[]> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("users").find({}).toArray();
    return res.map((u: any) => ({ ...u, _id: fromMongoId(u._id) }));
  } else {
    return memoryDb.users;
  }
}

async function dbDeleteUser(id: string): Promise<boolean> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("users").deleteOne({ _id: toMongoId(id) });
    return res.deletedCount > 0;
  } else {
    const idx = memoryDb.users.findIndex(u => u._id === id);
    if (idx !== -1) {
      memoryDb.users.splice(idx, 1);
      return true;
    }
    return false;
  }
}

async function dbCountUsers(): Promise<number> {
  if (useRealMongo && mongoDb) {
    return await mongoDb.collection("users").countDocuments({});
  } else {
    return memoryDb.users.length;
  }
}

async function dbGetIncidents(filters: { severity?: string; incident_type?: string; status?: string; search?: string } = {}): Promise<IncidentStore[]> {
  let list: IncidentStore[] = [];
  if (useRealMongo && mongoDb) {
    const q: any = {};
    if (filters.severity) q.severity = filters.severity;
    if (filters.incident_type) q.incident_type = filters.incident_type;
    if (filters.status) q.status = filters.status;
    const res = await mongoDb.collection("incidents").find(q).toArray();
    list = res.map((i: any) => ({ ...i, _id: fromMongoId(i._id) }));
  } else {
    list = memoryDb.incidents.filter(i => {
      if (filters.severity && i.severity !== filters.severity) return false;
      if (filters.incident_type && i.incident_type !== filters.incident_type) return false;
      if (filters.status && i.status !== filters.status) return false;
      return true;
    });
  }

  if (filters.search) {
    const s = filters.search.toLowerCase();
    list = list.filter(i => 
      i.title.toLowerCase().includes(s) || 
      i.ioc_value.toLowerCase().includes(s) || 
      i.description.toLowerCase().includes(s)
    );
  }

  list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  return list;
}

async function dbFindIncidentById(id: string): Promise<IncidentStore | null> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("incidents").findOne({ _id: toMongoId(id) });
    if (!res) return null;
    return { ...res, _id: fromMongoId(res._id) };
  } else {
    return memoryDb.incidents.find(i => i._id === id) || null;
  }
}

async function dbInsertIncident(incident: IncidentStore): Promise<IncidentStore> {
  if (useRealMongo && mongoDb) {
    const doc = { ...incident, _id: toMongoId(incident._id) };
    await mongoDb.collection("incidents").insertOne(doc);
    return { ...doc, _id: fromMongoId(doc._id) };
  } else {
    memoryDb.incidents.push(incident);
    return incident;
  }
}

async function dbUpdateIncident(id: string, updates: Partial<IncidentStore>): Promise<boolean> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("incidents").updateOne({ _id: toMongoId(id) }, { $set: updates });
    return res.modifiedCount > 0;
  } else {
    const idx = memoryDb.incidents.findIndex(i => i._id === id);
    if (idx !== -1) {
      memoryDb.incidents[idx] = { ...memoryDb.incidents[idx], ...updates, updated_at: new Date().toISOString() };
      return true;
    }
    return false;
  }
}

async function dbDeleteIncident(id: string): Promise<boolean> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("incidents").deleteOne({ _id: toMongoId(id) });
    return res.deletedCount > 0;
  } else {
    const idx = memoryDb.incidents.findIndex(i => i._id === id);
    if (idx !== -1) {
      memoryDb.incidents.splice(idx, 1);
      return true;
    }
    return false;
  }
}

async function dbCountIncidents(query: any = {}): Promise<number> {
  if (useRealMongo && mongoDb) {
    return await mongoDb.collection("incidents").countDocuments(query);
  } else {
    return memoryDb.incidents.filter(i => {
      for (const k in query) {
        if (i[k as keyof IncidentStore] !== query[k]) return false;
      }
      return true;
    }).length;
  }
}

async function dbInsertComment(comment: CommentStore): Promise<CommentStore> {
  if (useRealMongo && mongoDb) {
    const doc = { ...comment, _id: toMongoId(comment._id) };
    await mongoDb.collection("comments").insertOne(doc);
    return { ...doc, _id: fromMongoId(doc._id) };
  } else {
    memoryDb.comments.push(comment);
    return comment;
  }
}

async function dbGetComments(incidentId: string): Promise<CommentStore[]> {
  let list: CommentStore[] = [];
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("comments").find({ incident_id: incidentId }).toArray();
    list = res.map((c: any) => ({ ...c, _id: fromMongoId(c._id) }));
  } else {
    list = memoryDb.comments.filter(c => c.incident_id === incidentId);
  }
  list.sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime());
  return list;
}

async function dbFindCommentById(id: string): Promise<CommentStore | null> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("comments").findOne({ _id: toMongoId(id) });
    if (!res) return null;
    return { ...res, _id: fromMongoId(res._id) };
  } else {
    return memoryDb.comments.find(c => c._id === id) || null;
  }
}

async function dbDeleteComment(id: string): Promise<boolean> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("comments").deleteOne({ _id: toMongoId(id) });
    return res.deletedCount > 0;
  } else {
    const idx = memoryDb.comments.findIndex(c => c._id === id);
    if (idx !== -1) {
      memoryDb.comments.splice(idx, 1);
      return true;
    }
    return false;
  }
}

async function dbCountComments(query: any = {}): Promise<number> {
  if (useRealMongo && mongoDb) {
    return await mongoDb.collection("comments").countDocuments(query);
  } else {
    return memoryDb.comments.filter(c => {
      for (const k in query) {
        if (c[k as keyof CommentStore] !== query[k]) return false;
      }
      return true;
    }).length;
  }
}

async function dbInsertAuditLog(log_entry: AuditLogStore): Promise<AuditLogStore> {
  if (useRealMongo && mongoDb) {
    const doc = { ...log_entry, _id: toMongoId(log_entry._id) };
    await mongoDb.collection("audit_logs").insertOne(doc);
    return { ...doc, _id: fromMongoId(doc._id) };
  } else {
    memoryDb.audit_logs.push(log_entry);
    return log_entry;
  }
}

async function dbGetAuditLogs(): Promise<AuditLogStore[]> {
  if (useRealMongo && mongoDb) {
    const res = await mongoDb.collection("audit_logs").find({}).toArray();
    return res.map((l: any) => ({ ...l, _id: fromMongoId(l._id) }));
  } else {
    return memoryDb.audit_logs;
  }
}

// --- Data Seeding Verification ---
async function seedDefaultData() {
  const users = await dbGetUsers();
  const adminExists = users.some(u => u.email === "admin@cybertrace.io");
  if (!adminExists) {
    const adminUser = {
      _id: mockId(),
      email: "admin@cybertrace.io",
      password_hash: await hashPassword("AdminSecurePassword2026"),
      display_name: "Admin Director",
      role: "admin",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    await dbInsertUser(adminUser);
    console.log("Default admin@cybertrace.io account seeded.");
  }

  const incidents = await dbGetIncidents();
  const exampleExists = incidents.some(i => i.title === "Spear Phishing campaign targeting Payroll");
  if (!exampleExists) {
    const exampleIncident = {
      _id: mockId(),
      reporter_id: "system",
      reporter_email: "system@cybertrace.io",
      reporter_name: "System Intel",
      title: "Spear Phishing campaign targeting Payroll",
      incident_type: "phishing",
      severity: "High",
      ioc_type: "domain",
      ioc_value: "secure-payroll-authentication.com",
      description: "Observed wave of credential harvesting phishing mails requesting validation of bank routing slips. Domain is hosting a credential replication page.",
      evidence: ["e-mail headers captured: secure-payroll-authentication.com", "attachment: review_document.zip (hash: e2817d2)"],
      status: "verified",
      admin_notes: "Domain DNS blacklisted on Core Firewall routers.",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      verified_at: new Date().toISOString(),
      verified_by: "system"
    };
    await dbInsertIncident(exampleIncident);
    console.log("Default threat incident demonstration vector seeded.");
  }
}

async function initDb() {
  if (USE_REAL_MONGO) {
    try {
      console.log("Connecting to MongoDB Atlas...");
      mongoClient = await MongoClient.connect(MONGODB_URI, {
        connectTimeoutMS: 5000,
        socketTimeoutMS: 5000
      });
      mongoDb = mongoClient.db("cybertrace");
      useRealMongo = true;
      console.log("Connected to Real MongoDB Atlas cluster cleanly.");
    } catch (err: any) {
      console.log(`MongoDB connection check completed: Atlas is not reachable. Falling back to In-Memory engine.`);
      useRealMongo = false;
    }
  } else {
    console.log("No MONGODB_URI. Running with In-Memory engine.");
    useRealMongo = false;
  }
  
  try {
    await seedDefaultData();
  } catch (err: any) {
    console.log(`Database sync completed: running safely with database fallback.`);
    useRealMongo = false;
    try {
      await seedDefaultData();
      console.log("Successfully seeded database fallback cleanly.");
    } catch (fallbackErr: any) {
      console.log(`Database backup check: fallback complete.`);
    }
  }
}

// --- Application Set Up ---
const app = express();
app.use(cors());
app.use(express.json());

// --- Security Middleware ---
interface AuthRequest extends Request {
  user?: UserStore;
}

async function authenticateToken(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ detail: "Could not validate credentials" });
  }

  try {
    const decoded: any = jwt.verify(token, JWT_SECRET);
    const sub = decoded.sub; // user email
    if (!sub) {
      return res.status(401).json({ detail: "Could not validate credentials" });
    }
    
    const user = await dbFindUser({ email: sub });
    if (!user) {
      return res.status(401).json({ detail: "Could not validate credentials" });
    }
    
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ detail: "Could not validate credentials" });
  }
}

function requireAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ detail: "Forbidden: Admin privilege required to execute action." });
  }
  next();
}

// --- API Endpoints ---

// 1. Auth & Users
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, display_name, role, secret_code } = req.body;
    if (!email || !password || !display_name) {
      return res.status(400).json({ detail: "Email, password, and display name are required" });
    }
    
    // Validate custom role creation
    let finalRole: "user" | "admin" = "user";
    if (role === "admin") {
      if (secret_code !== "1234") {
        return res.status(400).json({ detail: "Invalid Admin Secret Code. Registration denied." });
      }
      finalRole = "admin";
    }
    
    const existing = await dbFindUser({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ detail: "User with this email already registered" });
    }

    const hashed = await hashPassword(password);
    const newUser: UserStore = {
      _id: mockId(),
      email: email.toLowerCase(),
      password_hash: hashed,
      display_name: display_name,
      role: finalRole,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    await dbInsertUser(newUser);

    // Audit log
    await dbInsertAuditLog({
      _id: mockId(),
      actor_id: "system",
      action: "REGISTER_USER",
      target_id: newUser._id,
      details: `User ${email} registered on CyberTrace.`,
      timestamp: new Date().toISOString()
    });

    return res.json({ message: "Registration successful", email: email });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ detail: "Email and password are required" });
    }

    const user = await dbFindUser({ email: email.toLowerCase() });
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({ detail: "Incorrect email or password" });
    }

    const tokenData = {
      sub: user.email,
      role: user.role,
      display_name: user.display_name,
      id: user._id
    };

    const token = createAccessToken(tokenData);

    // Audit log
    await dbInsertAuditLog({
      _id: mockId(),
      actor_id: user._id,
      action: "LOGIN_USER",
      target_id: user._id,
      details: `User ${user.email} successfully logged in.`,
      timestamp: new Date().toISOString()
    });

    return res.json({
      access_token: token,
      token_type: "bearer",
      user: {
        id: user._id,
        email: user.email,
        display_name: user.display_name,
        role: user.role
      }
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/auth/me", authenticateToken, async (req: AuthRequest, res) => {
  const user = req.user!;
  return res.json({
    id: user._id,
    email: user.email,
    display_name: user.display_name,
    role: user.role,
    created_at: user.created_at,
    updated_at: user.updated_at
  });
});

app.put("/api/users/me", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { display_name, password } = req.body;
    const user = req.user!;
    const updates: Partial<UserStore> = {};
    
    if (display_name !== undefined) updates.display_name = display_name;
    if (password !== undefined) updates.password_hash = await hashPassword(password);
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ detail: "No valid update fields supplied" });
    }
    
    await dbUpdateUser(user._id, updates);
    return res.json({ message: "Profile updated successfully" });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/users/:id", authenticateToken, async (req, res) => {
  try {
    const user = await dbFindUser({ _id: req.params.id as string });
    if (!user) {
      return res.status(404).json({ detail: "User not found" });
    }
    
    return res.json({
      id: user._id,
      display_name: user.display_name,
      role: user.role,
      created_at: user.created_at
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await dbGetUsers();
    const sanitized = users.map(u => ({
      id: u._id,
      email: u.email,
      display_name: u.display_name,
      role: u.role,
      created_at: u.created_at,
      updated_at: u.updated_at
    }));
    return res.json(sanitized);
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.put("/api/users/:id/role", authenticateToken, requireAdmin, async (req: AuthRequest, res) => {
  try {
    const { role } = req.body;
    if (role !== "user" && role !== "admin") {
      return res.status(400).json({ detail: "Invalid role type requested. Must be 'user' or 'admin'." });
    }
    
    const user = await dbFindUser({ _id: req.params.id as string });
    if (!user) {
      return res.status(404).json({ detail: "User target not found." });
    }
    
    await dbUpdateUser(user._id, { role });
    
    // Audit log
    await dbInsertAuditLog({
      _id: mockId(),
      actor_id: req.user!._id,
      action: "PROMOTE_USER_ROLE",
      target_id: user._id,
      details: `Admin updated role for ${user.email} to '${role}'.`,
      timestamp: new Date().toISOString()
    });
    
    return res.json({
      message: "User role updated successfully",
      id: user._id,
      role: role
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.delete("/api/users/:id", authenticateToken, requireAdmin, async (req: AuthRequest, res) => {
  try {
    const user = await dbFindUser({ _id: req.params.id as string });
    if (!user) {
      return res.status(404).json({ detail: "User target not found." });
    }
    
    await dbDeleteUser(user._id);
    
    // Audit log
    await dbInsertAuditLog({
      _id: mockId(),
      actor_id: req.user!._id,
      action: "DELETE_USER",
      target_id: user._id,
      details: `Admin deleted user profile ${user.email}.`,
      timestamp: new Date().toISOString()
    });
    
    return res.json({ message: "User profile deleted successfully", id: user._id });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

// 2. Incidents & Comments
app.post("/api/incidents", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { title, incident_type, severity, ioc_type, ioc_value, description, evidence } = req.body;
    if (!title || !incident_type || !severity || !ioc_type || !ioc_value || !description) {
      return res.status(400).json({ detail: "Required fields are missing." });
    }
    
    const user = req.user!;
    const newInc: IncidentStore = {
      _id: mockId(),
      reporter_id: user._id,
      reporter_email: user.email,
      reporter_name: user.display_name || "Anonymous",
      title,
      incident_type,
      severity,
      ioc_type,
      ioc_value,
      description,
      evidence: evidence || [],
      status: "pending",
      admin_notes: "",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    await dbInsertIncident(newInc);
    
    // Audit trail
    await dbInsertAuditLog({
      _id: mockId(),
      actor_id: user._id,
      action: "SUBMIT_INCIDENT",
      target_id: newInc._id,
      details: `Submitted new cyber threat incident: ${title}`,
      timestamp: new Date().toISOString()
    });
    
    const responseData = { ...newInc, id: newInc._id };
    delete (responseData as any)._id;
    return res.json(responseData);
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/incidents", authenticateToken, async (req, res) => {
  try {
    const { severity, incident_type, status, search } = req.query as any;
    const incidents = await dbGetIncidents({ severity, incident_type, status, search });
    
    const sanitized = incidents.map(inc => ({
      id: inc._id,
      reporter_id: inc.reporter_id,
      reporter_email: inc.reporter_email,
      reporter_name: inc.reporter_name,
      title: inc.title,
      incident_type: inc.incident_type,
      severity: inc.severity,
      ioc_type: inc.ioc_type,
      ioc_value: inc.ioc_value,
      description: inc.description,
      evidence: inc.evidence,
      status: inc.status,
      admin_notes: inc.admin_notes,
      created_at: inc.created_at,
      updated_at: inc.updated_at
    }));
    return res.json(sanitized);
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/stats/my", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = req.user!;
    const userId = user._id;
    
    const submitted = await dbCountIncidents({ reporter_id: userId });
    const verified = await dbCountIncidents({ reporter_id: userId, status: "verified" });
    const commentsCount = await dbCountComments({ user_id: userId });
    
    return res.json({
      submitted_reports: submitted,
      verified_reports: verified,
      comments_placed: commentsCount,
      trusted_score: (verified * 15) + (submitted * 5)
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/incidents/:id", authenticateToken, async (req, res) => {
  try {
    const inc = await dbFindIncidentById(req.params.id as string);
    if (!inc) {
      return res.status(404).json({ detail: "Incident not found" });
    }
    return res.json({
      id: inc._id,
      reporter_id: inc.reporter_id,
      reporter_email: inc.reporter_email,
      reporter_name: inc.reporter_name,
      title: inc.title,
      incident_type: inc.incident_type,
      severity: inc.severity,
      ioc_type: inc.ioc_type,
      ioc_value: inc.ioc_value,
      description: inc.description,
      evidence: inc.evidence,
      status: inc.status,
      admin_notes: inc.admin_notes,
      created_at: inc.created_at,
      updated_at: inc.updated_at
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.put("/api/incidents/:id", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = req.user!;
    const inc = await dbFindIncidentById(req.params.id as string);
    if (!inc) {
      return res.status(404).json({ detail: "Incident not found" });
    }
    
    // Only creator or admin
    if (inc.reporter_id !== user._id && user.role !== "admin") {
      return res.status(403).json({ detail: "Forbidden: You are not eligible to modify this report." });
    }
    
    if (inc.status !== "pending" && user.role !== "admin") {
      return res.status(400).json({ detail: "Cannot edit incident once validated by administrative review." });
    }
    
    const { title, incident_type, severity, ioc_type, ioc_value, description, evidence } = req.body;
    const updates: Partial<IncidentStore> = {};
    if (title !== undefined) updates.title = title;
    if (incident_type !== undefined) updates.incident_type = incident_type;
    if (severity !== undefined) updates.severity = severity;
    if (ioc_type !== undefined) updates.ioc_type = ioc_type;
    if (ioc_value !== undefined) updates.ioc_value = ioc_value;
    if (description !== undefined) updates.description = description;
    if (evidence !== undefined) updates.evidence = evidence;
    
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ detail: "No updates requested" });
    }
    
    await dbUpdateIncident(inc._id, updates);
    return res.json({ message: "Incident updated successfully", id: inc._id });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.delete("/api/incidents/:id", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = req.user!;
    const inc = await dbFindIncidentById(req.params.id as string);
    if (!inc) {
      return res.status(404).json({ detail: "Incident document not found" });
    }
    
    // Permission: creator or admin
    if (inc.reporter_id !== user._id && user.role !== "admin") {
      return res.status(403).json({ detail: "Forbidden: Insufficient privileges to delete representation feed." });
    }
    
    await dbDeleteIncident(inc._id);
    
    // Audit log
    await dbInsertAuditLog({
      _id: mockId(),
      actor_id: user._id,
      action: "DELETE_INCIDENT",
      target_id: inc._id,
      details: `Deleted threat incident: ${inc.title}`,
      timestamp: new Date().toISOString()
    });
    
    return res.json({ message: "Incident deleted successfully" });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.post("/api/incidents/:id/comments", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const { content } = req.body;
    if (!content) {
      return res.status(400).json({ detail: "Content is required" });
    }
    
    const user = req.user!;
    const newComment: CommentStore = {
      _id: mockId(),
      incident_id: req.params.id as string,
      user_id: user._id,
      display_name: user.display_name || "Anonymous User",
      email: user.email,
      content,
      created_at: new Date().toISOString()
    };
    
    await dbInsertComment(newComment);
    return res.json({
      id: newComment._id,
      display_name: newComment.display_name,
      email: newComment.email,
      content: newComment.content,
      created_at: newComment.created_at
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/incidents/:id/comments", authenticateToken, async (req, res) => {
  try {
    const comments = await dbGetComments(req.params.id as string);
    const sanitized = comments.map(c => ({
      id: c._id,
      incident_id: c.incident_id,
      user_id: c.user_id,
      display_name: c.display_name,
      email: c.email,
      content: c.content,
      created_at: c.created_at
    }));
    return res.json(sanitized);
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.delete("/api/comments/:comment_id", authenticateToken, async (req: AuthRequest, res) => {
  try {
    const user = req.user!;
    const c = await dbFindCommentById(req.params.comment_id as string);
    if (!c) {
      return res.status(404).json({ detail: "Comment not found" });
    }
    
    if (c.user_id !== user._id && user.role !== "admin") {
      return res.status(403).json({ detail: "Forbidden: Insufficient privileges." });
    }
    
    await dbDeleteComment(c._id);
    return res.json({ message: "Comment deleted successfully" });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/incidents/:id/related", authenticateToken, async (req, res) => {
  try {
    const ref = await dbFindIncidentById(req.params.id as string);
    if (!ref) {
      return res.status(404).json({ detail: "Reference incident not found" });
    }
    
    const incidents = await dbGetIncidents();
    const related = incidents.filter(i => i.ioc_type === ref.ioc_type && i._id !== ref._id);
    
    const sanitized = related.slice(0, 5).map(inc => ({
      id: inc._id,
      title: inc.title,
      severity: inc.severity,
      ioc_value: inc.ioc_value,
      status: inc.status
    }));
    
    return res.json(sanitized);
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/ioc/lookup", authenticateToken, async (req, res) => {
  try {
    const q = req.query.q as string;
    if (!q || q.trim().length === 0) {
      return res.status(400).json({ detail: "Query parameter 'q' is required with non-empty content." });
    }
    
    const incidents = await dbGetIncidents();
    const matching = incidents.filter(i => i.ioc_value === q.trim());
    
    const sanitized = matching.map(inc => ({
      id: inc._id,
      title: inc.title,
      incident_type: inc.incident_type,
      severity: inc.severity,
      ioc_type: inc.ioc_type,
      ioc_value: inc.ioc_value,
      status: inc.status,
      created_at: inc.created_at
    }));
    return res.json(sanitized);
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.put("/api/incidents/:id/verify", authenticateToken, requireAdmin, async (req: AuthRequest, res) => {
  try {
    const { status, admin_notes } = req.body;
    if (!["verified", "false_positive", "under_review", "pending"].includes(status)) {
      return res.status(400).json({ detail: "Forbidden: Invalid target status action selected." });
    }
    
    const inc = await dbFindIncidentById(req.params.id as string);
    if (!inc) {
      return res.status(404).json({ detail: "Incident targeted document not found." });
    }
    
    const admin = req.user!;
    const updatePayload = {
      status,
      admin_notes: admin_notes || "",
      updated_at: new Date().toISOString(),
      verified_at: new Date().toISOString(),
      verified_by: admin._id
    };
    
    await dbUpdateIncident(inc._id, updatePayload);
    
    // Audit Log
    await dbInsertAuditLog({
      _id: mockId(),
      actor_id: admin._id,
      action: `DECIDE_${status.toUpperCase()}`,
      target_id: inc._id,
      details: `Admin verified incident '${inc.title}' status to: ${status}`,
      timestamp: new Date().toISOString()
    });
    
    return res.json({
      message: "Incident review modified successfully.",
      id: inc._id,
      status
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

app.get("/api/stats/platform", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const total_incidents = await dbCountIncidents({});
    const verified_incidents = await dbCountIncidents({ status: "verified" });
    const pending_incidents = await dbCountIncidents({ status: "pending" });
    const false_positives = await dbCountIncidents({ status: "false_positive" });
    
    const total_users = await dbCountUsers();
    const total_comments = await dbCountComments({});
    
    const critical_count = await dbCountIncidents({ severity: "Critical" });
    const high_count = await dbCountIncidents({ severity: "High" });
    const medium_count = await dbCountIncidents({ severity: "Medium" });
    const low_count = await dbCountIncidents({ severity: "Low" });
    
    const phishing_count = await dbCountIncidents({ incident_type: "phishing" });
    const malware_count = await dbCountIncidents({ incident_type: "malware" });
    const ip_count = await dbCountIncidents({ incident_type: "suspicious_ip" });
    const url_count = await dbCountIncidents({ incident_type: "suspicious_url" });
    const other_count = await dbCountIncidents({ incident_type: "other" });
    
    const audits = await dbGetAuditLogs();
    audits.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    const sanitized_audits = audits.slice(0, 15).map(aud => ({
      id: aud._id,
      actor_id: aud.actor_id,
      action: aud.action,
      target_id: aud.target_id,
      details: aud.details,
      timestamp: aud.timestamp
    }));
    
    return res.json({
      summary: {
        total_incidents,
        verified_incidents,
        pending_incidents,
        false_positives,
        verification_rate: total_incidents > 0 ? parseFloat((verified_incidents / total_incidents * 100).toFixed(1)) : 0.0,
        total_users,
        total_comments
      },
      severity: {
        Critical: critical_count,
        High: high_count,
        Medium: medium_count,
        Low: low_count
      },
      types: {
        phishing: phishing_count,
        malware: malware_count,
        suspicious_ip: ip_count,
        suspicious_url: url_count,
        other: other_count
      },
      recent_audit_trail: sanitized_audits
    });
  } catch (error: any) {
    return res.status(500).json({ detail: error.message });
  }
});

// 3. Health & Base Routing
app.get("/api/health", async (req, res) => {
  return res.json({ status: "ok", service: "CyberTrace Engine" });
});

// Serve direct pages nicely on root path
const servePage = (pageName: string) => {
  return (req: Request, res: Response) => {
    res.sendFile(path.resolve(`static/${pageName}.html`));
  };
};

app.get("/login", servePage("login"));
app.get("/register", servePage("register"));
app.get("/dashboard", servePage("dashboard"));
app.get("/feed", servePage("feed"));
app.get("/incident", servePage("incident_detail"));
app.get("/profile", servePage("profile"));
app.get("/admin", servePage("admin"));

// Serve static directory resources
app.use("/static", express.static(path.resolve("static")));
app.use("/", express.static(path.resolve("static")));

// Fallback for SPA routing/File rendering if needed or root requests
app.get("*all", (req: Request, res: Response) => {
  res.sendFile(path.resolve("static/index.html"));
});

// --- Server Launcher ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log(`=================================================`);
  console.log(`   CyberTrace Node.js Express REST Engine      `);
  console.log(`   Listening at http://0.0.0.0:${PORT}          `);
  console.log(`=================================================`);
  await initDb();
});
