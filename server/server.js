const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 10000;

// In-memory upload handling for cargo photos — 5MB cap, images only.
const IMAGE_BUCKET = process.env.SUPABASE_IMAGE_BUCKET || 'shipment-images';
const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (!ALLOWED_IMAGE_TYPES.has(file.mimetype)) return cb(new Error('UNSUPPORTED_TYPE'));
        cb(null, true);
    }
});

// Secure admin key — MUST be set as env var on Render. No fallback.
const SECURE_ADMIN_KEY = process.env.ADMIN_KEY;
if (!SECURE_ADMIN_KEY) {
    console.error("[FATAL] ADMIN_KEY environment variable is not set. Server will not start.");
    process.exit(1);
}

// Supabase setup
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
let supabase = null;
if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    console.warn("[WARNING] SUPABASE_URL or SUPABASE_ANON_KEY missing. All DB routes will return 503.");
} else {
    supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    console.log("[INFO] Supabase client ready.");
}

// Session store: token (UUID) -> { expiresAt }
const SESSION_TTL_MS = 30 * 60 * 1000;
const activeSessions = new Map();

// Rate limiting: ip -> { count, resetAt }
const AUTH_MAX_ATTEMPTS = 10;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const authRateMap = new Map();

// Cleanup expired sessions and rate limit windows every 5 min
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of activeSessions.entries()) { if (now > v.expiresAt) activeSessions.delete(k); }
    for (const [k, v] of authRateMap.entries()) { if (now > v.resetAt) authRateMap.delete(k); }
}, 5 * 60 * 1000);

// CORS — allow logiswift.delivery, GitHub Pages, Render previews
const ALLOWED_ORIGINS = [
    'https://logiswift.delivery',
    'https://www.logiswift.delivery',
];
app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        const ok = ALLOWED_ORIGINS.includes(origin)
            || /\.github\.io$/.test(origin)
            || /\.onrender\.com$/.test(origin)
            || /^https?:\/\/localhost(:\d+)?$/.test(origin);
        cb(ok ? null : new Error('CORS: origin not allowed.'), ok);
    },
    credentials: true
}));
app.use(express.json());

// Middleware: require database
const requireDb = (req, res, next) => {
    if (!supabase) return res.status(503).json({ message: "Database not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY on Render." });
    next();
};

// Middleware: require valid session token (UUID, not the raw password)
const authenticateAdmin = (req, res, next) => {
    const token = req.headers['x-admin-token'];
    if (!token) return res.status(401).json({ message: "Missing x-admin-token header." });
    const session = activeSessions.get(token);
    if (!session || Date.now() > session.expiresAt) {
        activeSessions.delete(token);
        return res.status(401).json({ message: "Session expired or invalid. Please log in again." });
    }
    session.expiresAt = Date.now() + SESSION_TTL_MS; // sliding expiry
    next();
};

// ── Health check ─────────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        status: 'online',
        db: supabase ? 'connected' : 'disconnected',
        sessions: activeSessions.size,
        timestamp: new Date().toISOString()
    });
});

// ── Admin: Login ──────────────────────────────────────────────
app.post('/api/admin/verify', (req, res) => {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
    const now = Date.now();

    let rate = authRateMap.get(ip);
    if (!rate || now > rate.resetAt) { rate = { count: 0, resetAt: now + AUTH_WINDOW_MS }; authRateMap.set(ip, rate); }
    if (rate.count >= AUTH_MAX_ATTEMPTS) return res.status(429).json({ message: "Too many attempts. Try again in 15 minutes." });

    const { password } = req.body;
    if (password === SECURE_ADMIN_KEY) {
        rate.count = 0;
        const token = crypto.randomUUID();
        activeSessions.set(token, { expiresAt: now + SESSION_TTL_MS });
        return res.status(200).json({ success: true, token, expiresIn: SESSION_TTL_MS });
    }
    rate.count++;
    res.status(401).json({ success: false, message: "Invalid passkey credentials.", attemptsLeft: AUTH_MAX_ATTEMPTS - rate.count });
});

// ── Admin: Logout ─────────────────────────────────────────────
app.post('/api/admin/logout', authenticateAdmin, (req, res) => {
    activeSessions.delete(req.headers['x-admin-token']);
    res.json({ success: true });
});

// ── Admin: Session refresh ────────────────────────────────────
app.post('/api/admin/refresh', authenticateAdmin, (req, res) => {
    const session = activeSessions.get(req.headers['x-admin-token']);
    res.json({ success: true, expiresAt: session.expiresAt, expiresIn: SESSION_TTL_MS });
});

// ── Public: Stats ─────────────────────────────────────────────
app.get('/api/stats', requireDb, async (req, res) => {
    try {
        const { data, error } = await supabase.from('shipments').select('status, weight');
        if (error) throw error;
        res.json({
            total: data.length,
            delivered: data.filter(s => s.status === 'Delivered').length,
            inTransit: data.filter(s => s.status === 'In Transit').length,
            pending: data.filter(s => !['Delivered', 'In Transit'].includes(s.status)).length,
            totalWeightKg: parseFloat(data.reduce((a, c) => a + (parseFloat(c.weight) || 0), 0).toFixed(2)),
        });
    } catch (err) {
        res.status(500).json({ message: "Stats query error.", error: err.message });
    }
});

// ── Public: Get all shipments (with optional filtering) ───────
app.get('/api/shipments', requireDb, async (req, res) => {
    try {
        let query = supabase.from('shipments').select('*').order('created_at', { ascending: false });
        if (req.query.status && req.query.status !== 'ALL') query = query.eq('status', req.query.status);
        if (req.query.search) {
            // Escape % and _ so a user can't widen the match beyond what they typed.
            const term = req.query.search.toUpperCase().replace(/[%_]/g, m => `\\${m}`);
            query = query.ilike('shipmentId', `%${term}%`);
        }
        if (req.query.limit) query = query.limit(parseInt(req.query.limit) || 100);
        const { data, error } = await query;
        if (error) throw error;
        res.status(200).json(data || []);
    } catch (err) {
        res.status(500).json({ message: "Database read error.", error: err.message });
    }
});

// ── Public: Track single shipment ────────────────────────────
app.get('/api/shipments/:id', requireDb, async (req, res) => {
    // Case-insensitive match: tolerates rows whose shipmentId wasn't stored
    // in uppercase (e.g. inserted directly via the Supabase dashboard).
    const targetId = req.params.id.trim().replace(/[%_]/g, m => `\\${m}`);
    try {
        const { data, error } = await supabase.from('shipments').select('*').ilike('shipmentId', targetId).maybeSingle();
        if (error || !data) return res.status(404).json({ message: "Shipment not found in registry." });
        res.status(200).json(data);
    } catch (err) {
        res.status(500).json({ message: "Tracking lookup error." });
    }
});

// ── Protected: Create shipment ────────────────────────────────
app.post('/api/shipments', authenticateAdmin, requireDb, async (req, res) => {
    const { shipmentId, sender, receiver, weight, status, location, eta, imageUrl, notes } = req.body;
    if (!shipmentId || !sender || !receiver || weight == null || !status || !location) {
        return res.status(400).json({ message: "Missing required fields: shipmentId, sender, receiver, weight, status, location." });
    }
    try {
        const { data, error } = await supabase.from('shipments').insert([{
            shipmentId: shipmentId.trim().toUpperCase(),
            sender: sender.trim(), receiver: receiver.trim(),
            weight: parseFloat(weight), status: status.trim(), location: location.trim(),
            eta: eta?.trim() || "", imageUrl: imageUrl?.trim() || "", notes: notes?.trim() || ""
        }]).select();
        if (error) throw error;
        res.status(201).json(data[0]);
    } catch (err) {
        // Postgres error codes: 23505 = unique_violation, 23502 = not_null_violation,
        // 42501 = insufficient_privilege (RLS). Surface the real cause instead of
        // always assuming a duplicate ID.
        let message = "Error saving shipment.";
        if (err.code === '23505') message = "A shipment with this ID already exists.";
        else if (err.code === '23502') message = "A required database field was left empty.";
        else if (err.code === '42501') message = "Database permission denied (row-level security policy blocked this write).";
        else if (err.message) message = err.message;
        res.status(400).json({ message, error: err.message, code: err.code || null });
    }
});

// ── Protected: Update shipment ────────────────────────────────
app.put('/api/shipments/:id', authenticateAdmin, requireDb, async (req, res) => {
    const targetId = req.params.id.trim().replace(/[%_]/g, m => `\\${m}`);
    const { sender, receiver, weight, status, location, eta, imageUrl, notes } = req.body;
    try {
        const updates = {};
        // Use ?. so a null (rather than omitted) field can't crash the request
        // with an uncaught TypeError outside our error handling.
        if (sender !== undefined) updates.sender = sender?.trim() ?? '';
        if (receiver !== undefined) updates.receiver = receiver?.trim() ?? '';
        if (weight !== undefined) {
            const w = parseFloat(weight);
            if (Number.isNaN(w)) return res.status(400).json({ message: "Weight must be a valid number." });
            updates.weight = w;
        }
        if (status !== undefined) updates.status = status?.trim() ?? '';
        if (location !== undefined) updates.location = location?.trim() ?? '';
        if (eta !== undefined) updates.eta = eta?.trim() ?? '';
        if (imageUrl !== undefined) updates.imageUrl = imageUrl?.trim() ?? '';
        if (notes !== undefined) updates.notes = notes?.trim() ?? '';

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: "No valid fields provided to update." });
        }

        const { data, error } = await supabase.from('shipments').update(updates).ilike('shipmentId', targetId).select();
        if (error || !data || data.length === 0) return res.status(404).json({ message: "No record found to update." });
        res.status(200).json(data[0]);
    } catch (err) {
        res.status(500).json({ message: "Update error.", error: err.message });
    }
});

// ── Protected: Delete shipment ────────────────────────────────
app.delete('/api/shipments/:id', authenticateAdmin, requireDb, async (req, res) => {
    const targetId = req.params.id.trim().replace(/[%_]/g, m => `\\${m}`);
    try {
        const { data, error } = await supabase.from('shipments').delete().ilike('shipmentId', targetId).select();
        if (error || !data || data.length === 0) return res.status(404).json({ message: "No record found to delete." });
        res.status(200).json({ message: "Shipment purged from registry." });
    } catch (err) {
        res.status(500).json({ message: "Delete error.", error: err.message });
    }
});

// ── Protected: Upload cargo image ──────────────────────────────
// Accepts multipart/form-data with a single "image" field, stores it in
// Supabase Storage, and returns the public URL to save on a shipment.
app.post('/api/upload-image', authenticateAdmin, requireDb, (req, res) => {
    upload.single('image')(req, res, async (err) => {
        if (err) {
            const message = err.message === 'UNSUPPORTED_TYPE'
                ? 'Unsupported file type. Use JPEG, PNG, WEBP, or GIF.'
                : err.code === 'LIMIT_FILE_SIZE'
                    ? 'Image exceeds the 5MB limit.'
                    : 'Upload error.';
            return res.status(400).json({ message });
        }
        if (!req.file) return res.status(400).json({ message: 'No image file provided.' });
        try {
            const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '') || 'jpg';
            const path = `${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}.${ext}`;
            const { error: uploadError } = await supabase.storage
                .from(IMAGE_BUCKET)
                .upload(path, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
            if (uploadError) throw uploadError;
            const { data: publicData } = supabase.storage.from(IMAGE_BUCKET).getPublicUrl(path);
            res.status(201).json({ url: publicData.publicUrl });
        } catch (uploadErr) {
            res.status(500).json({ message: 'Image storage error. Confirm the storage bucket exists and is public.', error: uploadErr.message });
        }
    });
});

app.get('/', (req, res) => res.json({ service: "LogiSwift API", version: "2.0", status: "online" }));
app.listen(PORT, () => console.log(`[INFO] LogiSwift API running on port ${PORT}`));
