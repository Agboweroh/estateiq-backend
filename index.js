require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { parse } = require("csv-parse/sync");
const { v4: uuid } = require("uuid");

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const JWT_SECRET =
	process.env.JWT_SECRET || "estateiq-secret-change-in-production";

app.use(
	cors({
		origin: [
			process.env.CLIENT_URL || "http://localhost:5173",
			/\.vercel\.app$/,
			/localhost/,
		],
		credentials: true,
	}),
);
app.use(express.json());

// ── DB POOL ───────────────────────────────────────────────────────────────────
let pool;
async function db() {
	if (!pool) {
		pool = mysql.createPool(
			process.env.DATABASE_URL
				? {
						uri: process.env.DATABASE_URL,
						waitForConnections: true,
						connectionLimit: 10,
					}
				: {
						host: process.env.DB_HOST || "localhost",
						port: +process.env.DB_PORT || 3306,
						user: process.env.DB_USER || "root",
						password: process.env.DB_PASSWORD || "",
						database: process.env.DB_NAME || "estateiq",
						waitForConnections: true,
						connectionLimit: 10,
					},
		);
	}
	return pool;
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function auth(roles = []) {
	return (req, res, next) => {
		const token = req.headers.authorization?.split(" ")[1];
		if (!token) return res.status(401).json({ error: "No token" });
		try {
			const decoded = jwt.verify(token, JWT_SECRET);
			if (roles.length && !roles.includes(decoded.role))
				return res.status(403).json({ error: "Forbidden" });
			req.user = decoded;
			next();
		} catch {
			res.status(401).json({ error: "Invalid token" });
		}
	};
}

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "EstateIQ API v2 ✓" }));
app.get("/api/health", async (req, res) => {
	try {
		await (await db()).query("SELECT 1");
		res.json({ status: "ok", db: "connected", version: "2.0.0" });
	} catch (e) {
		res.status(500).json({ status: "error", db: e.message });
	}
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
	try {
		const { email, password } = req.body;
		if (!email || !password)
			return res.status(400).json({ error: "Email and password required" });
		const d = await db();
		const [[user]] = await d.query(
			"SELECT * FROM users WHERE email = ? AND is_active = 1",
			[email],
		);
		if (!user) return res.status(401).json({ error: "Invalid credentials" });
		const valid = await bcrypt.compare(password, user.password_hash);
		if (!valid) return res.status(401).json({ error: "Invalid credentials" });
		await d.query("UPDATE users SET last_login = NOW() WHERE id = ?", [
			user.id,
		]);
		const token = jwt.sign(
			{ id: user.id, name: user.name, email: user.email, role: user.role },
			JWT_SECRET,
			{ expiresIn: "7d" },
		);
		res.json({
			token,
			user: {
				id: user.id,
				name: user.name,
				email: user.email,
				role: user.role,
				phone: user.phone,
			},
		});
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.post("/api/auth/register", auth(["admin"]), async (req, res) => {
	try {
		const { name, email, password, role, phone } = req.body;
		if (!name || !email || !password)
			return res.status(400).json({ error: "name, email, password required" });
		const hash = await bcrypt.hash(password, 10);
		const id = uuid();
		const d = await db();
		await d.query(
			"INSERT INTO users (id,name,email,phone,password_hash,role) VALUES (?,?,?,?,?,?)",
			[id, name, email, phone || "", hash, role || "staff"],
		);
		const [[u]] = await d.query(
			"SELECT id,name,email,role,phone FROM users WHERE id=?",
			[id],
		);
		res.status(201).json(u);
	} catch (e) {
		if (e.code === "ER_DUP_ENTRY")
			return res.status(400).json({ error: "Email already exists" });
		res.status(500).json({ error: e.message });
	}
});

app.get("/api/auth/me", auth(), async (req, res) => {
	try {
		const [[u]] = await (
			await db()
		).query("SELECT id,name,email,role,phone FROM users WHERE id=?", [
			req.user.id,
		]);
		res.json(u);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.put("/api/auth/me", auth(), async (req, res) => {
	try {
		const { name, phone } = req.body;
		await (
			await db()
		).query("UPDATE users SET name=?,phone=? WHERE id=?", [
			name,
			phone,
			req.user.id,
		]);
		res.json({ success: true });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.put("/api/auth/change-password", auth(), async (req, res) => {
	try {
		const { currentPassword, newPassword } = req.body;
		const d = await db();
		const [[u]] = await d.query("SELECT password_hash FROM users WHERE id=?", [
			req.user.id,
		]);
		const valid = await bcrypt.compare(currentPassword, u.password_hash);
		if (!valid)
			return res.status(400).json({ error: "Current password incorrect" });
		const hash = await bcrypt.hash(newPassword, 10);
		await d.query("UPDATE users SET password_hash=? WHERE id=?", [
			hash,
			req.user.id,
		]);
		res.json({ success: true });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// ── USERS ────────────────────────────────────────────────────────────────────
app.get("/api/users", auth(["admin", "manager"]), async (req, res) => {
	try {
		const [rows] = await (
			await db()
		).query(
			"SELECT id,name,email,role,phone,is_active,last_login,created_at FROM users ORDER BY created_at",
		);
		res.json(rows);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.put("/api/users/:id", auth(["admin"]), async (req, res) => {
	try {
		const { name, email, role, phone, is_active } = req.body;
		await (
			await db()
		).query(
			"UPDATE users SET name=?,email=?,role=?,phone=?,is_active=? WHERE id=?",
			[name, email, role, phone, is_active ? 1 : 0, req.params.id],
		);
		res.json({ success: true });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.delete("/api/users/:id", auth(["admin"]), async (req, res) => {
	try {
		if (req.params.id === "admin-001")
			return res.status(403).json({ error: "Cannot delete primary admin" });
		await (await db()).query("DELETE FROM users WHERE id=?", [req.params.id]);
		res.json({ success: true });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// ─────────────────────────────────────────────────────────────────────────────
// TENANTS
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/tenants", auth(), async (req, res) => {
	try {
		const { search, status } = req.query;
		let sql = "SELECT * FROM tenants WHERE 1=1";
		const p = [];
		if (search) {
			sql +=
				" AND (tenant_name LIKE ? OR accommodation_type LIKE ? OR property_address LIKE ? OR email LIKE ?)";
			const l = `%${search}%`;
			p.push(l, l, l, l);
		}
		if (status === "paid")
			sql += " AND amount_paid >= rent_per_annum AND rent_per_annum > 0";
		else if (status === "partial")
			sql += " AND amount_paid > 0 AND amount_paid < rent_per_annum";
		else if (status === "unpaid") sql += " AND amount_paid = 0";
		else if (status === "quit") sql += " AND quit_notice = 1";
		else if (status === "expiring")
			sql +=
				" AND lease_end BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)";
		sql += " ORDER BY sn ASC";
		const [rows] = await (await db()).query(sql, p);
		res.json(rows);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.get("/api/tenants/:id", auth(), async (req, res) => {
	try {
		const d = await db();
		const [[t]] = await d.query("SELECT * FROM tenants WHERE id=?", [
			req.params.id,
		]);
		if (!t) return res.status(404).json({ error: "Not found" });
		const [payments] = await d.query(
			"SELECT * FROM payments WHERE tenant_id=? ORDER BY payment_date DESC",
			[req.params.id],
		);
		const [maintenance] = await d.query(
			"SELECT * FROM maintenance WHERE tenant_id=? ORDER BY created_at DESC",
			[req.params.id],
		);
		res.json({ ...t, payments, maintenance });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.post("/api/tenants", auth(), async (req, res) => {
	try {
		const {
			tenant_name,
			accommodation_type,
			property_address,
			period,
			lease_start,
			lease_end,
			rent_per_annum,
			amount_paid,
			phone,
			email,
			whatsapp,
			notes,
			quit_notice,
		} = req.body;
		if (!tenant_name)
			return res.status(400).json({ error: "tenant_name required" });
		const id = uuid();
		await (
			await db()
		).query(
			`INSERT INTO tenants (id,tenant_name,accommodation_type,property_address,period,lease_start,lease_end,rent_per_annum,amount_paid,phone,email,whatsapp,notes,quit_notice,created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			[
				id,
				tenant_name,
				accommodation_type || "",
				property_address || "",
				period || "",
				lease_start || null,
				lease_end || null,
				rent_per_annum || 0,
				amount_paid || 0,
				phone || "",
				email || "",
				whatsapp || "",
				notes || "",
				quit_notice ? 1 : 0,
				req.user.id,
			],
		);
		const [[row]] = await (
			await db()
		).query("SELECT * FROM tenants WHERE id=?", [id]);
		res.status(201).json(row);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.put("/api/tenants/:id", auth(), async (req, res) => {
	try {
		const {
			tenant_name,
			accommodation_type,
			property_address,
			period,
			lease_start,
			lease_end,
			rent_per_annum,
			amount_paid,
			phone,
			email,
			whatsapp,
			notes,
			quit_notice,
		} = req.body;
		await (
			await db()
		).query(
			`UPDATE tenants SET tenant_name=?,accommodation_type=?,property_address=?,period=?,
       lease_start=?,lease_end=?,rent_per_annum=?,amount_paid=?,phone=?,email=?,whatsapp=?,notes=?,quit_notice=? WHERE id=?`,
			[
				tenant_name,
				accommodation_type,
				property_address,
				period,
				lease_start || null,
				lease_end || null,
				rent_per_annum || 0,
				amount_paid || 0,
				phone,
				email,
				whatsapp,
				notes,
				quit_notice ? 1 : 0,
				req.params.id,
			],
		);
		const [[row]] = await (
			await db()
		).query("SELECT * FROM tenants WHERE id=?", [req.params.id]);
		res.json(row);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.patch("/api/tenants/:id/payment", auth(), async (req, res) => {
	try {
		const { amount_paid } = req.body;
		await (
			await db()
		).query("UPDATE tenants SET amount_paid=? WHERE id=?", [
			amount_paid || 0,
			req.params.id,
		]);
		const [[row]] = await (
			await db()
		).query("SELECT * FROM tenants WHERE id=?", [req.params.id]);
		res.json(row);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.patch("/api/tenants/:id/quit", auth(), async (req, res) => {
	try {
		const { quit_notice } = req.body;
		await (
			await db()
		).query("UPDATE tenants SET quit_notice=?,quit_notice_date=? WHERE id=?", [
			quit_notice ? 1 : 0,
			quit_notice ? new Date().toISOString().split("T")[0] : null,
			req.params.id,
		]);
		const [[row]] = await (
			await db()
		).query("SELECT * FROM tenants WHERE id=?", [req.params.id]);
		res.json(row);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.delete("/api/tenants/:id", auth(["admin", "manager"]), async (req, res) => {
	try {
		await (await db()).query("DELETE FROM tenants WHERE id=?", [req.params.id]);
		res.json({ success: true });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// CSV Import
app.post(
	"/api/tenants/import",
	auth(),
	upload.single("file"),
	async (req, res) => {
		try {
			if (!req.file) return res.status(400).json({ error: "No file" });
			const records = parse(req.file.buffer.toString("utf8"), {
				columns: true,
				skip_empty_lines: true,
				trim: true,
			});
			const d = await db();
			const inserted = [];
			for (const row of records) {
				const g = (keys) => {
					for (const k of keys) {
						const f = Object.keys(row).find(
							(rk) =>
								rk.toLowerCase().replace(/[\s_]/g, "") ===
								k.toLowerCase().replace(/[\s_]/g, ""),
						);
						if (f && row[f]) return row[f];
					}
					return "";
				};
				const name = g(["nameoftenant", "tenant", "name"]);
				if (!name) continue;
				const id = uuid();
				await d.query(
					`INSERT INTO tenants (id,tenant_name,accommodation_type,property_address,period,rent_per_annum,amount_paid,phone,email,notes,quit_notice,created_by)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
					[
						id,
						name,
						g(["typeofaccommodation", "type", "accommodation"]),
						g(["property", "address", "block"]),
						g(["period"]),
						parseFloat(g(["rentperannum", "rent"]).replace(/[^0-9.]/g, "")) ||
							0,
						parseFloat(g(["amountpaid", "paid"]).replace(/[^0-9.]/g, "")) || 0,
						g(["phone", "mobile"]),
						g(["email"]),
						g(["notes", "remarks"]),
						g(["quitnotice", "quit"]).toLowerCase() === "yes" ? 1 : 0,
						req.user.id,
					],
				);
				const [[r]] = await d.query("SELECT * FROM tenants WHERE id=?", [id]);
				inserted.push(r);
			}
			res.json({ imported: inserted.length, tenants: inserted });
		} catch (e) {
			res.status(500).json({ error: e.message });
		}
	},
);

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENTS
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/payments", auth(), async (req, res) => {
	try {
		const { tenant_id, from, to } = req.query;
		let sql = `SELECT p.*, t.tenant_name, t.property_address FROM payments p 
               LEFT JOIN tenants t ON p.tenant_id = t.id WHERE 1=1`;
		const params = [];
		if (tenant_id) {
			sql += " AND p.tenant_id=?";
			params.push(tenant_id);
		}
		if (from) {
			sql += " AND p.payment_date >= ?";
			params.push(from);
		}
		if (to) {
			sql += " AND p.payment_date <= ?";
			params.push(to);
		}
		sql += " ORDER BY p.payment_date DESC";
		const [rows] = await (await db()).query(sql, params);
		res.json(rows);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.post("/api/payments", auth(), async (req, res) => {
	try {
		const {
			tenant_id,
			amount,
			payment_date,
			payment_method,
			reference,
			notes,
		} = req.body;
		if (!tenant_id || !amount)
			return res.status(400).json({ error: "tenant_id and amount required" });
		const d = await db();
		const [[lastReceipt]] = await d.query(
			"SELECT receipt_number FROM payments ORDER BY created_at DESC LIMIT 1",
		);
		const lastNum = lastReceipt?.receipt_number
			? parseInt(lastReceipt.receipt_number.split("-").pop()) + 1
			: 1;
		const receipt_number = `RCP-${new Date().getFullYear()}-${String(lastNum).padStart(4, "0")}`;
		const id = uuid();
		await d.query(
			`INSERT INTO payments (id,tenant_id,amount,payment_date,payment_method,reference,notes,receipt_number,recorded_by)
       VALUES (?,?,?,?,?,?,?,?,?)`,
			[
				id,
				tenant_id,
				amount,
				payment_date || new Date().toISOString().split("T")[0],
				payment_method || "cash",
				reference || "",
				notes || "",
				receipt_number,
				req.user.id,
			],
		);
		// Update tenant amount_paid
		await d.query(
			"UPDATE tenants SET amount_paid = amount_paid + ? WHERE id=?",
			[amount, tenant_id],
		);
		const [[payment]] = await d.query(
			"SELECT p.*,t.tenant_name FROM payments p LEFT JOIN tenants t ON p.tenant_id=t.id WHERE p.id=?",
			[id],
		);
		res.status(201).json(payment);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.delete(
	"/api/payments/:id",
	auth(["admin", "manager"]),
	async (req, res) => {
		try {
			const d = await db();
			const [[p]] = await d.query("SELECT * FROM payments WHERE id=?", [
				req.params.id,
			]);
			if (!p) return res.status(404).json({ error: "Not found" });
			await d.query(
				"UPDATE tenants SET amount_paid = GREATEST(0, amount_paid - ?) WHERE id=?",
				[p.amount, p.tenant_id],
			);
			await d.query("DELETE FROM payments WHERE id=?", [req.params.id]);
			res.json({ success: true });
		} catch (e) {
			res.status(500).json({ error: e.message });
		}
	},
);

// ─────────────────────────────────────────────────────────────────────────────
// MAINTENANCE
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/maintenance", auth(), async (req, res) => {
	try {
		const { status, priority } = req.query;
		let sql =
			"SELECT m.*, u.name as assigned_name FROM maintenance m LEFT JOIN users u ON m.assigned_to=u.id WHERE 1=1";
		const p = [];
		if (status) {
			sql += " AND m.status=?";
			p.push(status);
		}
		if (priority) {
			sql += " AND m.priority=?";
			p.push(priority);
		}
		sql +=
			" ORDER BY FIELD(m.priority,'urgent','high','medium','low'), m.created_at DESC";
		const [rows] = await (await db()).query(sql, p);
		res.json(rows);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.post("/api/maintenance", auth(), async (req, res) => {
	try {
		const {
			tenant_id,
			tenant_name,
			property_address,
			category,
			title,
			description,
			priority,
		} = req.body;
		if (!title) return res.status(400).json({ error: "title required" });
		const id = uuid();
		await (
			await db()
		).query(
			`INSERT INTO maintenance (id,tenant_id,tenant_name,property_address,category,title,description,priority)
       VALUES (?,?,?,?,?,?,?,?)`,
			[
				id,
				tenant_id || null,
				tenant_name || "",
				property_address || "",
				category || "other",
				title,
				description || "",
				priority || "medium",
			],
		);
		const [[row]] = await (
			await db()
		).query("SELECT * FROM maintenance WHERE id=?", [id]);
		res.status(201).json(row);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.patch("/api/maintenance/:id", auth(), async (req, res) => {
	try {
		const { status, assigned_to, priority } = req.body;
		const resolved_at = status === "resolved" ? new Date() : null;
		await (
			await db()
		).query(
			"UPDATE maintenance SET status=?,assigned_to=?,priority=?,resolved_at=? WHERE id=?",
			[status, assigned_to || null, priority, resolved_at, req.params.id],
		);
		const [[row]] = await (
			await db()
		).query("SELECT * FROM maintenance WHERE id=?", [req.params.id]);
		res.json(row);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.delete(
	"/api/maintenance/:id",
	auth(["admin", "manager"]),
	async (req, res) => {
		try {
			await (
				await db()
			).query("DELETE FROM maintenance WHERE id=?", [req.params.id]);
			res.json({ success: true });
		} catch (e) {
			res.status(500).json({ error: e.message });
		}
	},
);

// ─────────────────────────────────────────────────────────────────────────────
// NOTIFICATIONS
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/notifications", auth(), async (req, res) => {
	try {
		const [rows] = await (
			await db()
		).query(
			"SELECT * FROM notifications WHERE user_id=? OR user_id IS NULL ORDER BY created_at DESC LIMIT 50",
			[req.user.id],
		);
		res.json(rows);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.patch("/api/notifications/:id/read", auth(), async (req, res) => {
	try {
		await (
			await db()
		).query("UPDATE notifications SET is_read=1 WHERE id=?", [req.params.id]);
		res.json({ success: true });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.patch("/api/notifications/read-all", auth(), async (req, res) => {
	try {
		await (
			await db()
		).query(
			"UPDATE notifications SET is_read=1 WHERE user_id=? OR user_id IS NULL",
			[req.user.id],
		);
		res.json({ success: true });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE LOG (WhatsApp / SMS)
// ─────────────────────────────────────────────────────────────────────────────
app.post("/api/messages/send", auth(), async (req, res) => {
	try {
		const { tenant_id, tenant_name, phone, channel, message } = req.body;
		const id = uuid();
		await (
			await db()
		).query(
			"INSERT INTO message_log (id,tenant_id,tenant_name,phone,channel,message,status,sent_by) VALUES (?,?,?,?,?,?,?,?)",
			[
				id,
				tenant_id || null,
				tenant_name || "",
				phone || "",
				channel || "whatsapp",
				message || "",
				"sent",
				req.user.id,
			],
		);

		// Generate WhatsApp link (no API key needed)
		const cleanPhone = (phone || "").replace(/\D/g, "");
		const intlPhone = cleanPhone.startsWith("0")
			? "234" + cleanPhone.slice(1)
			: cleanPhone;
		const waLink = `https://wa.me/${intlPhone}?text=${encodeURIComponent(message)}`;

		res.json({
			success: true,
			id,
			whatsapp_link: waLink,
			message: "Message logged. Use the WhatsApp link to send.",
		});
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

app.get("/api/messages", auth(), async (req, res) => {
	try {
		const [rows] = await (
			await db()
		).query("SELECT * FROM message_log ORDER BY created_at DESC LIMIT 100");
		res.json(rows);
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// Bulk reminder — sends to all tenants with outstanding balance
app.post(
	"/api/messages/bulk-reminder",
	auth(["admin", "manager"]),
	async (req, res) => {
		try {
			const { message_template } = req.body;
			const d = await db();
			const [tenants] = await d.query(
				"SELECT * FROM tenants WHERE amount_paid < rent_per_annum AND phone != ''",
			);
			const links = [];
			for (const t of tenants) {
				const owed = t.rent_per_annum - t.amount_paid;
				const msg = (
					message_template ||
					"Dear {name}, your outstanding rent balance is ₦{amount}. Please contact us. - EstateIQ"
				)
					.replace("{name}", t.tenant_name)
					.replace("{amount}", Number(owed).toLocaleString("en-NG"))
					.replace("{property}", t.property_address);
				const id = uuid();
				await d.query(
					"INSERT INTO message_log (id,tenant_id,tenant_name,phone,channel,message,status,sent_by) VALUES (?,?,?,?,?,?,?,?)",
					[
						id,
						t.id,
						t.tenant_name,
						t.phone,
						"whatsapp",
						msg,
						"sent",
						req.user.id,
					],
				);
				const clean = t.phone.replace(/\D/g, "");
				const intl = clean.startsWith("0") ? "234" + clean.slice(1) : clean;
				links.push({
					tenant: t.tenant_name,
					phone: t.phone,
					link: `https://wa.me/${intl}?text=${encodeURIComponent(msg)}`,
					amount_owed: owed,
				});
			}
			res.json({ sent: links.length, links });
		} catch (e) {
			res.status(500).json({ error: e.message });
		}
	},
);

// ─────────────────────────────────────────────────────────────────────────────
// ANALYTICS
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/stats", auth(), async (req, res) => {
	try {
		const d = await db();
		const [[summary]] = await d.query(`
      SELECT
        COUNT(*) as total_tenants,
        SUM(rent_per_annum) as total_rent,
        SUM(amount_paid) as total_paid,
        SUM(GREATEST(0, rent_per_annum - amount_paid)) as total_outstanding,
        SUM(quit_notice=1) as quit_count,
        SUM(amount_paid >= rent_per_annum AND rent_per_annum > 0) as fully_paid,
        SUM(amount_paid > 0 AND amount_paid < rent_per_annum) as partial_paid,
        SUM(amount_paid = 0) as unpaid_count,
        SUM(lease_end BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)) as expiring_soon
      FROM tenants
    `);

		// Monthly payments for chart (last 12 months)
		const [monthly] = await d.query(`
      SELECT DATE_FORMAT(payment_date,'%b %Y') as month,
             DATE_FORMAT(payment_date,'%Y-%m') as month_key,
             SUM(amount) as total
      FROM payments
      WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
      GROUP BY month_key, month ORDER BY month_key ASC
    `);

		// By accommodation type
		const [byType] = await d.query(`
      SELECT accommodation_type as type, COUNT(*) as count, SUM(rent_per_annum) as total_rent
      FROM tenants GROUP BY accommodation_type ORDER BY count DESC
    `);

		// Maintenance by status
		const [maintStats] = await d.query(`
      SELECT status, COUNT(*) as count FROM maintenance GROUP BY status
    `);

		res.json({ summary, monthly, byType, maintStats });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// ─────────────────────────────────────────────────────────────────────────────
// ALERTS — Check expiring leases & overdue rent
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/alerts", auth(), async (req, res) => {
	try {
		const d = await db();
		const [expiring] = await d.query(`
      SELECT id, tenant_name, property_address, lease_end, phone,
             DATEDIFF(lease_end, CURDATE()) as days_remaining
      FROM tenants WHERE lease_end BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 60 DAY)
      ORDER BY lease_end ASC
    `);
		const [overdue] = await d.query(`
      SELECT id, tenant_name, property_address, rent_per_annum, amount_paid, phone,
             (rent_per_annum - amount_paid) as amount_owed
      FROM tenants WHERE amount_paid < rent_per_annum AND rent_per_annum > 0
      ORDER BY amount_owed DESC
    `);
		const [quitNotices] = await d.query(`
      SELECT id, tenant_name, property_address, quit_notice_date, phone
      FROM tenants WHERE quit_notice = 1
    `);
		res.json({ expiring, overdue, quitNotices });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// ── TENANT PORTAL (public, by token) ─────────────────────────────────────────
app.get("/api/portal/:tenantId", async (req, res) => {
	try {
		const [[t]] = await (
			await db()
		).query(
			"SELECT id,tenant_name,accommodation_type,property_address,period,lease_start,lease_end,rent_per_annum,amount_paid,phone FROM tenants WHERE id=?",
			[req.params.tenantId],
		);
		if (!t) return res.status(404).json({ error: "Not found" });
		const [payments] = await (
			await db()
		).query(
			"SELECT amount,payment_date,payment_method,receipt_number FROM payments WHERE tenant_id=? ORDER BY payment_date DESC",
			[req.params.tenantId],
		);
		res.json({ ...t, payments });
	} catch (e) {
		res.status(500).json({ error: e.message });
	}
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, "0.0.0.0", () =>
	console.log(`\n🚀 EstateIQ API v2 on port ${PORT}\n`),
);
