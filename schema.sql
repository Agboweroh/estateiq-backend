-- EstateIQ v2 — Full Database Schema
-- Run this to upgrade your existing database OR start fresh

CREATE DATABASE IF NOT EXISTS estateiq;
USE estateiq;

-- ── USERS (with roles & auth) ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  phone VARCHAR(50),
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin','manager','staff') DEFAULT 'staff',
  is_active BOOLEAN DEFAULT TRUE,
  last_login TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ── PROPERTIES ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS properties (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  name VARCHAR(255) NOT NULL,
  address TEXT,
  total_units INT DEFAULT 0,
  created_by VARCHAR(36),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── TENANTS ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  sn INT AUTO_INCREMENT UNIQUE,
  tenant_name VARCHAR(255) NOT NULL,
  accommodation_type VARCHAR(100),
  property_address VARCHAR(255),
  property_id VARCHAR(36) NULL,
  period VARCHAR(100),
  lease_start DATE NULL,
  lease_end DATE NULL,
  rent_per_annum DECIMAL(15,2) DEFAULT 0,
  amount_paid DECIMAL(15,2) DEFAULT 0,
  phone VARCHAR(50),
  email VARCHAR(255),
  whatsapp VARCHAR(50),
  notes TEXT,
  quit_notice BOOLEAN DEFAULT FALSE,
  quit_notice_date DATE NULL,
  created_by VARCHAR(36),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ── PAYMENTS (payment history log) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payments (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  tenant_id VARCHAR(36) NOT NULL,
  amount DECIMAL(15,2) NOT NULL,
  payment_date DATE NOT NULL,
  payment_method ENUM('cash','bank_transfer','cheque','pos','online') DEFAULT 'cash',
  reference VARCHAR(100),
  notes TEXT,
  receipt_number VARCHAR(50),
  recorded_by VARCHAR(36),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- ── MAINTENANCE REQUESTS ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS maintenance (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  tenant_id VARCHAR(36),
  tenant_name VARCHAR(255),
  property_address VARCHAR(255),
  category ENUM('plumbing','electrical','structural','painting','security','cleaning','other') DEFAULT 'other',
  title VARCHAR(255) NOT NULL,
  description TEXT,
  priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
  status ENUM('open','in_progress','resolved','closed') DEFAULT 'open',
  assigned_to VARCHAR(36) NULL,
  resolved_at TIMESTAMP NULL,
  images TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
);

-- ── NOTIFICATIONS / ALERTS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  type ENUM('rent_due','rent_overdue','lease_expiry','quit_notice','maintenance','payment','system') NOT NULL,
  title VARCHAR(255) NOT NULL,
  message TEXT,
  tenant_id VARCHAR(36) NULL,
  user_id VARCHAR(36) NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
);

-- ── WHATSAPP/SMS LOG ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS message_log (
  id VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  tenant_id VARCHAR(36),
  tenant_name VARCHAR(255),
  phone VARCHAR(50),
  channel ENUM('whatsapp','sms','email') DEFAULT 'whatsapp',
  message TEXT,
  status ENUM('sent','failed','pending') DEFAULT 'pending',
  sent_by VARCHAR(36),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── SEED: Default Admin User ──────────────────────────────────────────────────
-- Default password: Admin@1234 (bcrypt hash)
INSERT IGNORE INTO users (id, name, email, phone, password_hash, role)
VALUES (
  'admin-001',
  'Admin User',
  'admin@estateiq.ng',
  '08000000000',
  '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'admin'
);

-- ── SEED: Sample Tenants ──────────────────────────────────────────────────────
INSERT IGNORE INTO tenants (id, tenant_name, accommodation_type, property_address, period, lease_start, lease_end, rent_per_annum, amount_paid, phone, email, whatsapp, quit_notice)
VALUES
  ('t-001','Adebayo Okafor','2-Bedroom Flat','Block A, No. 5','Jan 2024 - Dec 2024','2024-01-01','2024-12-31',480000,480000,'08012345678','adebayo@email.com','08012345678',FALSE),
  ('t-002','Ngozi Eze','Self-Contain','Block B, No. 2','Mar 2024 - Feb 2025','2024-03-01','2025-02-28',220000,150000,'08023456789','ngozi@email.com','08023456789',FALSE),
  ('t-003','Emeka Nwosu','3-Bedroom Flat','Block C, No. 1','Jun 2023 - May 2024','2023-06-01','2024-05-31',650000,0,'08034567890','emeka@email.com','08034567890',TRUE),
  ('t-004','Fatima Bello','1-Bedroom Flat','Block A, No. 8','Apr 2024 - Mar 2025','2024-04-01','2025-03-31',320000,320000,'08045678901','fatima@email.com','08045678901',FALSE),
  ('t-005','Chukwudi Obi','Self-Contain','Block D, No. 3','Feb 2024 - Jan 2025','2024-02-01','2025-01-31',200000,100000,'08056789012','chukwudi@email.com','08056789012',FALSE);

-- ── SEED: Sample Payments ─────────────────────────────────────────────────────
INSERT IGNORE INTO payments (id, tenant_id, amount, payment_date, payment_method, receipt_number)
VALUES
  (UUID(),'t-001',480000,'2024-01-05','bank_transfer','RCP-2024-001'),
  (UUID(),'t-002',150000,'2024-03-10','cash','RCP-2024-002'),
  (UUID(),'t-004',320000,'2024-04-02','bank_transfer','RCP-2024-003'),
  (UUID(),'t-005',100000,'2024-02-15','pos','RCP-2024-004');

-- ── SEED: Sample Maintenance ──────────────────────────────────────────────────
INSERT IGNORE INTO maintenance (id, tenant_id, tenant_name, property_address, category, title, priority, status)
VALUES
  (UUID(),'t-002','Ngozi Eze','Block B, No. 2','plumbing','Leaking pipe in kitchen','high','open'),
  (UUID(),'t-004','Fatima Bello','Block A, No. 8','electrical','Faulty socket in bedroom','medium','in_progress'),
  (UUID(),'t-005','Chukwudi Obi','Block D, No. 3','structural','Crack in ceiling','urgent','open');
