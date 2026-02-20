CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  brand TEXT NOT NULL CHECK (brand IN ('sholly-home', 'apex-apparel')),
  category TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  price_kobo INTEGER NOT NULL CHECK (price_kobo >= 0),
  compare_at_kobo INTEGER CHECK (compare_at_kobo IS NULL OR compare_at_kobo >= price_kobo),
  stock_qty INTEGER NOT NULL DEFAULT 0 CHECK (stock_qty >= 0),
  reorder_threshold INTEGER NOT NULL DEFAULT 5 CHECK (reorder_threshold >= 0),
  has_variants BOOLEAN NOT NULL DEFAULT FALSE,
  image_url TEXT NOT NULL,
  gallery_urls TEXT[] NOT NULL DEFAULT '{}',
  is_featured BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE products
  ADD COLUMN IF NOT EXISTS reorder_threshold INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS has_variants BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE products
  DROP CONSTRAINT IF EXISTS products_reorder_threshold_check;

ALTER TABLE products
  ADD CONSTRAINT products_reorder_threshold_check
  CHECK (reorder_threshold >= 0);

CREATE TABLE IF NOT EXISTS orders (
  id BIGSERIAL PRIMARY KEY,
  order_number TEXT NOT NULL UNIQUE,
  customer_id BIGINT,
  customer_name TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  customer_email TEXT,
  notes TEXT NOT NULL DEFAULT '',
  shipping_state TEXT NOT NULL DEFAULT '',
  shipping_city TEXT,
  subtotal_kobo BIGINT NOT NULL CHECK (subtotal_kobo >= 0),
  shipping_fee_kobo BIGINT NOT NULL DEFAULT 0 CHECK (shipping_fee_kobo >= 0),
  coupon_code TEXT,
  coupon_discount_kobo BIGINT NOT NULL DEFAULT 0 CHECK (coupon_discount_kobo >= 0),
  total_kobo BIGINT NOT NULL DEFAULT 0 CHECK (total_kobo >= 0),
  status TEXT NOT NULL DEFAULT 'pending_payment',
  payment_channel TEXT,
  paystack_reference TEXT,
  moniepoint_reference TEXT,
  payment_proof_url TEXT,
  payment_proof_note TEXT NOT NULL DEFAULT '',
  payment_proof_uploaded_at TIMESTAMPTZ,
  payment_proof_status TEXT NOT NULL DEFAULT 'none',
  payment_review_note TEXT NOT NULL DEFAULT '',
  payment_reviewed_at TIMESTAMPTZ,
  payment_reviewed_by TEXT,
  payment_verified_at TIMESTAMPTZ,
  payment_verified_by TEXT,
  reconciliation_status TEXT NOT NULL DEFAULT 'unreconciled',
  reconciliation_note TEXT NOT NULL DEFAULT '',
  reconciled_at TIMESTAMPTZ,
  reconciled_by TEXT,
  payment_reminder_count INTEGER NOT NULL DEFAULT 0 CHECK (payment_reminder_count >= 0),
  last_payment_reminder_at TIMESTAMPTZ,
  paid_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE orders
  ADD COLUMN IF NOT EXISTS customer_id BIGINT,
  ADD COLUMN IF NOT EXISTS shipping_state TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS shipping_city TEXT,
  ADD COLUMN IF NOT EXISTS shipping_fee_kobo BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS coupon_code TEXT,
  ADD COLUMN IF NOT EXISTS coupon_discount_kobo BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS total_kobo BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS payment_channel TEXT,
  ADD COLUMN IF NOT EXISTS paystack_reference TEXT,
  ADD COLUMN IF NOT EXISTS moniepoint_reference TEXT,
  ADD COLUMN IF NOT EXISTS payment_proof_url TEXT,
  ADD COLUMN IF NOT EXISTS payment_proof_note TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS payment_proof_uploaded_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS payment_proof_status TEXT NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS payment_review_note TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS payment_reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS payment_reviewed_by TEXT,
  ADD COLUMN IF NOT EXISTS payment_verified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS payment_verified_by TEXT,
  ADD COLUMN IF NOT EXISTS reconciliation_status TEXT NOT NULL DEFAULT 'unreconciled',
  ADD COLUMN IF NOT EXISTS reconciliation_note TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS reconciled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS reconciled_by TEXT,
  ADD COLUMN IF NOT EXISTS payment_reminder_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_payment_reminder_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;

UPDATE orders
SET total_kobo = GREATEST(subtotal_kobo - COALESCE(coupon_discount_kobo, 0) + COALESCE(shipping_fee_kobo, 0), 0)
WHERE total_kobo = 0;

UPDATE orders
SET shipping_state = ''
WHERE shipping_state IS NULL;

ALTER TABLE orders
  ALTER COLUMN shipping_state SET DEFAULT '';

ALTER TABLE orders
  ALTER COLUMN shipping_state SET NOT NULL;

ALTER TABLE orders
  ALTER COLUMN shipping_fee_kobo SET DEFAULT 0;

ALTER TABLE orders
  ALTER COLUMN payment_reminder_count SET DEFAULT 0;

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_shipping_fee_kobo_check;

ALTER TABLE orders
  ADD CONSTRAINT orders_shipping_fee_kobo_check
  CHECK (shipping_fee_kobo >= 0);

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_payment_reminder_count_check;

ALTER TABLE orders
  ADD CONSTRAINT orders_payment_reminder_count_check
  CHECK (payment_reminder_count >= 0);

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_status_check;

ALTER TABLE orders
  ADD CONSTRAINT orders_status_check
  CHECK (status IN ('pending_payment', 'paid', 'processing', 'shipped', 'delivered', 'cancelled', 'refunded'));

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_payment_proof_status_check;

ALTER TABLE orders
  ADD CONSTRAINT orders_payment_proof_status_check
  CHECK (payment_proof_status IN ('none', 'pending_review', 'approved', 'rejected'));

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_reconciliation_status_check;

ALTER TABLE orders
  ADD CONSTRAINT orders_reconciliation_status_check
  CHECK (reconciliation_status IN ('unreconciled', 'reconciled', 'disputed'));

CREATE TABLE IF NOT EXISTS order_items (
  id BIGSERIAL PRIMARY KEY,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id BIGINT REFERENCES products(id) ON DELETE SET NULL,
  variant_id BIGINT,
  variant_sku TEXT,
  variant_label TEXT,
  product_name TEXT NOT NULL,
  brand TEXT NOT NULL CHECK (brand IN ('sholly-home', 'apex-apparel')),
  unit_price_kobo INTEGER NOT NULL CHECK (unit_price_kobo >= 0),
  qty INTEGER NOT NULL CHECK (qty > 0),
  line_total_kobo BIGINT NOT NULL CHECK (line_total_kobo >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE order_items
  ADD COLUMN IF NOT EXISTS variant_id BIGINT,
  ADD COLUMN IF NOT EXISTS variant_sku TEXT,
  ADD COLUMN IF NOT EXISTS variant_label TEXT;

CREATE TABLE IF NOT EXISTS product_variants (
  id BIGSERIAL PRIMARY KEY,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  sku TEXT NOT NULL UNIQUE,
  option_size TEXT,
  option_color TEXT,
  option_style TEXT,
  price_override_kobo INTEGER CHECK (price_override_kobo IS NULL OR price_override_kobo >= 0),
  stock_qty INTEGER NOT NULL DEFAULT 0 CHECK (stock_qty >= 0),
  reorder_threshold INTEGER NOT NULL DEFAULT 2 CHECK (reorder_threshold >= 0),
  image_url TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stock_movements (
  id BIGSERIAL PRIMARY KEY,
  product_id BIGINT REFERENCES products(id) ON DELETE SET NULL,
  variant_id BIGINT REFERENCES product_variants(id) ON DELETE SET NULL,
  movement_type TEXT NOT NULL,
  delta_qty INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  reference_type TEXT,
  reference_id TEXT,
  admin_user_id BIGINT,
  admin_username TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT stock_movements_entity_check CHECK (product_id IS NOT NULL OR variant_id IS NOT NULL)
);

ALTER TABLE stock_movements
  DROP CONSTRAINT IF EXISTS stock_movements_movement_type_check;

ALTER TABLE stock_movements
  ADD CONSTRAINT stock_movements_movement_type_check
  CHECK (movement_type IN ('adjustment', 'sale', 'restock', 'reversal', 'manual'));

CREATE TABLE IF NOT EXISTS order_status_history (
  id BIGSERIAL PRIMARY KEY,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  previous_status TEXT,
  new_status TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  changed_by_user_id BIGINT,
  changed_by_username TEXT NOT NULL DEFAULT 'system',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS expenses (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'general',
  amount_kobo BIGINT NOT NULL CHECK (amount_kobo >= 0),
  notes TEXT NOT NULL DEFAULT '',
  spent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupons (
  id BIGSERIAL PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  discount_type TEXT NOT NULL CHECK (discount_type IN ('percent', 'fixed')),
  discount_value INTEGER NOT NULL CHECK (discount_value > 0),
  min_order_kobo BIGINT NOT NULL DEFAULT 0 CHECK (min_order_kobo >= 0),
  max_discount_kobo BIGINT CHECK (max_discount_kobo IS NULL OR max_discount_kobo >= 0),
  brand TEXT CHECK (brand IS NULL OR brand IN ('sholly-home', 'apex-apparel')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  usage_limit INTEGER CHECK (usage_limit IS NULL OR usage_limit > 0),
  used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
  starts_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupon_redemptions (
  id BIGSERIAL PRIMARY KEY,
  coupon_id BIGINT NOT NULL REFERENCES coupons(id) ON DELETE CASCADE,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  discount_kobo BIGINT NOT NULL CHECK (discount_kobo >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'manager', 'editor', 'viewer')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  totp_secret TEXT,
  totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  totp_confirmed_at TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE admin_users
  ADD COLUMN IF NOT EXISTS totp_secret TEXT,
  ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS totp_confirmed_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS admin_sessions (
  session_id TEXT PRIMARY KEY,
  admin_user_id BIGINT,
  admin_username TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'manager', 'editor', 'viewer')),
  source TEXT NOT NULL DEFAULT 'session',
  user_agent TEXT,
  ip_address TEXT,
  csrf_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  admin_user_id BIGINT,
  admin_username TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cart_sessions (
  session_id TEXT PRIMARY KEY,
  customer_name TEXT,
  customer_phone TEXT,
  customer_email TEXT,
  items_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  subtotal_kobo BIGINT NOT NULL DEFAULT 0 CHECK (subtotal_kobo >= 0),
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'abandoned', 'converted', 'contacted', 'recovered')),
  reminder_count INTEGER NOT NULL DEFAULT 0 CHECK (reminder_count >= 0),
  last_reminder_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE cart_sessions
  ADD COLUMN IF NOT EXISTS last_reminder_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS paystack_events (
  id BIGSERIAL PRIMARY KEY,
  event_id TEXT UNIQUE,
  event_type TEXT NOT NULL,
  reference TEXT,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed BOOLEAN NOT NULL DEFAULT FALSE,
  processed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS moniepoint_events (
  id BIGSERIAL PRIMARY KEY,
  event_id TEXT UNIQUE,
  event_type TEXT NOT NULL,
  reference TEXT,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed BOOLEAN NOT NULL DEFAULT FALSE,
  processed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS order_payment_reminders (
  id BIGSERIAL PRIMARY KEY,
  order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  reminder_channel TEXT NOT NULL DEFAULT 'whatsapp',
  message TEXT NOT NULL DEFAULT '',
  sent_by_user_id BIGINT,
  sent_by_username TEXT NOT NULL DEFAULT 'system',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS shipping_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  default_fee_kobo BIGINT NOT NULL DEFAULT 550000 CHECK (default_fee_kobo >= 0),
  free_shipping_threshold_kobo BIGINT NOT NULL DEFAULT 0 CHECK (free_shipping_threshold_kobo >= 0),
  eta_min_days INTEGER NOT NULL DEFAULT 1 CHECK (eta_min_days >= 0),
  eta_max_days INTEGER NOT NULL DEFAULT 5 CHECK (eta_max_days >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO shipping_settings (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS shipping_rules (
  id BIGSERIAL PRIMARY KEY,
  state_text TEXT NOT NULL,
  city_text TEXT,
  fee_kobo BIGINT NOT NULL CHECK (fee_kobo >= 0),
  eta_min_days INTEGER CHECK (eta_min_days IS NULL OR eta_min_days >= 0),
  eta_max_days INTEGER CHECK (eta_max_days IS NULL OR eta_max_days >= 0),
  priority INTEGER NOT NULL DEFAULT 100,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS shipping_blackout_dates (
  id BIGSERIAL PRIMARY KEY,
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT shipping_blackout_dates_range_check CHECK (ends_at > starts_at)
);

CREATE TABLE IF NOT EXISTS customers (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL DEFAULT '',
  phone TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_customer_id_fkey;

ALTER TABLE orders
  ADD CONSTRAINT orders_customer_id_fkey
  FOREIGN KEY (customer_id)
  REFERENCES customers(id)
  ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS customer_sessions (
  session_id TEXT PRIMARY KEY,
  customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  user_agent TEXT,
  ip_address TEXT,
  csrf_token TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS customer_addresses (
  id BIGSERIAL PRIMARY KEY,
  customer_id BIGINT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT 'Home',
  recipient_name TEXT NOT NULL,
  recipient_phone TEXT NOT NULL,
  line1 TEXT NOT NULL,
  line2 TEXT,
  city TEXT NOT NULL,
  state TEXT NOT NULL,
  country TEXT NOT NULL DEFAULT 'Nigeria',
  postal_code TEXT,
  is_default BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wishlists (
  id BIGSERIAL PRIMARY KEY,
  customer_id BIGINT NOT NULL UNIQUE REFERENCES customers(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wishlist_items (
  id BIGSERIAL PRIMARY KEY,
  wishlist_id BIGINT NOT NULL REFERENCES wishlists(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  variant_id BIGINT REFERENCES product_variants(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'products_set_updated_at'
  ) THEN
    CREATE TRIGGER products_set_updated_at
    BEFORE UPDATE ON products
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'product_variants_set_updated_at'
  ) THEN
    CREATE TRIGGER product_variants_set_updated_at
    BEFORE UPDATE ON product_variants
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'orders_set_updated_at'
  ) THEN
    CREATE TRIGGER orders_set_updated_at
    BEFORE UPDATE ON orders
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'shipping_rules_set_updated_at'
  ) THEN
    CREATE TRIGGER shipping_rules_set_updated_at
    BEFORE UPDATE ON shipping_rules
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'shipping_blackout_dates_set_updated_at'
  ) THEN
    CREATE TRIGGER shipping_blackout_dates_set_updated_at
    BEFORE UPDATE ON shipping_blackout_dates
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'customers_set_updated_at'
  ) THEN
    CREATE TRIGGER customers_set_updated_at
    BEFORE UPDATE ON customers
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'customer_addresses_set_updated_at'
  ) THEN
    CREATE TRIGGER customer_addresses_set_updated_at
    BEFORE UPDATE ON customer_addresses
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'wishlists_set_updated_at'
  ) THEN
    CREATE TRIGGER wishlists_set_updated_at
    BEFORE UPDATE ON wishlists
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'coupons_set_updated_at'
  ) THEN
    CREATE TRIGGER coupons_set_updated_at
    BEFORE UPDATE ON coupons
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'admin_users_set_updated_at'
  ) THEN
    CREATE TRIGGER admin_users_set_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'cart_sessions_set_updated_at'
  ) THEN
    CREATE TRIGGER cart_sessions_set_updated_at
    BEFORE UPDATE ON cart_sessions
    FOR EACH ROW
    EXECUTE PROCEDURE set_updated_at();
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_products_brand ON products (brand);
CREATE INDEX IF NOT EXISTS idx_products_featured ON products (is_featured);
CREATE INDEX IF NOT EXISTS idx_products_created_at ON products (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_products_low_stock ON products (stock_qty, reorder_threshold);
CREATE INDEX IF NOT EXISTS idx_products_has_variants ON products (has_variants);

CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_paystack_reference_unique
  ON orders (paystack_reference)
  WHERE paystack_reference IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_moniepoint_reference_unique
  ON orders (moniepoint_reference)
  WHERE moniepoint_reference IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (status);
CREATE INDEX IF NOT EXISTS idx_orders_customer_id ON orders (customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_payment_proof_status ON orders (payment_proof_status, status);
CREATE INDEX IF NOT EXISTS idx_orders_reconciliation_status ON orders (reconciliation_status, status);

CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items (order_id);
CREATE INDEX IF NOT EXISTS idx_order_items_product_id ON order_items (product_id);
CREATE INDEX IF NOT EXISTS idx_order_items_variant_id ON order_items (variant_id);
CREATE INDEX IF NOT EXISTS idx_order_status_history_order_id ON order_status_history (order_id);
CREATE INDEX IF NOT EXISTS idx_order_payment_reminders_order_id ON order_payment_reminders (order_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_expenses_spent_at ON expenses (spent_at DESC);
CREATE INDEX IF NOT EXISTS idx_coupons_code ON coupons (code);
CREATE INDEX IF NOT EXISTS idx_coupon_redemptions_coupon_id ON coupon_redemptions (coupon_id);

CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users (role);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_username ON admin_sessions (admin_username, revoked, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_user_id ON admin_sessions (admin_user_id, revoked, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_cart_sessions_status_seen ON cart_sessions (status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_paystack_events_reference ON paystack_events (reference);
CREATE INDEX IF NOT EXISTS idx_moniepoint_events_reference ON moniepoint_events (reference);

CREATE INDEX IF NOT EXISTS idx_product_variants_product_id ON product_variants (product_id, is_active);
CREATE INDEX IF NOT EXISTS idx_product_variants_sku ON product_variants (sku);
CREATE INDEX IF NOT EXISTS idx_product_variants_low_stock ON product_variants (stock_qty, reorder_threshold);

CREATE INDEX IF NOT EXISTS idx_stock_movements_variant_id ON stock_movements (variant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_stock_movements_product_id ON stock_movements (product_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_shipping_rules_lookup ON shipping_rules (LOWER(state_text), LOWER(COALESCE(city_text, '')), is_active, priority);
CREATE INDEX IF NOT EXISTS idx_shipping_blackout_active ON shipping_blackout_dates (is_active, starts_at, ends_at);

CREATE INDEX IF NOT EXISTS idx_customers_email ON customers (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_customer_sessions_customer_id ON customer_sessions (customer_id, revoked, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_customer_addresses_customer_id ON customer_addresses (customer_id, is_default DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_wishlist_items_wishlist_id ON wishlist_items (wishlist_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_wishlist_items_unique_triplet
  ON wishlist_items (wishlist_id, product_id, COALESCE(variant_id, 0));
