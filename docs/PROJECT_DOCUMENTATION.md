# Sholly & Shaddy's / Apex Apparel

Comprehensive project documentation for maintainers, collaborators, and business stakeholders.

## 1. Project Overview

This application is a full-stack commerce platform serving two brands:
- `sholly-home` (luxury home/bedding)
- `apex-apparel` (fashion/apparel)

It provides:
- Public storefront with animated UI, brand switch, cart, checkout, and order tracking
- Admin operations dashboard for products, variants, shipping rules, orders, expenses, coupons, alerts, and audit logs
- Customer account area with authentication, order history, wishlist, and saved addresses
- Online payments (Paystack, Moniepoint) and direct bank transfer workflow
- Cloudinary media uploads
- Neon Postgres persistence

## 2. Tech Stack

- Backend: Node.js + Express (`server.js`)
- Database: Postgres (Neon)
- Frontend: Vanilla HTML/CSS/JS (`public/`)
- Uploads: `multer` + Cloudinary SDK
- Payments: Paystack + Moniepoint APIs/webhooks
- Auth/security:
  - HMAC-signed session cookies
  - CSRF token enforcement for state-changing admin/customer requests
  - Role-based access control for admin actions
  - Admin 2FA (TOTP)
  - Admin login throttling

## 3. High-Level Architecture

### 3.1 Client apps
- Storefront: `/` (`public/index.html`, `public/app.js`, `public/styles.css`)
- Checkout: `/checkout` (`public/checkout.html`, `public/checkout.js`, `public/checkout.css`)
- Admin: `/admin` (`public/admin.html`, `public/admin.js`, `public/admin.css`)
- Customer account: `/account` (`public/account.html`, `public/account.js`, `public/account.css`)
- Tracking page: `/track` (`public/track.html`, `public/track.js`, `public/track.css`)

### 3.2 API service
- Single Express service in `server.js`
- Serves static files and JSON API routes
- Uses `DATABASE_URL` for all persistent operations

### 3.3 Data layer
- Schema in `db/schema.sql`
- Optional auto-migration at startup when `AUTO_MIGRATE=true`
- Seed script available for baseline data (`scripts/seed-db.js`)

## 4. Repository Structure

```text
.
|- db/
|  |- schema.sql
|- docs/
|  |- PROJECT_DOCUMENTATION.md
|- public/
|  |- index.html, app.js, styles.css
|  |- admin.html, admin.js, admin.css
|  |- account.html, account.js, account.css
|  |- track.html, track.js, track.css
|- scripts/
|  |- init-db.js
|  |- seed-db.js
|- server.js
|- .env.example
|- render.yaml
|- README.md
```

## 5. Core Features

### 5.1 Storefront
- Brand switching between Sholly and Apex sections
- Light/dark theme toggle
- Mobile header menu (hamburger)
- Product browsing with category/search filters
- Product modal with variant selection
- Cart drawer with totals, shipping estimate, coupon support
- Checkout modes:
  - Paystack
  - Moniepoint
  - Direct bank transfer
- WhatsApp floating action button

### 5.2 Inventory and products
- Product CRUD
- Variant CRUD with stock control
- Variant-level stock movements
- Low-stock alerts (product + variant)

### 5.3 Orders and operations
- Order lifecycle statuses (`pending_payment` -> `paid` -> `processing` -> `shipped` -> `delivered`)
- Payment proof upload + admin review
- Reconciliation status management
- Pending-payment and abandoned-cart reminder helpers (WhatsApp links)
- Expense logging and analytics

### 5.4 Customer account
- Register/login/logout
- Session-based auth with CSRF protection
- Address book CRUD
- Wishlist add/remove
- Order history
- Reorder-to-cart helper (pushes valid items back into storefront cart)

### 5.5 Admin security
- Session cookie auth + CSRF token enforcement
- Optional legacy API key auth support
- Roles: `owner`, `manager`, `editor`, `viewer`
- 2FA (TOTP) setup/verify/disable
- Session list/revoke
- Login throttling and temporary blocking
- Audit logging

## 6. Data Model Summary

Primary tables:
- `products`
- `product_variants`
- `stock_movements`
- `orders`
- `order_items`
- `order_status_history`
- `coupons`, `coupon_redemptions`
- `expenses`
- `admin_users`, `admin_sessions`, `audit_logs`
- `customers`, `customer_sessions`, `customer_addresses`
- `wishlists`, `wishlist_items`
- `cart_sessions`
- `paystack_events`, `moniepoint_events`
- `order_payment_reminders`
- `shipping_settings`, `shipping_rules`, `shipping_blackout_dates`

Important relationships:
- `product_variants.product_id -> products.id`
- `order_items.order_id -> orders.id`
- `order_items.product_id -> products.id`
- `orders.customer_id -> customers.id`
- `wishlist_items.wishlist_id -> wishlists.id`
- `customer_addresses.customer_id -> customers.id`

## 7. Security Model

### 7.1 Admin
- Auth:
  - Preferred: `/api/admin/login` session cookie
  - Optional: `x-admin-key` legacy key
- CSRF:
  - Required for non-GET admin requests when using session auth
  - Header: `x-csrf-token`
- RBAC:
  - Viewer: read-only
  - Editor: product editing
  - Manager: order/ops/coupon/shipping/expense controls
  - Owner: full access + admin user management

### 7.2 Customer
- Session cookie auth
- CSRF required for non-GET customer requests
- Header: `x-customer-csrf-token`

### 7.3 Payments
- Verification endpoints confirm transaction state before marking paid
- Webhook idempotency via event tables (`paystack_events`, `moniepoint_events`)

## 8. Environment Variables

Use `.env.example` as source of truth. Key categories:

### 8.1 Required for baseline
- `DATABASE_URL`
- `SESSION_SECRET`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `ADMIN_API_KEY`

### 8.2 Optional/feature-specific
- Cloudinary: `CLOUDINARY_*`
- Paystack: `PAYSTACK_*`
- Moniepoint: `MONIEPOINT_*`
- Social/contact: `INSTAGRAM_*`, `WHATSAPP_NUMBER`
- Bank transfer: `BANK_*`
- Shipping defaults: `DEFAULT_SHIPPING_FEE_KOBO`, `FREE_SHIPPING_THRESHOLD_KOBO`

## 9. API Surface (Grouped)

### 9.1 Public/storefront
- `GET /api/health`
- `GET /api/public-config`
- `GET /api/products`
- `GET /api/products/:id`
- `GET /api/products/:id/variants`
- `GET /api/brands`
- `GET /api/inventory/summary`
- `GET /api/shipping/quote`
- `POST /api/cart/track`

### 9.2 Checkout and payment
- `POST /api/paystack/initialize`
- `POST /api/paystack/verify`
- `POST /api/moniepoint/initialize`
- `POST /api/moniepoint/verify`
- `POST /api/checkout` (bank transfer / direct)
- `POST /api/paystack/webhook`
- `POST /api/moniepoint/webhook`

### 9.3 Tracking
- `POST /api/track/order`
- `POST /api/track/order/payment-proof`

### 9.4 Admin auth and security
- `POST /api/admin/login`
- `POST /api/admin/logout`
- `GET /api/admin/me`
- `GET /api/admin/sessions`
- `POST /api/admin/sessions/:sessionId/revoke`
- `POST /api/admin/2fa/setup`
- `POST /api/admin/2fa/verify-setup`
- `POST /api/admin/2fa/disable`

### 9.5 Admin operations
- Products/variants CRUD
- Dashboard, analytics, alerts, abandoned carts
- Orders status/review/reconciliation/reminders
- Shipping settings/rules/blackouts
- Coupons, expenses, audit logs
- Cloudinary upload/status

### 9.6 Customer account
- `POST /api/customer/register`
- `POST /api/customer/login`
- `POST /api/customer/logout`
- `GET /api/customer/me`
- `GET /api/customer/orders`
- `GET /api/customer/addresses`
- `POST /api/customer/addresses`
- `PUT /api/customer/addresses/:id`
- `DELETE /api/customer/addresses/:id`
- `GET /api/customer/wishlist`
- `POST /api/customer/wishlist/items`
- `DELETE /api/customer/wishlist/items/:id`
- `POST /api/customer/orders/:orderId/reorder`

## 10. Local Development

1. Install dependencies:
   - `npm install`
2. Configure environment:
   - copy `.env.example` to `.env`
3. Initialize DB:
   - `npm run db:init`
   - `npm run db:seed` (optional baseline data)
4. Start app:
   - `npm run dev` (watch mode)
5. URLs:
   - Storefront: `http://localhost:3000/`
   - Admin: `http://localhost:3000/admin`
   - Account: `http://localhost:3000/account`
   - Track: `http://localhost:3000/track`

## 11. Deployment Guide (Render + Neon)

### 11.1 Prerequisites
- Source code pushed to GitHub/GitLab
- Neon project created
- Render account + web service access

### 11.2 Option A: Blueprint deploy (`render.yaml`)

1. In Render dashboard, choose **New +** -> **Blueprint**.
2. Select your repository.
3. Render detects `render.yaml` and prepares service config.
4. Set all `sync: false` variables in Render Environment tab:
   - `DATABASE_URL`, `ADMIN_*`, `SESSION_SECRET` (if not auto-generated), payment keys, Cloudinary keys, etc.
5. Deploy.
6. Verify health endpoint:
   - `https://<your-service>.onrender.com/api/health`

### 11.3 Option B: Manual web service

Use:
- Build command: `npm ci`
- Start command: `npm start`
- Health check path: `/api/health`
- Environment: Node
- Add all `.env.example` variables as needed

### 11.4 Database migration behavior

- `AUTO_MIGRATE=true` applies `db/schema.sql` on startup.
- Keep this enabled for easy deploys unless you introduce strict migration discipline.

## 12. Operational Checklist

### 12.1 Go-live checklist
- Neon `DATABASE_URL` valid
- Admin account credentials set
- `SESSION_SECRET` high entropy
- Cloudinary credentials set
- Payment gateways configured and tested
- `PAYSTACK_CALLBACK_URL` and `MONIEPOINT_REDIRECT_URL` point to production domain
- Webhook secrets configured and verified
- Instagram/WhatsApp/bank details set

### 12.2 Post-deploy checks
- `/api/health` returns 200
- Homepage, admin, account, track pages load
- Product list loads
- Cart and checkout paths work
- Admin login + dashboard works
- Customer register/login works
- Payment verify routes work in sandbox

## 13. Manual QA Checklist

### Storefront
- Brand switch updates header logo/text
- Theme switch toggles correctly
- Mobile header menu opens/closes
- Variant products enforce variant selection
- Cart updates quantity and totals correctly
- Shipping quote updates after state/city changes
- WhatsApp floating icon opens chat

### Admin
- Login/logout/session expiry handling
- 2FA setup and disable
- Product and variant CRUD
- Stock adjustments and low-stock alerts
- Shipping settings/rules/blackouts updates
- Order status changes and payment proof review
- Reconciliation updates

### Customer
- Register/login/logout
- Address create/edit/delete/default
- Wishlist add/remove
- Reorder to cart and redirect to storefront

## 14. Troubleshooting

### `ERR_INVALID_URL` on startup
- Usually malformed `DATABASE_URL`.
- Ensure full Postgres connection string, e.g.:
  - `postgresql://user:password@host/db?sslmode=require`

### Module not found on startup
- Run `npm install`.
- Ensure `package-lock.json` and dependency tree are intact.

### Payment initialized but order not marked paid
- Verify callback/redirect URLs
- Check webhook secret and request signature handling
- Inspect `paystack_events` or `moniepoint_events` for processing state

### Cloudinary upload fails
- Validate `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`
- Confirm allowed file type and size

### Admin requests return 403
- Missing/invalid CSRF token in state-changing requests.
- Re-login to refresh session and CSRF token.

## 15. Maintenance Notes

- Keep `db/schema.sql` and API behavior aligned whenever adding features.
- For future scale, consider:
  - background queue for reminders and webhooks
  - structured log shipping
  - automated integration tests
  - object-level RBAC tightening for large teams
