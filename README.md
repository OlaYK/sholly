# Sholly & Shaddy's Live Storefront

Full-stack luxury storefront with:
- Express backend API
- Neon Postgres database
- Dynamic public storefront with switchable brand view (Sholly Home or Apex Apparel)
- Admin panel to manage products, variants, stock, pricing, and image URLs
- Cloudinary image upload from admin product form
- Cloudinary URL optimization (`f_auto,q_auto`) for storefront images
- Paystack checkout integration and payment verification
- Moniepoint checkout integration and verification
- Moniepoint webhook endpoint with idempotent event handling
- Direct bank transfer checkout option
- Customer order tracking page with payment-proof upload
- Payment proof review + reconciliation endpoints for admin operations
- Shipping settings/rules/blackout-date admin endpoints
- Customer account API: auth, addresses, wishlist, order history, reorder helper
- Customer account page: login/register, orders, addresses, wishlist, reorder-to-cart
- Admin security hardening: signed sessions, CSRF protection, login throttling, 2FA (TOTP), session revoke
- Abandoned-cart and pending-payment WhatsApp reminder actions in admin

## 1. Setup

```bash
npm install
```

Create `.env` from `.env.example` and fill in your values:

```env
PORT=3000
DATABASE_URL=postgresql://<USER>:<PASSWORD>@<HOST>/<DATABASE>?sslmode=require
ADMIN_API_KEY=replace-with-a-strong-secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=replace-with-a-strong-password
SESSION_SECRET=replace-with-a-long-random-secret
ADMIN_SESSION_TTL_SECONDS=43200
CUSTOMER_SESSION_TTL_SECONDS=1209600
ADMIN_LOGIN_MAX_ATTEMPTS=8
ADMIN_LOGIN_WINDOW_SECONDS=900
ADMIN_LOGIN_BLOCK_SECONDS=900
APP_2FA_ISSUER=Sholly Store
AUTO_MIGRATE=true
CLOUDINARY_CLOUD_NAME=
CLOUDINARY_API_KEY=
CLOUDINARY_API_SECRET=
CLOUDINARY_FOLDER=sholly-store
CLOUDINARY_URL=
PAYSTACK_PUBLIC_KEY=
PAYSTACK_SECRET_KEY=
PAYSTACK_CALLBACK_URL=
MONIEPOINT_API_KEY=
MONIEPOINT_SECRET_KEY=
MONIEPOINT_CONTRACT_CODE=
MONIEPOINT_BASE_URL=https://api.monnify.com
MONIEPOINT_REDIRECT_URL=
MONIEPOINT_WEBHOOK_SECRET=
BANK_NAME=
BANK_ACCOUNT_NAME=
BANK_ACCOUNT_NUMBER=
BANK_TRANSFER_INSTRUCTIONS=
INSTAGRAM_SHOLLY_URL=
INSTAGRAM_APEX_URL=
WHATSAPP_NUMBER=2348101653634
DEFAULT_SHIPPING_FEE_KOBO=550000
FREE_SHIPPING_THRESHOLD_KOBO=0
```

## 2. Initialize and seed database

```bash
npm run db:init
npm run db:seed
```

## 3. Run app

```bash
npm run dev
```

- Storefront: `http://localhost:3000/`
- Admin panel: `http://localhost:3000/admin`
- Customer account: `http://localhost:3000/account`
- Tracking page: `http://localhost:3000/track`

## 4. Documentation

- Full project documentation: `docs/PROJECT_DOCUMENTATION.md`

## 5. Deploy on Render

This repository includes `render.yaml` for Blueprint deployment.

Quick steps:
1. Push repository to GitHub/GitLab.
2. In Render, create a **Blueprint** service from the repo.
3. Set required environment variables in Render (all `sync: false` keys).
4. Confirm deploy is healthy at `/api/health`.

Key notes:
- Uses `npm ci` build and `npm start` runtime.
- `AUTO_MIGRATE=true` in Render config applies schema at startup.

## API Endpoints

- `GET /api/health`
- `GET /api/public-config`
- `GET /api/shipping/quote`
- `GET /api/brands`
- `GET /api/inventory/summary`
- `GET /api/products?brand=sholly-home|apex-apparel&featured=true|false&q=...`
- `GET /api/products/:id`
- `POST /api/paystack/initialize`
- `POST /api/paystack/verify`
- `POST /api/moniepoint/initialize`
- `POST /api/moniepoint/verify`
- `POST /api/checkout` (direct checkout fallback)
- `POST /api/track/order`
- `POST /api/track/order/payment-proof` (`multipart/form-data`, field: `proof`)
- `POST /api/cart/track`
- `POST /api/admin/login`
- `POST /api/admin/logout`
- `GET /api/admin/me`
- `GET /api/admin/sessions`
- `POST /api/admin/sessions/:sessionId/revoke`
- `POST /api/admin/2fa/setup`
- `POST /api/admin/2fa/verify-setup`
- `POST /api/admin/2fa/disable`
- `POST /api/products` (admin auth required)
- `PUT /api/products/:id` (admin auth required)
- `DELETE /api/products/:id` (admin auth required)
- `GET /api/products/:id/variants`
- `GET /api/admin/products/:id/variants`
- `POST /api/admin/products/:id/variants`
- `PUT /api/admin/variants/:id`
- `PATCH /api/admin/variants/:id/stock`
- `DELETE /api/admin/variants/:id`
- `GET /api/admin/inventory/stock-movements`
- `GET /api/admin/shipping/settings`
- `PATCH /api/admin/shipping/settings`
- `GET /api/admin/shipping/rules`
- `POST /api/admin/shipping/rules`
- `PATCH /api/admin/shipping/rules/:id`
- `DELETE /api/admin/shipping/rules/:id`
- `GET /api/admin/shipping/blackouts`
- `POST /api/admin/shipping/blackouts`
- `PATCH /api/admin/shipping/blackouts/:id`
- `DELETE /api/admin/shipping/blackouts/:id`
- `GET /api/admin/orders/payment-review`
- `PATCH /api/admin/orders/:id/payment-proof`
- `PATCH /api/admin/orders/:id/reconciliation`
- `GET /api/admin/orders/:id/payment-reminders`
- `GET /api/admin/cloudinary/status` (admin auth required)
- `POST /api/admin/upload-image` (admin auth required, `multipart/form-data` with field `image`)
- `POST /api/admin/orders/:id/payment-reminder` (admin auth required)
- `POST /api/admin/abandoned-carts/:sessionId/reminder` (admin auth required)
- `POST /api/paystack/webhook`
- `POST /api/moniepoint/webhook`
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

Admin auth:
- Primary: login via `/api/admin/login` and use session cookie.
- Optional legacy: API key header.

```http
x-admin-key: <ADMIN_API_KEY>
```
