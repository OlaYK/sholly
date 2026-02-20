const ORDER_STATUSES = [
  "pending_payment",
  "paid",
  "processing",
  "shipped",
  "delivered",
  "cancelled",
  "refunded",
];

const ORDER_STATUS_LABELS = {
  pending_payment: "Pending Payment",
  paid: "Paid",
  processing: "Processing",
  shipped: "Shipped",
  delivered: "Delivered",
  cancelled: "Cancelled",
  refunded: "Refunded",
};

const ROLE_LEVEL = { viewer: 1, editor: 2, manager: 3, owner: 4 };

const ui = {
  username: document.getElementById("admin-username"),
  password: document.getElementById("admin-password"),
  loginBtn: document.getElementById("admin-login"),
  logoutBtn: document.getElementById("admin-logout"),
  twoFaSetupBtn: document.getElementById("admin-2fa-setup"),
  twoFaDisableBtn: document.getElementById("admin-2fa-disable"),
  sessionsBtn: document.getElementById("admin-sessions"),
  authStatus: document.getElementById("admin-auth-status"),
  toast: document.getElementById("admin-toast"),
  form: document.getElementById("product-form"),
  resetForm: document.getElementById("reset-form"),
  refreshList: document.getElementById("refresh-list"),
  search: document.getElementById("search-products"),
  inventory: document.getElementById("inventory-list"),
  uploadImage: document.getElementById("upload-image"),
  imageFile: document.getElementById("image-file"),
  cloudinaryStatus: document.getElementById("cloudinary-status"),
  fields: {
    id: document.getElementById("product-id"),
    name: document.getElementById("name"),
    slug: document.getElementById("slug"),
    brand: document.getElementById("brand"),
    category: document.getElementById("category"),
    description: document.getElementById("description"),
    price: document.getElementById("price"),
    compare: document.getElementById("compare"),
    stock: document.getElementById("stock"),
    reorderThreshold: document.getElementById("reorder-threshold"),
    hasVariants: document.getElementById("has-variants"),
    featured: document.getElementById("featured"),
    imageUrl: document.getElementById("image-url"),
    galleryUrls: document.getElementById("gallery-urls"),
  },
  refreshDashboard: document.getElementById("refresh-dashboard"),
  shippingConfigBtn: document.getElementById("shipping-config-btn"),
  stats: {
    products: document.getElementById("stat-products"),
    lowStock: document.getElementById("stat-low-stock"),
    revenue: document.getElementById("stat-revenue"),
    expenses: document.getElementById("stat-expenses"),
    profit: document.getElementById("stat-profit"),
    abandoned: document.getElementById("stat-abandoned"),
  },
  refreshOrders: document.getElementById("refresh-orders"),
  ordersFilterStatus: document.getElementById("orders-filter-status"),
  ordersList: document.getElementById("orders-list"),
  refreshCoupons: document.getElementById("refresh-coupons"),
  couponForm: document.getElementById("coupon-form"),
  couponsList: document.getElementById("coupons-list"),
  couponFields: {
    code: document.getElementById("coupon-code"),
    type: document.getElementById("coupon-type"),
    value: document.getElementById("coupon-value"),
    brand: document.getElementById("coupon-brand"),
    minOrder: document.getElementById("coupon-min-order"),
    usageLimit: document.getElementById("coupon-usage-limit"),
    description: document.getElementById("coupon-description"),
  },
  refreshAlerts: document.getElementById("refresh-alerts"),
  alertsList: document.getElementById("alerts-list"),
  refreshCarts: document.getElementById("refresh-carts"),
  abandonedList: document.getElementById("abandoned-list"),
  refreshUsers: document.getElementById("refresh-users"),
  adminUserForm: document.getElementById("admin-user-form"),
  adminUsersList: document.getElementById("admin-users-list"),
  adminUserFields: {
    username: document.getElementById("new-admin-username"),
    password: document.getElementById("new-admin-password"),
    role: document.getElementById("new-admin-role"),
  },
  refreshAudit: document.getElementById("refresh-audit"),
  auditList: document.getElementById("audit-list"),
  refreshExpenses: document.getElementById("refresh-expenses"),
  expenseForm: document.getElementById("expense-form"),
  expensesList: document.getElementById("expenses-list"),
  expenseFields: {
    title: document.getElementById("expense-title"),
    category: document.getElementById("expense-category"),
    amount: document.getElementById("expense-amount"),
    date: document.getElementById("expense-date"),
    notes: document.getElementById("expense-notes"),
  },
  refreshAnalytics: document.getElementById("refresh-analytics"),
  analyticsWindow: document.getElementById("analytics-window"),
  analyticsSummary: document.getElementById("analytics-summary"),
  analyticsTopProducts: document.getElementById("analytics-top-products"),
  analyticsBrandSplit: document.getElementById("analytics-brand-split"),
};

ui.panels = {
  adminUsers: ui.adminUsersList?.closest(".panel") || null,
  audit: ui.auditList?.closest(".panel") || null,
};

const state = {
  authenticated: false,
  userId: null,
  adminUsername: "",
  adminRole: "viewer",
  csrfToken: "",
  sessionId: "",
  twoFactorEnabled: false,
  products: [],
  orders: [],
  orderDetails: {},
  coupons: [],
  alerts: [],
  variantAlerts: [],
  carts: [],
  adminUsers: [],
  logs: [],
  expenses: [],
  analytics: null,
};

const money = new Intl.NumberFormat("en-NG", {
  style: "currency",
  currency: "NGN",
  maximumFractionDigits: 0,
});

const formatMoney = (kobo = 0) => money.format(Number(kobo || 0) / 100);
const roleAtLeast = (role) => (ROLE_LEVEL[state.adminRole] || 0) >= (ROLE_LEVEL[role] || 0);
const canEditProducts = () => roleAtLeast("editor");
const canManageOps = () => roleAtLeast("manager");
const isOwner = () => state.adminRole === "owner";
const canViewAudit = () => roleAtLeast("manager");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString("en-NG");
}

function setToast(message) {
  ui.toast.textContent = message;
  ui.toast.classList.add("show");
  setTimeout(() => ui.toast.classList.remove("show"), 2400);
}

function setCloudinaryStatus(message, isError = false) {
  ui.cloudinaryStatus.textContent = message;
  ui.cloudinaryStatus.style.color = isError ? "#f8d0bf" : "";
}

function setPanelMessage(container, message) {
  if (!container) return;
  container.innerHTML = `<p class="muted">${escapeHtml(message)}</p>`;
}

function setManagementDisabled(disabled) {
  document
    .querySelectorAll(".admin-managed input, .admin-managed textarea, .admin-managed select, .admin-managed button")
    .forEach((el) => {
      el.disabled = disabled;
    });
}

function setRoleVisibility() {
  if (ui.panels.adminUsers) {
    ui.panels.adminUsers.style.display = "";
    if (!isOwner()) {
      setPanelMessage(ui.adminUsersList, "Owner role required to view or create admin users.");
    }
  }
  if (ui.panels.audit) ui.panels.audit.style.display = canViewAudit() ? "" : "none";
}

function setRoleControlDisabled() {
  ui.form?.querySelectorAll("input, textarea, select, button").forEach((el) => {
    el.disabled = !canEditProducts();
  });
  ui.couponForm?.querySelectorAll("input, textarea, select, button").forEach((el) => {
    el.disabled = !canManageOps();
  });
  ui.expenseForm?.querySelectorAll("input, textarea, select, button").forEach((el) => {
    el.disabled = !canManageOps();
  });
  ui.adminUserForm?.querySelectorAll("input, textarea, select, button").forEach((el) => {
    el.disabled = !isOwner();
  });
}

function setAuthState(authenticated, meta = {}) {
  state.authenticated = authenticated;
  state.userId = meta.userId ?? null;
  state.adminUsername = meta.username || "";
  state.adminRole = meta.role || "viewer";
  state.csrfToken = authenticated ? meta.csrfToken || state.csrfToken || "" : "";
  state.sessionId = authenticated ? meta.sessionId || state.sessionId || "" : "";
  state.twoFactorEnabled = authenticated ? Boolean(meta.twoFactorEnabled) : false;

  setManagementDisabled(!authenticated);
  ui.username.disabled = false;
  ui.password.disabled = false;
  ui.loginBtn.disabled = false;
  ui.logoutBtn.disabled = !authenticated;
  if (ui.twoFaSetupBtn) ui.twoFaSetupBtn.disabled = !authenticated || !state.userId;
  if (ui.twoFaDisableBtn) ui.twoFaDisableBtn.disabled = !authenticated || !state.userId;
  if (ui.sessionsBtn) ui.sessionsBtn.disabled = !authenticated;
  setRoleVisibility();

  if (!authenticated) {
    state.csrfToken = "";
    state.sessionId = "";
    state.twoFactorEnabled = false;
    ui.authStatus.textContent = "Not logged in.";
    setCloudinaryStatus("Log in to manage uploads.");
    state.products = [];
    state.orders = [];
    state.orderDetails = {};
    state.coupons = [];
    state.alerts = [];
    state.variantAlerts = [];
    state.carts = [];
    state.adminUsers = [];
    state.logs = [];
    state.expenses = [];
    state.analytics = null;
    ui.stats.products.textContent = "0";
    ui.stats.lowStock.textContent = "0";
    ui.stats.revenue.textContent = formatMoney(0);
    ui.stats.expenses.textContent = formatMoney(0);
    ui.stats.profit.textContent = formatMoney(0);
    ui.stats.abandoned.textContent = "0";
    [
      ui.inventory,
      ui.ordersList,
      ui.couponsList,
      ui.alertsList,
      ui.abandonedList,
      ui.adminUsersList,
      ui.auditList,
      ui.expensesList,
      ui.analyticsSummary,
      ui.analyticsTopProducts,
      ui.analyticsBrandSplit,
    ].forEach((panel) => setPanelMessage(panel, "Log in to see data."));
    return;
  }

  ui.authStatus.textContent = `Logged in as ${state.adminUsername} (${state.adminRole})${
    state.twoFactorEnabled ? " | 2FA enabled" : ""
  }`;
  setCloudinaryStatus("Checking Cloudinary configuration...");
  setRoleControlDisabled();
}

async function fetchAdmin(url, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };
  const isSafe = method === "GET" || method === "HEAD" || method === "OPTIONS";
  if (!isSafe && state.csrfToken && !headers["x-csrf-token"]) {
    headers["x-csrf-token"] = state.csrfToken;
  }
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) {
    setAuthState(false);
    throw new Error("Admin session expired. Log in again.");
  }
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function readFormPayload() {
  const priceNaira = Number.parseFloat(ui.fields.price.value || "0");
  const compareNaira = ui.fields.compare.value === "" ? null : Number.parseFloat(ui.fields.compare.value);
  const stockQty = Number.parseInt(ui.fields.stock.value || "0", 10);
  const reorderThreshold = Number.parseInt(ui.fields.reorderThreshold.value || "0", 10);
  if (Number.isNaN(priceNaira) || priceNaira < 0) throw new Error("Price must be valid.");
  if (compareNaira !== null && (Number.isNaN(compareNaira) || compareNaira < 0)) throw new Error("Compare At must be valid.");
  if (!Number.isInteger(stockQty) || stockQty < 0) throw new Error("Stock must be a non-negative integer.");
  if (!Number.isInteger(reorderThreshold) || reorderThreshold < 0) throw new Error("Reorder threshold must be a non-negative integer.");

  return {
    name: ui.fields.name.value.trim(),
    slug: ui.fields.slug.value.trim(),
    brand: ui.fields.brand.value,
    category: ui.fields.category.value.trim(),
    description: ui.fields.description.value.trim(),
    priceKobo: Math.round(priceNaira * 100),
    compareAtKobo: compareNaira === null ? null : Math.round(compareNaira * 100),
    stockQty,
    reorderThreshold,
    hasVariants: ui.fields.hasVariants.checked,
    imageUrl: ui.fields.imageUrl.value.trim(),
    galleryUrls: ui.fields.galleryUrls.value.split(",").map((url) => url.trim()).filter(Boolean),
    isFeatured: ui.fields.featured.checked,
  };
}

function populateForm(product) {
  ui.fields.id.value = String(product.id);
  ui.fields.name.value = product.name;
  ui.fields.slug.value = product.slug;
  ui.fields.brand.value = product.brand;
  ui.fields.category.value = product.category;
  ui.fields.description.value = product.description || "";
  ui.fields.price.value = String(Math.round(Number(product.priceKobo || 0) / 100));
  ui.fields.compare.value = product.compareAtKobo == null ? "" : String(Math.round(Number(product.compareAtKobo) / 100));
  ui.fields.stock.value = String(Number(product.stockQty || 0));
  ui.fields.reorderThreshold.value = String(Number(product.reorderThreshold || 0));
  ui.fields.hasVariants.checked = Boolean(product.hasVariants);
  ui.fields.featured.checked = Boolean(product.isFeatured);
  ui.fields.imageUrl.value = product.imageUrl || "";
  ui.fields.galleryUrls.value = (product.galleryUrls || []).join(", ");
}

function clearForm() {
  ui.form.reset();
  ui.fields.id.value = "";
  ui.fields.reorderThreshold.value = "0";
}

function renderInventory() {
  const q = ui.search.value.trim().toLowerCase();
  const filtered = state.products.filter((p) => p.name.toLowerCase().includes(q));
  ui.inventory.innerHTML = "";
  if (!filtered.length) return setPanelMessage(ui.inventory, "No products found.");

  for (const product of filtered) {
    const isLow = Number(product.stockQty || 0) <= Number(product.reorderThreshold || 0);
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(product.name)}</strong><span class="tag">${product.brand === "sholly-home" ? "Sholly" : "Apex"}</span></div>
      <p class="inv-meta">${escapeHtml(product.category)} | ${formatMoney(product.priceKobo)} | ${Number(product.stockQty || 0)} units | ${product.hasVariants ? "variants enabled" : "single SKU"}</p>
      <p class="inv-meta">Reorder threshold: ${Number(product.reorderThreshold || 0)} ${isLow ? "| LOW STOCK" : ""}</p>
      <div class="inv-actions">
        <button class="threshold-btn" type="button">Threshold</button>
        <button class="btn-alt variants-btn" type="button">Variants</button>
        <button class="edit-btn" type="button">Edit</button>
        <button class="delete-btn" type="button">Delete</button>
      </div>
    `;
    const thresholdBtn = node.querySelector(".threshold-btn");
    const variantsBtn = node.querySelector(".variants-btn");
    const editBtn = node.querySelector(".edit-btn");
    const deleteBtn = node.querySelector(".delete-btn");
    thresholdBtn.disabled = !canEditProducts();
    variantsBtn.disabled = !canEditProducts();
    editBtn.disabled = !canEditProducts();
    deleteBtn.disabled = !canManageOps();
    thresholdBtn.addEventListener("click", async () => {
      const raw = window.prompt(`Set reorder threshold for "${product.name}"`, String(product.reorderThreshold || 0));
      if (raw === null) return;
      const reorderThreshold = Number.parseInt(raw, 10);
      if (!Number.isInteger(reorderThreshold) || reorderThreshold < 0) return setToast("Threshold must be a non-negative integer.");
      await updateReorderThreshold(product.id, reorderThreshold);
    });
    editBtn.addEventListener("click", () => {
      populateForm(product);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
    variantsBtn.addEventListener("click", async () => {
      await manageVariants(product);
    });
    deleteBtn.addEventListener("click", async () => {
      if (window.confirm(`Delete "${product.name}"?`)) await deleteProduct(product.id);
    });
    ui.inventory.appendChild(node);
  }
}

async function fetchProducts({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const body = await fetchAdmin("/api/products?limit=500");
    state.products = Array.isArray(body.products) ? body.products : [];
    renderInventory();
  } catch (error) {
    setPanelMessage(ui.inventory, error.message);
    if (!silent) setToast(error.message);
  }
}

async function saveProduct(event) {
  event.preventDefault();
  if (!state.authenticated) return setToast("Please login first.");
  try {
    const payload = readFormPayload();
    const id = ui.fields.id.value;
    await fetchAdmin(id ? `/api/products/${id}` : "/api/products", {
      method: id ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setToast(id ? "Product updated." : "Product created.");
    clearForm();
    await Promise.all([fetchProducts({ silent: true }), fetchAlerts({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

async function deleteProduct(id) {
  try {
    await fetchAdmin(`/api/products/${id}`, { method: "DELETE" });
    setToast("Product deleted.");
    await Promise.all([fetchProducts({ silent: true }), fetchAlerts({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

async function updateReorderThreshold(id, reorderThreshold) {
  try {
    await fetchAdmin(`/api/products/${id}/reorder-threshold`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reorderThreshold }),
    });
    setToast("Reorder threshold updated.");
    await Promise.all([fetchProducts({ silent: true }), fetchAlerts({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

function formatVariantForPrompt(variant, index) {
  const bits = [variant.optionSize, variant.optionColor, variant.optionStyle].filter(Boolean).join(" / ");
  const price = variant.priceOverrideKobo == null ? "base price" : formatMoney(variant.priceOverrideKobo);
  return `${index + 1}. ${variant.sku} | ${bits || "no options"} | ${price} | stock: ${variant.stockQty}`;
}

async function manageVariants(product) {
  try {
    const body = await fetchAdmin(
      `/api/admin/products/${product.id}/variants?includeInactive=true`
    );
    const variants = Array.isArray(body.variants) ? body.variants : [];
    const list = variants.length
      ? variants.map((variant, index) => formatVariantForPrompt(variant, index)).join("\n")
      : "No variants yet.";
    const input = window.prompt(
      `Variants for ${product.name}\n${list}\n\nActions:\nA = add variant\nS<number> = stock adjust (e.g. S1)\nD<number> = delete variant\nLeave blank to close`
    );
    if (!input) return;
    const action = input.trim().toUpperCase();
    if (action === "A") {
      const raw = window.prompt(
        "Enter: sku,size,color,style,priceNaira(optional),stockQty,reorderThreshold,imageUrl(optional)"
      );
      if (!raw) return;
      const [sku, size, color, style, priceNairaRaw, stockQtyRaw, reorderRaw, imageUrlRaw] = raw
        .split(",")
        .map((value) => value.trim());
      const priceOverrideKobo =
        priceNairaRaw === undefined || priceNairaRaw === ""
          ? null
          : Math.round(Number.parseFloat(priceNairaRaw || "0") * 100);
      const stockQty = Number.parseInt(stockQtyRaw || "0", 10);
      const reorderThreshold = Number.parseInt(reorderRaw || "2", 10);
      if (!sku) throw new Error("SKU is required.");
      if (!Number.isInteger(stockQty) || stockQty < 0) throw new Error("stockQty must be >= 0.");
      if (!Number.isInteger(reorderThreshold) || reorderThreshold < 0) {
        throw new Error("reorderThreshold must be >= 0.");
      }
      await fetchAdmin(`/api/admin/products/${product.id}/variants`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sku,
          optionSize: size || null,
          optionColor: color || null,
          optionStyle: style || null,
          priceOverrideKobo:
            priceOverrideKobo == null || Number.isNaN(priceOverrideKobo) ? null : priceOverrideKobo,
          stockQty,
          reorderThreshold,
          imageUrl: imageUrlRaw || null,
          isActive: true,
        }),
      });
      setToast("Variant added.");
      await Promise.all([fetchProducts({ silent: true }), fetchAlerts({ silent: true })]);
      return;
    }

    if (action.startsWith("S")) {
      const idx = Number.parseInt(action.slice(1), 10);
      if (!Number.isInteger(idx) || idx < 1 || idx > variants.length) throw new Error("Invalid variant index.");
      const variant = variants[idx - 1];
      const deltaRaw = window.prompt(
        `Adjust stock for ${variant.sku}. Enter + or - integer delta (e.g. 5 or -2):`,
        "0"
      );
      if (!deltaRaw) return;
      const deltaQty = Number.parseInt(deltaRaw, 10);
      if (!Number.isInteger(deltaQty) || deltaQty === 0) throw new Error("deltaQty must be a non-zero integer.");
      await fetchAdmin(`/api/admin/variants/${variant.id}/stock`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          deltaQty,
          reason: "Admin stock adjustment",
        }),
      });
      setToast("Variant stock adjusted.");
      await Promise.all([fetchProducts({ silent: true }), fetchAlerts({ silent: true })]);
      return;
    }

    if (action.startsWith("D")) {
      const idx = Number.parseInt(action.slice(1), 10);
      if (!Number.isInteger(idx) || idx < 1 || idx > variants.length) throw new Error("Invalid variant index.");
      const variant = variants[idx - 1];
      if (!window.confirm(`Delete variant ${variant.sku}?`)) return;
      await fetchAdmin(`/api/admin/variants/${variant.id}`, { method: "DELETE" });
      setToast("Variant deleted.");
      await Promise.all([fetchProducts({ silent: true }), fetchAlerts({ silent: true })]);
      return;
    }
  } catch (error) {
    setToast(error.message);
  }
}

async function fetchCloudinaryStatus({ silent = false } = {}) {
  if (!state.authenticated) return setCloudinaryStatus("Log in to check Cloudinary status.");
  try {
    const body = await fetchAdmin("/api/admin/cloudinary/status");
    if (!body.enabled) return setCloudinaryStatus("Cloudinary not configured yet. Add env keys and restart backend.", true);
    setCloudinaryStatus(`Cloudinary connected (${body.cloudName || "unknown cloud"}), folder: ${body.folder || "sholly-store"}.`);
  } catch (error) {
    setCloudinaryStatus(error.message, true);
    if (!silent) setToast(error.message);
  }
}

async function uploadImageToCloudinary() {
  if (!state.authenticated) return setToast("Please login first.");
  const file = ui.imageFile.files && ui.imageFile.files[0];
  if (!file) return setToast("Choose an image file first.");
  const fd = new FormData();
  fd.append("image", file);
  const oldText = ui.uploadImage.textContent;
  ui.uploadImage.disabled = true;
  ui.uploadImage.textContent = "Uploading...";
  try {
    const body = await fetchAdmin("/api/admin/upload-image", { method: "POST", body: fd });
    ui.fields.imageUrl.value = body.url || "";
    setCloudinaryStatus(`Upload successful: ${file.name}`);
    setToast("Image uploaded.");
  } catch (error) {
    setCloudinaryStatus(error.message, true);
    setToast(error.message);
  } finally {
    ui.uploadImage.disabled = false;
    ui.uploadImage.textContent = oldText;
  }
}

async function fetchDashboard({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const body = await fetchAdmin("/api/admin/dashboard");
    const totalProducts = Number(body.inventory?.totalProducts || 0);
    const totalVariants = Number(body.inventory?.totalVariants || 0);
    const lowStockProducts = Number(body.inventory?.lowStockProducts || 0);
    const lowStockVariants = Number(body.inventory?.lowStockVariants || 0);
    ui.stats.products.textContent = `${totalProducts.toLocaleString("en-NG")} / ${totalVariants.toLocaleString("en-NG")}v`;
    ui.stats.lowStock.textContent = `${lowStockProducts.toLocaleString("en-NG")}P / ${lowStockVariants.toLocaleString(
      "en-NG"
    )}V`;
    ui.stats.revenue.textContent = formatMoney(body.sales?.totalRevenueKobo || 0);
    ui.stats.expenses.textContent = formatMoney(body.expenses?.totalExpensesKobo || 0);
    ui.stats.profit.textContent = formatMoney(body.net?.totalProfitKobo || 0);
    ui.stats.abandoned.textContent = Number(body.abandoned?.carts || 0).toLocaleString("en-NG");
  } catch (error) {
    if (!silent) setToast(error.message);
  }
}

async function manageShippingConfig() {
  if (!state.authenticated) return setToast("Login first.");
  try {
    const [settingsBody, rulesBody, blackoutsBody] = await Promise.all([
      fetchAdmin("/api/admin/shipping/settings"),
      fetchAdmin("/api/admin/shipping/rules?limit=20&includeInactive=true"),
      fetchAdmin("/api/admin/shipping/blackouts?limit=10&includeInactive=true"),
    ]);
    const settings = settingsBody.settings || {};
    const rules = Array.isArray(rulesBody.rules) ? rulesBody.rules : [];
    const blackouts = Array.isArray(blackoutsBody.blackouts) ? blackoutsBody.blackouts : [];
    const ruleLines = rules
      .slice(0, 8)
      .map((rule, index) => `${index + 1}. ${rule.stateText}${rule.cityText ? ` / ${rule.cityText}` : ""}: ${formatMoney(rule.feeKobo)}`)
      .join("\n");
    const blackoutLines = blackouts
      .slice(0, 5)
      .map((item, index) => `${index + 1}. ${formatDate(item.startsAt)} -> ${formatDate(item.endsAt)}${item.isActive ? "" : " [inactive]"}`)
      .join("\n");

    const action = window.prompt(
      `Shipping settings:\nDefault fee: ${formatMoney(settings.defaultFeeKobo || 0)}\nFree threshold: ${formatMoney(
        settings.freeShippingThresholdKobo || 0
      )}\nETA: ${settings.etaMinDays || 0}-${settings.etaMaxDays || 0} days\n\nRules:\n${ruleLines || "-"}\n\nBlackouts:\n${blackoutLines || "-"}\n\nActions:\nS = update settings\nR = add rule\nB = add blackout`
    );
    if (!action) return;
    const code = action.trim().toUpperCase();
    if (code === "S") {
      const input = window.prompt(
        "Enter defaultFeeNaira,freeThresholdNaira,etaMinDays,etaMaxDays",
        `${Math.round(Number(settings.defaultFeeKobo || 0) / 100)},${Math.round(
          Number(settings.freeShippingThresholdKobo || 0) / 100
        )},${Number(settings.etaMinDays || 1)},${Number(settings.etaMaxDays || 5)}`
      );
      if (!input) return;
      const [defaultFeeNaira, freeThresholdNaira, etaMinDays, etaMaxDays] = input
        .split(",")
        .map((value) => value.trim());
      await fetchAdmin("/api/admin/shipping/settings", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          defaultFeeKobo: Math.round(Number.parseFloat(defaultFeeNaira || "0") * 100),
          freeShippingThresholdKobo: Math.round(Number.parseFloat(freeThresholdNaira || "0") * 100),
          etaMinDays: Number.parseInt(etaMinDays || "1", 10),
          etaMaxDays: Number.parseInt(etaMaxDays || "5", 10),
        }),
      });
      setToast("Shipping settings updated.");
      return;
    }
    if (code === "R") {
      const input = window.prompt(
        "Enter state,city(optional),feeNaira,etaMinDays(optional),etaMaxDays(optional),priority(optional)"
      );
      if (!input) return;
      const [stateText, cityText, feeNaira, etaMinDays, etaMaxDays, priority] = input
        .split(",")
        .map((value) => value.trim());
      await fetchAdmin("/api/admin/shipping/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          stateText,
          cityText: cityText || null,
          feeKobo: Math.round(Number.parseFloat(feeNaira || "0") * 100),
          etaMinDays: etaMinDays ? Number.parseInt(etaMinDays, 10) : null,
          etaMaxDays: etaMaxDays ? Number.parseInt(etaMaxDays, 10) : null,
          priority: priority ? Number.parseInt(priority, 10) : 100,
          isActive: true,
        }),
      });
      setToast("Shipping rule added.");
      return;
    }
    if (code === "B") {
      const input = window.prompt("Enter startsAtISO,endsAtISO,note(optional)");
      if (!input) return;
      const [startsAt, endsAt, note] = input.split(",").map((value) => value.trim());
      await fetchAdmin("/api/admin/shipping/blackouts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          startsAt,
          endsAt,
          note: note || "",
          isActive: true,
        }),
      });
      setToast("Shipping blackout added.");
      return;
    }
  } catch (error) {
    setToast(error.message);
  }
}

function renderOrders() {
  ui.ordersList.innerHTML = "";
  if (!state.orders.length) return setPanelMessage(ui.ordersList, "No orders found.");

  for (const order of state.orders) {
    const node = document.createElement("article");
    node.className = "inv-item";
    const hasProof = Boolean(order.paymentProofUrl);
    const canSendReminder = order.status === "pending_payment";
    node.innerHTML = `
      <div class="inv-top">
        <strong>#${escapeHtml(order.orderNumber)}</strong>
        <span class="tag">${escapeHtml(ORDER_STATUS_LABELS[order.status] || order.status)}</span>
      </div>
      <p class="inv-meta">${escapeHtml(order.customerName || "Customer")} | ${formatMoney(order.totalKobo)} | ${Number(order.totalItems || 0)} item(s)</p>
      <p class="inv-meta">${escapeHtml(order.paymentChannel || "manual")} ${order.reference ? `| Ref: ${escapeHtml(order.reference)}` : ""}</p>
      <p class="inv-meta">Shipping: ${escapeHtml(order.shippingState || "-")}${order.shippingCity ? `, ${escapeHtml(order.shippingCity)}` : ""} | Fee: ${formatMoney(order.shippingFeeKobo || 0)}</p>
      <p class="inv-meta">Proof: ${escapeHtml(order.paymentProofStatus || "none")} | Reconciliation: ${escapeHtml(order.reconciliationStatus || "unreconciled")}</p>
      ${hasProof ? `<p class="muted">Customer uploaded payment proof.</p>` : ""}
      <p class="muted">${formatDate(order.createdAt)}</p>
      <div class="inv-actions">
        <select class="order-status-select"></select>
        <button class="edit-btn order-update-btn" type="button">Update</button>
        <button class="btn-alt order-details-btn" type="button">Details</button>
        ${hasProof ? '<button class="btn-alt order-proof-btn" type="button">Proof</button>' : ""}
        ${hasProof ? '<button class="btn-alt order-proof-approve-btn" type="button">Approve Proof</button>' : ""}
        ${hasProof ? '<button class="btn-alt order-proof-reject-btn" type="button">Reject Proof</button>' : ""}
        <button class="btn-alt order-reconcile-btn" type="button">Reconcile</button>
        <button class="btn-alt order-reminder-btn" type="button">Reminder WA</button>
      </div>
      <div class="muted order-details" hidden></div>
    `;

    const statusSelect = node.querySelector(".order-status-select");
    const updateBtn = node.querySelector(".order-update-btn");
    const detailsBtn = node.querySelector(".order-details-btn");
    const proofBtn = node.querySelector(".order-proof-btn");
    const approveBtn = node.querySelector(".order-proof-approve-btn");
    const rejectBtn = node.querySelector(".order-proof-reject-btn");
    const reconcileBtn = node.querySelector(".order-reconcile-btn");
    const reminderBtn = node.querySelector(".order-reminder-btn");
    const details = node.querySelector(".order-details");

    for (const status of ORDER_STATUSES) {
      const option = document.createElement("option");
      option.value = status;
      option.textContent = ORDER_STATUS_LABELS[status] || status;
      statusSelect.appendChild(option);
    }
    statusSelect.value = order.status;
    statusSelect.disabled = !canManageOps();
    updateBtn.disabled = !canManageOps();
    if (proofBtn) {
      proofBtn.disabled = false;
    }
    if (approveBtn) approveBtn.disabled = !canManageOps();
    if (rejectBtn) rejectBtn.disabled = !canManageOps();
    if (reconcileBtn) reconcileBtn.disabled = !canManageOps();
    reminderBtn.disabled = !canManageOps() || !canSendReminder;

    updateBtn.addEventListener("click", async () => {
      const note = window.prompt("Optional status update note:", "") || "";
      await updateOrderStatus(order.id, statusSelect.value, note);
    });

    if (proofBtn) {
      proofBtn.addEventListener("click", () => {
        if (!order.paymentProofUrl) return;
        window.open(order.paymentProofUrl, "_blank", "noopener,noreferrer");
      });
    }

    approveBtn?.addEventListener("click", async () => {
      await reviewPaymentProof(order.id, "approved");
    });
    rejectBtn?.addEventListener("click", async () => {
      await reviewPaymentProof(order.id, "rejected");
    });
    reconcileBtn?.addEventListener("click", async () => {
      const next = window.prompt(
        "Set reconciliation status: unreconciled | reconciled | disputed",
        order.reconciliationStatus || "unreconciled"
      );
      if (!next) return;
      await updateReconciliation(order.id, next.trim().toLowerCase());
    });

    reminderBtn.addEventListener("click", async () => {
      await sendPaymentReminder(order.id);
    });

    detailsBtn.addEventListener("click", async () => {
      if (!details.hidden) {
        details.hidden = true;
        return;
      }
      try {
        let detail = state.orderDetails[order.id];
        if (!detail) {
          detail = await fetchAdmin(`/api/orders/${order.id}`);
          state.orderDetails[order.id] = detail;
        }
        const lines = [];
        lines.push(`Customer: ${detail.order?.customerName || "-"}`);
        lines.push(
          `Shipping: ${detail.order?.shippingState || "-"}${
            detail.order?.shippingCity ? `, ${detail.order.shippingCity}` : ""
          } (${formatMoney(detail.order?.shippingFeeKobo || 0)})`
        );
        lines.push(
          `Payment: ${detail.order?.paymentChannel || "-"}${
            detail.order?.paymentReminderCount
              ? ` | reminders: ${Number(detail.order.paymentReminderCount || 0)}`
              : ""
          }`
        );
        lines.push(`Proof Status: ${detail.order?.paymentProofStatus || "none"}`);
        lines.push(`Reconciliation: ${detail.order?.reconciliationStatus || "unreconciled"}`);
        if (detail.order?.paymentProofUrl) {
          lines.push(`Proof URL: ${detail.order.paymentProofUrl}`);
        }
        if (detail.order?.paymentProofNote) {
          lines.push(`Proof Note: ${detail.order.paymentProofNote}`);
        }
        if (detail.order?.paymentVerifiedAt) {
          lines.push(
            `Payment Verified: ${formatDate(detail.order.paymentVerifiedAt)} by ${
              detail.order.paymentVerifiedBy || "system"
            }`
          );
        }
        lines.push("Items:");
        for (const item of detail.items || []) {
          lines.push(
            `- ${item.qty} x ${item.productName}${item.variantLabel ? ` [${item.variantLabel}]` : ""} (${formatMoney(item.lineTotalKobo)})`
          );
        }
        if (!(detail.items || []).length) lines.push("- none");
        lines.push("Status History:");
        for (const h of (detail.history || []).slice(-8)) {
          lines.push(`- ${formatDate(h.createdAt)}: ${h.previousStatus || "none"} -> ${h.newStatus} (${h.changedByUsername || "system"})`);
        }
        if (!(detail.history || []).length) lines.push("- none");
        details.textContent = lines.join("\n");
        details.hidden = false;
      } catch (error) {
        setToast(error.message);
      }
    });

    ui.ordersList.appendChild(node);
  }
}

async function fetchOrders({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const status = ui.ordersFilterStatus.value;
    const query = status ? `?status=${encodeURIComponent(status)}&limit=100` : "?limit=100";
    const body = await fetchAdmin(`/api/orders${query}`);
    state.orders = Array.isArray(body.orders) ? body.orders : [];
    state.orderDetails = {};
    renderOrders();
  } catch (error) {
    setPanelMessage(ui.ordersList, error.message);
    if (!silent) setToast(error.message);
  }
}

async function updateOrderStatus(orderId, status, note = "") {
  try {
    await fetchAdmin(`/api/orders/${orderId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, note }),
    });
    delete state.orderDetails[orderId];
    setToast("Order status updated.");
    await Promise.all([fetchOrders({ silent: true }), fetchDashboard({ silent: true }), fetchAnalytics({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

async function sendPaymentReminder(orderId) {
  const popup = window.open("", "_blank", "noopener,noreferrer");
  try {
    const body = await fetchAdmin(`/api/admin/orders/${orderId}/payment-reminder`, {
      method: "POST",
    });
    if (body.whatsappUrl) {
      if (popup) {
        popup.location.href = body.whatsappUrl;
      } else {
        window.location.href = body.whatsappUrl;
      }
    } else if (popup) {
      popup.close();
    }
    setToast("Payment reminder prepared in WhatsApp.");
    await fetchOrders({ silent: true });
  } catch (error) {
    if (popup) popup.close();
    setToast(error.message);
  }
}

async function reviewPaymentProof(orderId, decision) {
  try {
    const note =
      window.prompt(
        decision === "approved"
          ? "Optional note for approval:"
          : "Reason for rejection:",
        ""
      ) || "";
    await fetchAdmin(`/api/admin/orders/${orderId}/payment-proof`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        decision,
        note,
        setStatusPaid: decision === "approved",
      }),
    });
    setToast(`Payment proof ${decision}.`);
    await Promise.all([fetchOrders({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

async function updateReconciliation(orderId, reconciliationStatus) {
  try {
    const note = window.prompt("Optional reconciliation note:", "") || "";
    await fetchAdmin(`/api/admin/orders/${orderId}/reconciliation`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reconciliationStatus, note }),
    });
    setToast("Reconciliation status updated.");
    await fetchOrders({ silent: true });
  } catch (error) {
    setToast(error.message);
  }
}

function renderCoupons() {
  ui.couponsList.innerHTML = "";
  if (!state.coupons.length) return setPanelMessage(ui.couponsList, "No coupons found.");

  for (const coupon of state.coupons) {
    const discountText = coupon.discountType === "percent" ? `${coupon.discountValue}%` : formatMoney(coupon.discountValue || 0);
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top">
        <strong>${escapeHtml(coupon.code)}</strong>
        <span class="tag">${coupon.isActive ? "active" : "inactive"}</span>
      </div>
      <p class="inv-meta">${escapeHtml(coupon.discountType)} ${escapeHtml(discountText)} | Used: ${Number(coupon.usedCount || 0)}</p>
      <p class="inv-meta">Brand: ${escapeHtml(coupon.brand || "all")} | Min: ${formatMoney(coupon.minOrderKobo || 0)}</p>
      <p class="muted">Expires: ${formatDate(coupon.expiresAt)}</p>
      <div class="inv-actions">
        <button class="edit-btn coupon-toggle-btn" type="button">${coupon.isActive ? "Deactivate" : "Activate"}</button>
        <button class="btn-alt coupon-limit-btn" type="button">Usage Limit</button>
      </div>
    `;
    const toggleBtn = node.querySelector(".coupon-toggle-btn");
    const limitBtn = node.querySelector(".coupon-limit-btn");
    toggleBtn.disabled = !canManageOps();
    limitBtn.disabled = !canManageOps();
    toggleBtn.addEventListener("click", async () => updateCoupon(coupon.id, { isActive: !coupon.isActive }));
    limitBtn.addEventListener("click", async () => {
      const raw = window.prompt("Set usage limit (leave empty for unlimited):", coupon.usageLimit == null ? "" : String(coupon.usageLimit));
      if (raw === null) return;
      const usageLimit = raw.trim() === "" ? null : Number.parseInt(raw, 10);
      if (usageLimit !== null && (!Number.isInteger(usageLimit) || usageLimit <= 0)) return setToast("Usage limit must be a positive integer.");
      await updateCoupon(coupon.id, { usageLimit });
    });
    ui.couponsList.appendChild(node);
  }
}

async function fetchCoupons({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const body = await fetchAdmin("/api/admin/coupons?limit=200");
    state.coupons = Array.isArray(body.coupons) ? body.coupons : [];
    renderCoupons();
  } catch (error) {
    setPanelMessage(ui.couponsList, error.message);
    if (!silent) setToast(error.message);
  }
}

async function createCoupon(event) {
  event.preventDefault();
  if (!state.authenticated) return setToast("Please login first.");
  try {
    const usageLimitRaw = ui.couponFields.usageLimit.value.trim();
    const payload = {
      code: ui.couponFields.code.value.trim().toUpperCase(),
      description: ui.couponFields.description.value.trim(),
      discountType: ui.couponFields.type.value,
      discountValue: Number.parseInt(ui.couponFields.value.value || "0", 10),
      minOrderKobo: Number.parseInt(ui.couponFields.minOrder.value || "0", 10),
      brand: ui.couponFields.brand.value || null,
      usageLimit: usageLimitRaw ? Number.parseInt(usageLimitRaw, 10) : null,
    };
    if (!payload.code) throw new Error("Coupon code is required.");
    if (!Number.isInteger(payload.discountValue) || payload.discountValue <= 0) throw new Error("Discount value must be a positive integer.");
    if (!Number.isInteger(payload.minOrderKobo) || payload.minOrderKobo < 0) throw new Error("Min order must be a non-negative integer.");
    if (payload.usageLimit !== null && (!Number.isInteger(payload.usageLimit) || payload.usageLimit <= 0)) throw new Error("Usage limit must be a positive integer.");
    await fetchAdmin("/api/admin/coupons", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setToast("Coupon created.");
    ui.couponForm.reset();
    ui.couponFields.minOrder.value = "0";
    await Promise.all([fetchCoupons({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

async function updateCoupon(couponId, payload) {
  try {
    await fetchAdmin(`/api/admin/coupons/${couponId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setToast("Coupon updated.");
    await Promise.all([fetchCoupons({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

function renderAlerts() {
  ui.alertsList.innerHTML = "";
  if (!state.alerts.length && !state.variantAlerts.length) {
    return setPanelMessage(ui.alertsList, "No low-stock alerts.");
  }
  for (const product of state.alerts) {
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(product.name)}</strong><span class="tag">${product.brand === "sholly-home" ? "Sholly" : "Apex"}</span></div>
      <p class="inv-meta">Stock: ${Number(product.stockQty || 0)} | Threshold: ${Number(product.reorderThreshold || 0)} | Shortfall: ${Number(product.shortfall || 0)}</p>
      <div class="inv-actions"><button class="edit-btn alert-threshold-btn" type="button">Update Threshold</button></div>
    `;
    const btn = node.querySelector(".alert-threshold-btn");
    btn.disabled = !canEditProducts();
    btn.addEventListener("click", async () => {
      const raw = window.prompt(`Set reorder threshold for "${product.name}"`, String(product.reorderThreshold || 0));
      if (raw === null) return;
      const reorderThreshold = Number.parseInt(raw, 10);
      if (!Number.isInteger(reorderThreshold) || reorderThreshold < 0) return setToast("Threshold must be a non-negative integer.");
      await updateReorderThreshold(product.id, reorderThreshold);
    });
    ui.alertsList.appendChild(node);
  }
  for (const variant of state.variantAlerts) {
    const label =
      [variant.optionSize, variant.optionColor, variant.optionStyle].filter(Boolean).join(" / ") ||
      variant.sku ||
      `Variant #${variant.id}`;
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(variant.productName || "Product")} (${escapeHtml(label)})</strong><span class="tag">${escapeHtml(variant.productBrand === "sholly-home" ? "Sholly" : "Apex")}</span></div>
      <p class="inv-meta">Variant Stock: ${Number(variant.stockQty || 0)} | Threshold: ${Number(
        variant.reorderThreshold || 0
      )} | Shortfall: ${Number(variant.shortfall || 0)}</p>
      <div class="inv-actions"><button class="edit-btn variant-stock-btn" type="button">Adjust Stock</button></div>
    `;
    const btn = node.querySelector(".variant-stock-btn");
    btn.disabled = !canEditProducts();
    btn.addEventListener("click", async () => {
      const raw = window.prompt(`Enter stock delta for "${variant.productName}" (${label})`, "0");
      if (!raw) return;
      const deltaQty = Number.parseInt(raw, 10);
      if (!Number.isInteger(deltaQty) || deltaQty === 0) return setToast("Delta must be a non-zero integer.");
      await fetchAdmin(`/api/admin/variants/${variant.id}/stock`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deltaQty, reason: "Low-stock adjustment" }),
      });
      setToast("Variant stock adjusted.");
      await fetchAlerts({ silent: true });
    });
    ui.alertsList.appendChild(node);
  }
}

async function fetchAlerts({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const body = await fetchAdmin("/api/admin/inventory/alerts?limit=200");
    state.alerts = Array.isArray(body.alerts) ? body.alerts : [];
    state.variantAlerts = Array.isArray(body.variantAlerts) ? body.variantAlerts : [];
    renderAlerts();
  } catch (error) {
    setPanelMessage(ui.alertsList, error.message);
    if (!silent) setToast(error.message);
  }
}

function renderAbandonedCarts() {
  ui.abandonedList.innerHTML = "";
  if (!state.carts.length) return setPanelMessage(ui.abandonedList, "No abandoned carts.");
  for (const cart of state.carts) {
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(cart.customerName || "Anonymous")}</strong><span class="tag">${escapeHtml(cart.status)}</span></div>
      <p class="inv-meta">${Number(Array.isArray(cart.items) ? cart.items.length : 0)} line(s) | ${formatMoney(cart.subtotalKobo || 0)} | reminders: ${Number(cart.reminderCount || 0)}</p>
      <p class="inv-meta">${escapeHtml(cart.customerPhone || "-")} | ${escapeHtml(cart.customerEmail || "-")}</p>
      <p class="muted">Last seen: ${formatDate(cart.lastSeenAt)} | Last reminder: ${formatDate(cart.lastReminderAt)}</p>
      <div class="inv-actions">
        <button class="edit-btn cart-reminder-btn" type="button">Reminder WA</button>
        <button class="btn-alt cart-contacted-btn" type="button">Mark Contacted</button>
        <button class="btn-alt cart-recovered-btn" type="button">Recovered</button>
        <button class="btn-alt cart-converted-btn" type="button">Converted</button>
      </div>
    `;
    const reminderBtn = node.querySelector(".cart-reminder-btn");
    const contactedBtn = node.querySelector(".cart-contacted-btn");
    const recoveredBtn = node.querySelector(".cart-recovered-btn");
    const convertedBtn = node.querySelector(".cart-converted-btn");
    const disabled = !canManageOps();
    reminderBtn.disabled = disabled;
    contactedBtn.disabled = disabled;
    recoveredBtn.disabled = disabled;
    convertedBtn.disabled = disabled;
    reminderBtn.addEventListener("click", async () => sendAbandonedCartReminder(cart.sessionId));
    contactedBtn.addEventListener("click", async () => updateCartStatus(cart.sessionId, "contacted", false));
    recoveredBtn.addEventListener("click", async () => updateCartStatus(cart.sessionId, "recovered", false));
    convertedBtn.addEventListener("click", async () => updateCartStatus(cart.sessionId, "converted", false));
    ui.abandonedList.appendChild(node);
  }
}

async function fetchAbandonedCarts({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const body = await fetchAdmin("/api/admin/abandoned-carts?hours=1&limit=200");
    state.carts = Array.isArray(body.carts) ? body.carts : [];
    renderAbandonedCarts();
  } catch (error) {
    setPanelMessage(ui.abandonedList, error.message);
    if (!silent) setToast(error.message);
  }
}

async function updateCartStatus(sessionId, status, incrementReminder) {
  try {
    await fetchAdmin(`/api/admin/abandoned-carts/${encodeURIComponent(sessionId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, incrementReminder }),
    });
    setToast("Cart status updated.");
    await Promise.all([fetchAbandonedCarts({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

async function sendAbandonedCartReminder(sessionId) {
  const popup = window.open("", "_blank", "noopener,noreferrer");
  try {
    const body = await fetchAdmin(
      `/api/admin/abandoned-carts/${encodeURIComponent(sessionId)}/reminder`,
      { method: "POST" }
    );
    if (body.whatsappUrl) {
      if (popup) {
        popup.location.href = body.whatsappUrl;
      } else {
        window.location.href = body.whatsappUrl;
      }
    } else if (popup) {
      popup.close();
    }
    setToast("Cart reminder prepared in WhatsApp.");
    await Promise.all([fetchAbandonedCarts({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    if (popup) popup.close();
    setToast(error.message);
  }
}

function renderAdminUsers() {
  ui.adminUsersList.innerHTML = "";
  if (!state.adminUsers.length) return setPanelMessage(ui.adminUsersList, "No admin users found.");
  for (const user of state.adminUsers) {
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(user.username)}</strong><span class="tag">${escapeHtml(user.role)}</span></div>
      <p class="inv-meta">Last login: ${formatDate(user.lastLoginAt)}</p>
      <div class="two-col">
        <label>Role
          <select class="user-role-select">
            <option value="viewer">viewer</option>
            <option value="editor">editor</option>
            <option value="manager">manager</option>
            <option value="owner">owner</option>
          </select>
        </label>
        <label>Reset Password
          <input class="user-password-input" type="password" placeholder="Optional new password" />
        </label>
      </div>
      <label>Active <input class="user-active-input" type="checkbox" /></label>
      <div class="inv-actions"><button class="edit-btn user-save-btn" type="button">Save</button></div>
    `;
    const roleSelect = node.querySelector(".user-role-select");
    const passwordInput = node.querySelector(".user-password-input");
    const activeInput = node.querySelector(".user-active-input");
    const saveBtn = node.querySelector(".user-save-btn");
    roleSelect.value = user.role;
    activeInput.checked = Boolean(user.isActive);
    saveBtn.disabled = !isOwner();
    saveBtn.addEventListener("click", async () => {
      const payload = {};
      if (roleSelect.value !== user.role) payload.role = roleSelect.value;
      if (activeInput.checked !== Boolean(user.isActive)) payload.isActive = activeInput.checked;
      if (passwordInput.value.trim()) payload.password = passwordInput.value.trim();
      if (!Object.keys(payload).length) return setToast("No changes to save.");
      await updateAdminUser(user.id, payload);
    });
    ui.adminUsersList.appendChild(node);
  }
}

async function fetchAdminUsers({ silent = false } = {}) {
  if (!state.authenticated) return;
  if (!isOwner()) {
    setPanelMessage(ui.adminUsersList, "Owner role required to view or create admin users.");
    return;
  }
  try {
    const body = await fetchAdmin("/api/admin/users");
    state.adminUsers = Array.isArray(body.users) ? body.users : [];
    renderAdminUsers();
  } catch (error) {
    setPanelMessage(ui.adminUsersList, error.message);
    if (!silent) setToast(error.message);
  }
}

async function createAdminUser(event) {
  event.preventDefault();
  if (!state.authenticated) return setToast("Please login first.");
  try {
    const payload = {
      username: ui.adminUserFields.username.value.trim(),
      password: ui.adminUserFields.password.value,
      role: ui.adminUserFields.role.value,
    };
    if (!payload.username || !payload.password) throw new Error("Username and password are required.");
    await fetchAdmin("/api/admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setToast("Admin user created.");
    ui.adminUserForm.reset();
    await fetchAdminUsers({ silent: true });
  } catch (error) {
    setToast(error.message);
  }
}

async function updateAdminUser(userId, payload) {
  try {
    await fetchAdmin(`/api/admin/users/${userId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setToast("Admin user updated.");
    await fetchAdminUsers({ silent: true });
  } catch (error) {
    setToast(error.message);
  }
}

function renderAuditLogs() {
  ui.auditList.innerHTML = "";
  if (!state.logs.length) return setPanelMessage(ui.auditList, "No audit logs found.");
  for (const log of state.logs) {
    const node = document.createElement("article");
    node.className = "inv-item";
    const metadata = log.metadata && typeof log.metadata === "object" ? JSON.stringify(log.metadata) : "";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(log.action)}</strong><span class="tag">${escapeHtml(log.entityType || "-")}</span></div>
      <p class="inv-meta">${escapeHtml(log.adminUsername || "system")} | ${escapeHtml(String(log.entityId || "-"))}</p>
      <p class="muted">${formatDate(log.createdAt)}</p>
      <p class="muted">${escapeHtml(metadata)}</p>
    `;
    ui.auditList.appendChild(node);
  }
}

async function fetchAuditLogs({ silent = false } = {}) {
  if (!state.authenticated || !canViewAudit()) return;
  try {
    const body = await fetchAdmin("/api/admin/audit-logs?limit=120");
    state.logs = Array.isArray(body.logs) ? body.logs : [];
    renderAuditLogs();
  } catch (error) {
    setPanelMessage(ui.auditList, error.message);
    if (!silent) setToast(error.message);
  }
}

function renderExpenses() {
  ui.expensesList.innerHTML = "";
  if (!state.expenses.length) return setPanelMessage(ui.expensesList, "No expenses recorded.");
  for (const expense of state.expenses) {
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(expense.title)}</strong><span class="tag">${escapeHtml(expense.category || "general")}</span></div>
      <p class="inv-meta">${formatMoney(expense.amountKobo)} | ${formatDate(expense.spentAt)}</p>
      <p class="muted">${escapeHtml(expense.notes || "")}</p>
      <div class="inv-actions"><button class="delete-btn expense-delete-btn" type="button">Delete</button></div>
    `;
    const deleteBtn = node.querySelector(".expense-delete-btn");
    deleteBtn.disabled = !canManageOps();
    deleteBtn.addEventListener("click", async () => {
      if (window.confirm(`Delete expense "${expense.title}"?`)) await deleteExpense(expense.id);
    });
    ui.expensesList.appendChild(node);
  }
}

async function fetchExpenses({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const body = await fetchAdmin("/api/expenses?limit=200");
    state.expenses = Array.isArray(body.expenses) ? body.expenses : [];
    renderExpenses();
  } catch (error) {
    setPanelMessage(ui.expensesList, error.message);
    if (!silent) setToast(error.message);
  }
}

async function createExpense(event) {
  event.preventDefault();
  if (!state.authenticated) return setToast("Please login first.");
  try {
    const amountNaira = Number.parseFloat(ui.expenseFields.amount.value || "0");
    if (Number.isNaN(amountNaira) || amountNaira < 0) throw new Error("Amount must be non-negative.");
    let spentAt = null;
    if (ui.expenseFields.date.value) {
      const parsed = new Date(ui.expenseFields.date.value);
      if (Number.isNaN(parsed.getTime())) throw new Error("Expense date is invalid.");
      spentAt = parsed.toISOString();
    }
    const payload = {
      title: ui.expenseFields.title.value.trim(),
      category: ui.expenseFields.category.value.trim() || "general",
      amountKobo: Math.round(amountNaira * 100),
      notes: ui.expenseFields.notes.value.trim(),
      spentAt,
    };
    if (!payload.title) throw new Error("Expense title is required.");
    await fetchAdmin("/api/expenses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setToast("Expense added.");
    ui.expenseForm.reset();
    ui.expenseFields.category.value = "operations";
    await Promise.all([fetchExpenses({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

async function deleteExpense(expenseId) {
  try {
    await fetchAdmin(`/api/expenses/${expenseId}`, { method: "DELETE" });
    setToast("Expense deleted.");
    await Promise.all([fetchExpenses({ silent: true }), fetchDashboard({ silent: true })]);
  } catch (error) {
    setToast(error.message);
  }
}

function renderAnalytics() {
  const analytics = state.analytics;
  if (!analytics) {
    setPanelMessage(ui.analyticsSummary, "Analytics unavailable.");
    setPanelMessage(ui.analyticsTopProducts, "Analytics unavailable.");
    return setPanelMessage(ui.analyticsBrandSplit, "Analytics unavailable.");
  }

  const funnel = analytics.funnel || {};
  const successRate = Number(funnel.successRate || 0) * 100;
  ui.analyticsSummary.innerHTML = `
    <article class="inv-item">
      <div class="inv-top"><strong>Window: ${Number(analytics.windowDays || 0)} day(s)</strong><span class="tag">Funnel</span></div>
      <p class="inv-meta">Initiated: ${Number(funnel.initiatedOrders || 0)} | Successful: ${Number(funnel.successfulOrders || 0)}</p>
      <p class="inv-meta">Revenue: ${formatMoney(funnel.successfulRevenueKobo || 0)} | Avg: ${formatMoney(funnel.averageOrderKobo || 0)}</p>
      <p class="muted">Success Rate: ${successRate.toFixed(1)}%</p>
    </article>
  `;

  ui.analyticsTopProducts.innerHTML = "";
  for (const product of analytics.topProducts || []) {
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(product.productName || "Unknown")}</strong><span class="tag">${Number(product.unitsSold || 0)} sold</span></div>
      <p class="inv-meta">${formatMoney(product.revenueKobo || 0)}</p>
    `;
    ui.analyticsTopProducts.appendChild(node);
  }
  if (!(analytics.topProducts || []).length) setPanelMessage(ui.analyticsTopProducts, "No top products in selected window.");

  ui.analyticsBrandSplit.innerHTML = "";
  for (const brand of analytics.brandSplit || []) {
    const node = document.createElement("article");
    node.className = "inv-item";
    node.innerHTML = `
      <div class="inv-top"><strong>${escapeHtml(brand.brand || "Unknown")}</strong><span class="tag">${Number(brand.unitsSold || 0)} sold</span></div>
      <p class="inv-meta">${formatMoney(brand.revenueKobo || 0)}</p>
    `;
    ui.analyticsBrandSplit.appendChild(node);
  }
  if (!(analytics.brandSplit || []).length) setPanelMessage(ui.analyticsBrandSplit, "No brand split data in selected window.");
}

async function fetchAnalytics({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    const days = Number.parseInt(ui.analyticsWindow.value || "30", 10);
    state.analytics = await fetchAdmin(`/api/admin/analytics?days=${encodeURIComponent(days)}`);
    renderAnalytics();
  } catch (error) {
    setPanelMessage(ui.analyticsSummary, error.message);
    setPanelMessage(ui.analyticsTopProducts, error.message);
    setPanelMessage(ui.analyticsBrandSplit, error.message);
    if (!silent) setToast(error.message);
  }
}

async function refreshAllData({ silent = false } = {}) {
  if (!state.authenticated) return;
  await Promise.all([
    fetchProducts({ silent }),
    fetchCloudinaryStatus({ silent }),
    fetchDashboard({ silent }),
    fetchOrders({ silent }),
    fetchCoupons({ silent }),
    fetchAlerts({ silent }),
    fetchAbandonedCarts({ silent }),
    fetchExpenses({ silent }),
    fetchAnalytics({ silent }),
    isOwner() ? fetchAdminUsers({ silent }) : Promise.resolve(),
    canViewAudit() ? fetchAuditLogs({ silent }) : Promise.resolve(),
  ]);
}

async function checkAuth() {
  try {
    const response = await fetch("/api/admin/me", { credentials: "same-origin" });
    if (!response.ok) return setAuthState(false);
    const body = await response.json().catch(() => ({}));
    if (!body.authenticated) return setAuthState(false);
    setAuthState(true, {
      userId: body.userId,
      username: body.username,
      role: body.role,
      csrfToken: body.csrfToken || "",
      sessionId: body.sessionId || "",
      twoFactorEnabled: Boolean(body.twoFactorEnabled),
    });
  } catch (_error) {
    setAuthState(false);
  }
}

async function loginAdmin() {
  const username = ui.username.value.trim();
  const password = ui.password.value;
  if (!username || !password) return setToast("Enter username and password.");
  ui.loginBtn.disabled = true;
  const old = ui.loginBtn.textContent;
  ui.loginBtn.textContent = "Logging in...";
  try {
    const submit = async (totpCode = "") =>
      fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username, password, totpCode }),
      });

    let response = await submit("");
    let body = await response.json().catch(() => ({}));
    if (!response.ok && String(body.error || "").toLowerCase().includes("two-factor code is required")) {
      const input = window.prompt("Enter your 6-digit authenticator code:");
      const totpCode = String(input || "").trim();
      if (!totpCode) {
        throw new Error("Two-factor code is required.");
      }
      response = await submit(totpCode);
      body = await response.json().catch(() => ({}));
    }
    if (!response.ok) throw new Error(body.error || "Login failed.");
    setAuthState(true, {
      userId: body.userId,
      username: body.username || username,
      role: body.role || "viewer",
      csrfToken: body.csrfToken || "",
      sessionId: body.sessionId || "",
      twoFactorEnabled: Boolean(body.twoFactorEnabled),
    });
    ui.password.value = "";
    setToast("Login successful.");
    await refreshAllData({ silent: true });
  } catch (error) {
    setAuthState(false);
    setToast(error.message);
  } finally {
    ui.loginBtn.disabled = false;
    ui.loginBtn.textContent = old;
  }
}

async function logoutAdmin() {
  try {
    await fetch("/api/admin/logout", { method: "POST", credentials: "same-origin" });
  } catch (_error) {
    // ignore
  }
  setAuthState(false);
  clearForm();
  setToast("Logged out.");
}

async function setupTwoFactor() {
  if (!state.authenticated || !state.userId) return setToast("Login with a database admin account first.");
  try {
    const setup = await fetchAdmin("/api/admin/2fa/setup", { method: "POST" });
    const secret = String(setup.secret || "").trim();
    const hint = setup.otpauthUrl ? `\n\nOTP URI:\n${setup.otpauthUrl}` : "";
    window.alert(`2FA setup started.\nSecret: ${secret || "-"}${hint}`);
    const code = window.prompt("Enter the 6-digit code from your authenticator app:");
    if (!code) return;
    await fetchAdmin("/api/admin/2fa/verify-setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: String(code).trim() }),
    });
    setToast("2FA enabled.");
    await checkAuth();
  } catch (error) {
    setToast(error.message);
  }
}

async function disableTwoFactor() {
  if (!state.authenticated || !state.userId) return setToast("Login first.");
  try {
    const code = window.prompt("Enter current 2FA code to disable (if enabled):") || "";
    await fetchAdmin("/api/admin/2fa/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: String(code).trim() }),
    });
    setToast("2FA disabled.");
    await checkAuth();
  } catch (error) {
    setToast(error.message);
  }
}

async function showAdminSessions() {
  if (!state.authenticated) return setToast("Login first.");
  try {
    const body = await fetchAdmin("/api/admin/sessions");
    const sessions = Array.isArray(body.sessions) ? body.sessions : [];
    if (!sessions.length) {
      window.alert("No active sessions found.");
      return;
    }
    const lines = sessions.slice(0, 20).map((session, index) => {
      const current = session.current ? " (current)" : "";
      const revoked = session.revoked ? " [revoked]" : "";
      return `${index + 1}. ${session.sessionId}${current}${revoked} | ${session.ipAddress || "-"} | ${formatDate(session.lastSeenAt)}`;
    });
    const input = window.prompt(
      `Sessions:\n${lines.join("\n")}\n\nEnter number to revoke, or leave blank to close:`
    );
    if (!input) return;
    const idx = Number.parseInt(input, 10);
    if (!Number.isInteger(idx) || idx < 1 || idx > sessions.length) {
      setToast("Invalid selection.");
      return;
    }
    const selected = sessions[idx - 1];
    await fetchAdmin(`/api/admin/sessions/${encodeURIComponent(selected.sessionId)}/revoke`, {
      method: "POST",
    });
    setToast("Session revoked.");
  } catch (error) {
    setToast(error.message);
  }
}

function initEvents() {
  ui.loginBtn.addEventListener("click", loginAdmin);
  ui.logoutBtn.addEventListener("click", logoutAdmin);
  ui.twoFaSetupBtn?.addEventListener("click", setupTwoFactor);
  ui.twoFaDisableBtn?.addEventListener("click", disableTwoFactor);
  ui.sessionsBtn?.addEventListener("click", showAdminSessions);
  ui.form.addEventListener("submit", saveProduct);
  ui.resetForm.addEventListener("click", clearForm);
  ui.refreshList.addEventListener("click", () => fetchProducts());
  ui.search.addEventListener("input", renderInventory);
  ui.uploadImage.addEventListener("click", uploadImageToCloudinary);
  ui.refreshDashboard.addEventListener("click", () => fetchDashboard());
  ui.shippingConfigBtn?.addEventListener("click", manageShippingConfig);
  ui.refreshOrders.addEventListener("click", () => fetchOrders());
  ui.ordersFilterStatus.addEventListener("change", () => fetchOrders());
  ui.couponForm.addEventListener("submit", createCoupon);
  ui.refreshCoupons.addEventListener("click", () => fetchCoupons());
  ui.refreshAlerts.addEventListener("click", () => fetchAlerts());
  ui.refreshCarts.addEventListener("click", () => fetchAbandonedCarts());
  ui.adminUserForm.addEventListener("submit", createAdminUser);
  ui.refreshUsers.addEventListener("click", () => fetchAdminUsers());
  ui.refreshAudit.addEventListener("click", () => fetchAuditLogs());
  ui.expenseForm.addEventListener("submit", createExpense);
  ui.refreshExpenses.addEventListener("click", () => fetchExpenses());
  ui.refreshAnalytics.addEventListener("click", () => fetchAnalytics());
  ui.analyticsWindow.addEventListener("change", () => fetchAnalytics({ silent: true }));
}

async function init() {
  setAuthState(false);
  initEvents();
  await checkAuth();
  if (state.authenticated) await refreshAllData({ silent: true });
}

init().catch((error) => {
  console.error(error);
  setToast("Failed to load admin page.");
});
