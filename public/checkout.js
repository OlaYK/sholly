const currency = new Intl.NumberFormat("en-NG", {
  style: "currency",
  currency: "NGN",
  maximumFractionDigits: 0,
});

const state = {
  products: [],
  variantsByProduct: {},
  cart: [],
  coupon: null,
  cartSessionId: localStorage.getItem("cartSessionId") || "",
  publicConfig: {
    paystackEnabled: false,
    paystackPublicKey: "",
    moniepointEnabled: false,
    bankName: "",
    bankAccountName: "",
    bankAccountNumber: "",
    bankTransferInstructions:
      "Complete transfer, then send your order number on WhatsApp for confirmation.",
    defaultShippingFeeKobo: 0,
  },
  shipping: {
    shippingState: localStorage.getItem("checkoutShippingState") || "",
    shippingCity: localStorage.getItem("checkoutShippingCity") || "",
    shippingFeeKobo: 0,
    freeShippingApplied: false,
    loading: false,
    signature: "",
    errorSignature: "",
  },
};

const ui = {
  themeToggle: document.getElementById("theme-toggle"),
  form: document.getElementById("checkout-form"),
  checkoutBtn: document.getElementById("checkout-btn"),
  name: document.getElementById("checkout-name"),
  phone: document.getElementById("checkout-phone"),
  email: document.getElementById("checkout-email"),
  shippingState: document.getElementById("checkout-shipping-state"),
  shippingCity: document.getElementById("checkout-shipping-city"),
  paymentMethod: document.getElementById("checkout-payment-method"),
  notes: document.getElementById("checkout-notes"),
  bankTransferPanel: document.getElementById("bank-transfer-panel"),
  bankTransferBankName: document.getElementById("bank-transfer-bank-name"),
  bankTransferAccountName: document.getElementById("bank-transfer-account-name"),
  bankTransferAccountNumber: document.getElementById("bank-transfer-account-number"),
  bankTransferNote: document.getElementById("bank-transfer-note"),
  items: document.getElementById("checkout-items"),
  couponCode: document.getElementById("coupon-code"),
  applyCoupon: document.getElementById("apply-coupon"),
  couponNote: document.getElementById("coupon-note"),
  subtotal: document.getElementById("cart-subtotal"),
  discount: document.getElementById("cart-discount"),
  shipping: document.getElementById("cart-shipping"),
  total: document.getElementById("cart-total"),
  shippingNote: document.getElementById("shipping-note"),
  success: document.getElementById("checkout-success"),
  toast: document.getElementById("toast"),
};

function formatMoney(kobo = 0) {
  return currency.format(Number(kobo || 0) / 100);
}

function setToast(message) {
  ui.toast.textContent = message;
  ui.toast.classList.add("show");
  setTimeout(() => ui.toast.classList.remove("show"), 2800);
}

function setSuccess(message = "") {
  if (!message) {
    ui.success.hidden = true;
    ui.success.textContent = "";
    return;
  }
  ui.success.hidden = false;
  ui.success.textContent = message;
}

function normalizePhone(value) {
  return String(value || "").replace(/[^\d]/g, "");
}

function applyTheme(theme) {
  const nextTheme = theme === "dark" ? "dark" : "light";
  document.body.setAttribute("data-theme", nextTheme);
  const label = nextTheme === "light" ? "Switch to dark mode" : "Switch to light mode";
  ui.themeToggle.setAttribute("aria-label", label);
  ui.themeToggle.setAttribute("title", label);
  localStorage.setItem("storeTheme", nextTheme);
}

function loadCart() {
  try {
    const parsed = JSON.parse(localStorage.getItem("storeCart") || "[]");
    if (Array.isArray(parsed)) {
      state.cart = parsed
        .map((item) => ({
          productId: Number(item.productId),
          variantId:
            item.variantId === null || item.variantId === undefined
              ? null
              : Number(item.variantId),
          variantLabel: String(item.variantLabel || ""),
          qty: Number(item.qty || 0),
          snapshot: item.snapshot || null,
        }))
        .filter(
          (item) =>
            Number.isInteger(item.productId) &&
            item.productId > 0 &&
            Number.isInteger(item.qty) &&
            item.qty > 0 &&
            (item.variantId === null || (Number.isInteger(item.variantId) && item.variantId > 0))
        );
    }
  } catch (_error) {
    state.cart = [];
  }
}

function saveCart() {
  localStorage.setItem("storeCart", JSON.stringify(state.cart));
}

function getProductById(productId) {
  return state.products.find((item) => item.id === Number(productId)) || null;
}

function getVariantForProduct(productId, variantId) {
  if (variantId == null) return null;
  const list = state.variantsByProduct[String(productId)] || [];
  return list.find((variant) => Number(variant.id) === Number(variantId)) || null;
}

function variantLabel(variant) {
  if (!variant) return "";
  return [variant.optionSize, variant.optionColor, variant.optionStyle]
    .map((item) => String(item || "").trim())
    .filter(Boolean)
    .join(" / ");
}

async function ensureProductVariants(productId, { force = false } = {}) {
  const key = String(Number(productId));
  if (!force && Array.isArray(state.variantsByProduct[key])) {
    return state.variantsByProduct[key];
  }
  const response = await fetch(`/api/products/${encodeURIComponent(key)}/variants`);
  if (!response.ok) {
    state.variantsByProduct[key] = [];
    return [];
  }
  const body = await response.json().catch(() => ({}));
  const variants = Array.isArray(body.variants) ? body.variants : [];
  state.variantsByProduct[key] = variants;
  return variants;
}

async function loadProducts() {
  const response = await fetch("/api/products?limit=500");
  if (!response.ok) throw new Error("Failed to load products.");
  const body = await response.json().catch(() => ({}));
  state.products = Array.isArray(body.products) ? body.products : [];
}

async function sanitizeCartAgainstInventory() {
  const next = [];
  for (const item of state.cart) {
    const product = getProductById(item.productId);
    if (!product) continue;

    let variant = null;
    if (item.variantId != null) {
      await ensureProductVariants(item.productId);
      variant = getVariantForProduct(item.productId, item.variantId);
      if (!variant) continue;
    }

    const maxStock =
      variant != null ? Number(variant.stockQty || 0) : Number(product.stockQty || 0);
    if (!Number.isFinite(maxStock) || maxStock < 1) continue;

    next.push({
      ...item,
      qty: Math.max(1, Math.min(item.qty, maxStock)),
      variantLabel: item.variantLabel || variantLabel(variant) || "",
    });
  }
  state.cart = next;
  saveCart();
}

function cartItemPricing(item) {
  const product = getProductById(item.productId);
  const variant = getVariantForProduct(item.productId, item.variantId);
  const unitPriceKobo =
    variant && variant.priceOverrideKobo != null
      ? Number(variant.priceOverrideKobo)
      : Number(product?.priceKobo || item.snapshot?.priceKobo || 0);
  const maxStock =
    variant != null
      ? Number(variant.stockQty || 0)
      : Number(product?.stockQty || item.snapshot?.stockQty || item.qty);
  const lineTotalKobo = unitPriceKobo * item.qty;
  return { product, variant, unitPriceKobo, maxStock, lineTotalKobo };
}

function cartSubtotalKobo() {
  return state.cart.reduce((sum, item) => sum + cartItemPricing(item).lineTotalKobo, 0);
}

function cartBrands() {
  const brands = new Set();
  for (const item of state.cart) {
    const product = getProductById(item.productId);
    if (product?.brand) brands.add(product.brand);
  }
  return Array.from(brands);
}

function cartDiscountKobo(subtotalKobo = cartSubtotalKobo()) {
  if (!state.coupon) return 0;
  return Math.min(Number(state.coupon.discountKobo || 0), subtotalKobo);
}

function computeCartTotals() {
  const subtotalKobo = cartSubtotalKobo();
  const discountKobo = cartDiscountKobo(subtotalKobo);
  const discountedSubtotalKobo = Math.max(subtotalKobo - discountKobo, 0);
  const shippingFeeKobo = Number(state.shipping.shippingFeeKobo || 0);
  const totalKobo = discountedSubtotalKobo + shippingFeeKobo;
  return { subtotalKobo, discountKobo, discountedSubtotalKobo, shippingFeeKobo, totalKobo };
}

function shippingNoteText() {
  if (state.shipping.loading) return "Calculating shipping...";
  const shippingState = (ui.shippingState.value || "").trim();
  const shippingCity = (ui.shippingCity.value || "").trim();
  if (!shippingState) return "Enter your delivery state to calculate shipping.";
  if (state.shipping.freeShippingApplied) return "Free shipping applied.";
  const location = shippingCity ? `${shippingCity}, ${shippingState}` : shippingState;
  return `Shipping estimate for ${location}.`;
}

function renderCartTotals() {
  const totals = computeCartTotals();
  ui.subtotal.textContent = formatMoney(totals.subtotalKobo);
  ui.discount.textContent = formatMoney(totals.discountKobo);
  ui.shipping.textContent = formatMoney(totals.shippingFeeKobo);
  ui.total.textContent = formatMoney(totals.totalKobo);
  ui.shippingNote.textContent = shippingNoteText();
}

function clearCoupon(message = "") {
  state.coupon = null;
  ui.couponNote.textContent = message;
}

function updateCheckoutAvailability() {
  const hasItems = state.cart.length > 0;
  ui.checkoutBtn.disabled = !hasItems;
  ui.applyCoupon.disabled = !hasItems;
  if (!hasItems) {
    ui.items.innerHTML = `<article class="cart-empty">Your cart is empty. <a href="/">Continue shopping</a>.</article>`;
  }
}

function changeCartQty(productId, variantId, delta) {
  const item = state.cart.find(
    (entry) => Number(entry.productId) === Number(productId) && Number(entry.variantId || 0) === Number(variantId || 0)
  );
  if (!item) return;
  const { maxStock } = cartItemPricing(item);
  item.qty = Math.max(1, Math.min(item.qty + delta, maxStock));
  clearCoupon("Coupon removed because cart changed.");
  saveCart();
  renderCart();
  scheduleShippingQuote({ force: true });
}

function removeCartItem(productId, variantId = null) {
  state.cart = state.cart.filter(
    (entry) => !(Number(entry.productId) === Number(productId) && Number(entry.variantId || 0) === Number(variantId || 0))
  );
  clearCoupon("Coupon removed because cart changed.");
  saveCart();
  renderCart();
  scheduleShippingQuote({ force: true });
}

function renderCart() {
  ui.items.innerHTML = "";
  if (!state.cart.length) {
    updateCheckoutAvailability();
    renderCartTotals();
    return;
  }

  for (const item of state.cart) {
    const { product, variant, unitPriceKobo, lineTotalKobo, maxStock } = cartItemPricing(item);
    const baseName = product?.name || item.snapshot?.name || "Unavailable product";
    const variantText = item.variantLabel || variantLabel(variant) || "";
    const title = variantText ? `${baseName} (${variantText})` : baseName;
    const imageUrl =
      variant?.imageUrlThumb ||
      variant?.imageUrlOptimized ||
      variant?.imageUrl ||
      product?.imageUrlThumb ||
      product?.imageUrlOptimized ||
      product?.imageUrl ||
      item.snapshot?.imageUrl ||
      "";

    const node = document.createElement("article");
    node.className = "checkout-item";
    node.innerHTML = `
      <img src="${imageUrl}" alt="${baseName}" />
      <div>
        <h4>${title}</h4>
        <p>${formatMoney(unitPriceKobo)} each</p>
        <p>In stock: ${Math.max(Number(maxStock || 0), 0)}</p>
        <div class="checkout-item-controls">
          <div class="qty-controls">
            <button type="button" data-action="minus">-</button>
            <span>${item.qty}</span>
            <button type="button" data-action="plus">+</button>
          </div>
          <strong class="checkout-item-total">${formatMoney(lineTotalKobo)}</strong>
          <button type="button" class="remove-item">Delete</button>
        </div>
      </div>
    `;

    node.querySelector('[data-action="minus"]').addEventListener("click", () => {
      changeCartQty(item.productId, item.variantId, -1);
    });
    node.querySelector('[data-action="plus"]').addEventListener("click", () => {
      if (item.qty >= Number(maxStock || 0)) {
        setToast("Cannot exceed available stock.");
        return;
      }
      changeCartQty(item.productId, item.variantId, 1);
    });
    node.querySelector(".remove-item").addEventListener("click", () => {
      removeCartItem(item.productId, item.variantId);
    });
    ui.items.appendChild(node);
  }

  updateCheckoutAvailability();
  renderCartTotals();
}

async function applyCouponCode() {
  if (!state.cart.length) {
    setToast("Cart is empty.");
    return;
  }
  const code = (ui.couponCode.value || "").trim().toUpperCase();
  if (!code) {
    clearCoupon("Enter a coupon code.");
    renderCartTotals();
    return;
  }

  try {
    const response = await fetch("/api/coupons/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code,
        subtotalKobo: cartSubtotalKobo(),
        brands: cartBrands(),
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Coupon not valid.");
    state.coupon = {
      code,
      discountKobo: Number(body.discountKobo || 0),
      totalKobo: Number(body.totalKobo || 0),
      details: body.coupon || null,
    };
    ui.couponNote.textContent = `${code} applied successfully.`;
    renderCartTotals();
  } catch (error) {
    clearCoupon(error.message || "Coupon not valid.");
    renderCartTotals();
  }
}

let shippingTimer = null;
let shippingRequestId = 0;

function scheduleShippingQuote({ force = false } = {}) {
  if (shippingTimer) clearTimeout(shippingTimer);
  shippingTimer = setTimeout(() => {
    refreshShippingQuote({ force }).catch(() => {});
  }, 320);
}

async function refreshShippingQuote({ force = false } = {}) {
  const shippingState = (ui.shippingState.value || "").trim();
  const shippingCity = (ui.shippingCity.value || "").trim();
  state.shipping.shippingState = shippingState;
  state.shipping.shippingCity = shippingCity;
  localStorage.setItem("checkoutShippingState", shippingState);
  localStorage.setItem("checkoutShippingCity", shippingCity);

  const discountedSubtotalKobo = Math.max(cartSubtotalKobo() - cartDiscountKobo(), 0);
  const signature = `${shippingState.toLowerCase()}|${shippingCity.toLowerCase()}|${discountedSubtotalKobo}`;
  if (!force && signature === state.shipping.signature) return;
  state.shipping.signature = signature;

  if (!shippingState || !state.cart.length) {
    state.shipping.shippingFeeKobo = 0;
    state.shipping.freeShippingApplied = false;
    state.shipping.loading = false;
    renderCartTotals();
    return;
  }

  const requestId = ++shippingRequestId;
  state.shipping.loading = true;
  renderCartTotals();

  try {
    const params = new URLSearchParams({
      state: shippingState,
      city: shippingCity,
      subtotalKobo: String(discountedSubtotalKobo),
    });
    const response = await fetch(`/api/shipping/quote?${params.toString()}`);
    const body = await response.json().catch(() => ({}));
    if (requestId !== shippingRequestId) return;
    if (!response.ok) throw new Error(body.error || "Failed to calculate shipping.");
    state.shipping.shippingFeeKobo = Number(body.shippingFeeKobo || 0);
    state.shipping.freeShippingApplied = Boolean(body.freeShippingApplied);
    state.shipping.errorSignature = "";
  } catch (error) {
    if (requestId !== shippingRequestId) return;
    state.shipping.shippingFeeKobo = Number(state.publicConfig.defaultShippingFeeKobo || 0);
    state.shipping.freeShippingApplied = false;
    if (state.shipping.errorSignature !== signature) {
      state.shipping.errorSignature = signature;
      setToast(error.message || "Using default shipping estimate.");
    }
  } finally {
    if (requestId === shippingRequestId) {
      state.shipping.loading = false;
      renderCartTotals();
    }
  }
}

function syncCheckoutPaymentUI() {
  const paystackConfigured =
    Boolean(state.publicConfig.paystackEnabled) && Boolean(state.publicConfig.paystackPublicKey);
  const moniepointConfigured = Boolean(state.publicConfig.moniepointEnabled);
  const hasBankDetails =
    Boolean(state.publicConfig.bankName) &&
    Boolean(state.publicConfig.bankAccountName) &&
    Boolean(state.publicConfig.bankAccountNumber);

  const paystackOption = ui.paymentMethod.querySelector('option[value="paystack"]');
  const moniepointOption = ui.paymentMethod.querySelector('option[value="moniepoint"]');
  const bankOption = ui.paymentMethod.querySelector('option[value="bank_transfer"]');
  if (paystackOption) paystackOption.disabled = !paystackConfigured;
  if (moniepointOption) moniepointOption.disabled = !moniepointConfigured;
  if (bankOption) bankOption.disabled = !hasBankDetails && (paystackConfigured || moniepointConfigured);

  const enabledMethods = [];
  if (paystackConfigured) enabledMethods.push("paystack");
  if (moniepointConfigured) enabledMethods.push("moniepoint");
  if (hasBankDetails || (!paystackConfigured && !moniepointConfigured)) enabledMethods.push("bank_transfer");
  if (!enabledMethods.includes(ui.paymentMethod.value)) {
    ui.paymentMethod.value = enabledMethods[0] || "bank_transfer";
  }

  const method = ui.paymentMethod.value;
  const requiresEmail = method === "paystack" || method === "moniepoint";
  ui.email.required = requiresEmail;
  if (method === "moniepoint") {
    ui.checkoutBtn.textContent = "Pay with Moniepoint";
  } else if (method === "bank_transfer") {
    ui.checkoutBtn.textContent = "Place Bank Transfer Order";
  } else {
    ui.checkoutBtn.textContent = "Pay with Paystack";
  }
  ui.bankTransferPanel.hidden = method !== "bank_transfer";
}

async function loadPublicConfig() {
  const response = await fetch("/api/public-config");
  if (!response.ok) return;
  const body = await response.json().catch(() => ({}));
  state.publicConfig = {
    ...state.publicConfig,
    ...body,
  };
  ui.bankTransferBankName.textContent = state.publicConfig.bankName || "Not set";
  ui.bankTransferAccountName.textContent = state.publicConfig.bankAccountName || "Not set";
  ui.bankTransferAccountNumber.textContent = state.publicConfig.bankAccountNumber || "Not set";
  ui.bankTransferNote.textContent =
    state.publicConfig.bankTransferInstructions ||
    "Complete transfer, then send your order number on WhatsApp for confirmation.";
  syncCheckoutPaymentUI();
}

async function trackCartSession(statusOverride = null) {
  const items = state.cart.map((item) => ({
    productId: item.productId,
    variantId: item.variantId == null ? null : Number(item.variantId),
    qty: item.qty,
  }));
  const response = await fetch("/api/cart/track", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      sessionId: state.cartSessionId || null,
      customerName: ui.name.value.trim() || null,
      customerPhone: ui.phone.value.trim() || null,
      customerEmail: ui.email.value.trim() || null,
      status: statusOverride || (items.length ? "open" : "converted"),
      items,
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) return;
  if (body.sessionId) {
    state.cartSessionId = body.sessionId;
    localStorage.setItem("cartSessionId", body.sessionId);
  }
}

function buildCheckoutPayload() {
  return {
    customerName: ui.name.value.trim(),
    customerPhone: ui.phone.value.trim(),
    customerEmail: ui.email.value.trim() || null,
    shippingState: ui.shippingState.value.trim(),
    shippingCity: ui.shippingCity.value.trim() || null,
    notes: ui.notes.value.trim(),
    couponCode: state.coupon?.code || null,
    items: state.cart.map((item) => ({
      productId: item.productId,
      variantId: item.variantId == null ? null : Number(item.variantId),
      qty: item.qty,
    })),
  };
}

function resetCheckoutStateAfterSuccess() {
  state.cart = [];
  clearCoupon("");
  saveCart();
  state.shipping.shippingFeeKobo = 0;
  state.shipping.freeShippingApplied = false;
  state.shipping.signature = "";
  renderCart();
}

async function onOrderSuccess(message, orderNumber = "") {
  resetCheckoutStateAfterSuccess();
  setSuccess(message);
  setToast(message);
  if (orderNumber) {
    localStorage.setItem("lastOrderNumber", orderNumber);
  }
  await trackCartSession("converted");
}

async function verifyPaystackPayment(reference) {
  if (!reference) return;
  const response = await fetch("/api/paystack/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reference }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "Payment verification failed.");
  const orderNumber = body.order?.orderNumber || "";
  await onOrderSuccess(`Payment confirmed. Order: ${orderNumber}`, orderNumber);
}

async function verifyMoniepointPayment({ paymentReference = "", transactionReference = "" } = {}) {
  const payload = {};
  if (paymentReference) payload.paymentReference = paymentReference;
  if (transactionReference) payload.transactionReference = transactionReference;
  if (!payload.paymentReference && !payload.transactionReference) return;
  const response = await fetch("/api/moniepoint/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "Moniepoint verification failed.");
  const orderNumber = body.order?.orderNumber || "";
  await onOrderSuccess(`Payment confirmed. Order: ${orderNumber}`, orderNumber);
}

async function handleCheckoutSubmit(event) {
  event.preventDefault();
  if (!state.cart.length) {
    setToast("Your cart is empty.");
    return;
  }
  setSuccess("");

  const payload = buildCheckoutPayload();
  const paymentMethod = ui.paymentMethod.value || "paystack";
  if (!payload.customerName || !payload.customerPhone) {
    setToast("Full name and phone number are required.");
    return;
  }
  if (!payload.shippingState) {
    setToast("Delivery state is required.");
    return;
  }
  if ((paymentMethod === "paystack" || paymentMethod === "moniepoint") && !payload.customerEmail) {
    setToast("Email is required for online payment.");
    return;
  }

  ui.checkoutBtn.disabled = true;
  const oldText = ui.checkoutBtn.textContent;
  ui.checkoutBtn.textContent = "Processing...";

  try {
    if (paymentMethod === "bank_transfer") {
      const response = await fetch("/api/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...payload,
          paymentMethod: "bank_transfer",
        }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Checkout failed.");
      const orderNumber = body.order?.orderNumber || "";
      await onOrderSuccess(`Order created: ${orderNumber}. Awaiting payment verification.`, orderNumber);
      return;
    }

    if (paymentMethod === "moniepoint") {
      const response = await fetch("/api/moniepoint/initialize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Payment initialization failed.");
      const checkoutUrl = body?.payment?.checkoutUrl;
      if (!checkoutUrl) throw new Error("Moniepoint checkout URL missing.");
      window.location.href = checkoutUrl;
      return;
    }

    const response = await fetch("/api/paystack/initialize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Payment initialization failed.");

    const payment = body.payment || {};
    const reference = payment.reference;
    const amountKobo = Number(payment.amountKobo || 0);
    const publicKey = payment.publicKey || state.publicConfig.paystackPublicKey;
    if (!reference || !amountKobo || !publicKey) {
      throw new Error("Paystack configuration is incomplete.");
    }

    if (window.PaystackPop && typeof window.PaystackPop.setup === "function") {
      const handler = window.PaystackPop.setup({
        key: publicKey,
        email: payload.customerEmail,
        amount: amountKobo,
        ref: reference,
        callback: async (paystackResponse) => {
          const paidReference = paystackResponse.reference || reference;
          await verifyPaystackPayment(paidReference);
        },
        onClose: () => {
          setToast("Payment window closed.");
        },
      });
      handler.openIframe();
      return;
    }

    if (payment.authorizationUrl) {
      window.location.href = payment.authorizationUrl;
      return;
    }

    throw new Error("Unable to open Paystack payment dialog.");
  } catch (error) {
    setToast(error.message || "Checkout failed.");
  } finally {
    ui.checkoutBtn.disabled = false;
    ui.checkoutBtn.textContent = oldText;
    syncCheckoutPaymentUI();
  }
}

async function handlePaystackRedirect() {
  const params = new URLSearchParams(window.location.search);
  const reference = String(params.get("reference") || params.get("trxref") || "").trim();
  if (!reference) return;
  await verifyPaystackPayment(reference);
  params.delete("reference");
  params.delete("trxref");
  const query = params.toString();
  window.history.replaceState({}, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
}

async function handleMoniepointRedirect() {
  const params = new URLSearchParams(window.location.search);
  const referenceParam = String(params.get("reference") || "").trim();
  const paymentReference =
    String(params.get("paymentReference") || "").trim() ||
    (referenceParam.startsWith("SSMON-") ? referenceParam : "");
  const transactionReference =
    String(params.get("transactionReference") || "").trim() ||
    String(params.get("transactionRef") || "").trim();
  if (!paymentReference && !transactionReference) return;
  await verifyMoniepointPayment({ paymentReference, transactionReference });
  [
    "paymentReference",
    "transactionReference",
    "transactionRef",
    "paymentStatus",
    "status",
    "reference",
  ].forEach((key) => params.delete(key));
  const query = params.toString();
  window.history.replaceState({}, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
}

function wireEvents() {
  ui.themeToggle.addEventListener("click", () => {
    const current = document.body.getAttribute("data-theme") || "light";
    applyTheme(current === "dark" ? "light" : "dark");
  });

  ui.form.addEventListener("submit", handleCheckoutSubmit);
  ui.paymentMethod.addEventListener("change", syncCheckoutPaymentUI);
  ui.shippingState.addEventListener("input", () => scheduleShippingQuote({ force: true }));
  ui.shippingCity.addEventListener("input", () => scheduleShippingQuote({ force: true }));
  ui.applyCoupon.addEventListener("click", applyCouponCode);
  ui.couponCode.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      applyCouponCode();
    }
  });
  [ui.name, ui.phone, ui.email, ui.shippingState, ui.shippingCity].forEach((input) => {
    input.addEventListener("change", () => trackCartSession("open").catch(() => {}));
  });
}

async function init() {
  const storedTheme = localStorage.getItem("storeTheme") || "light";
  applyTheme(storedTheme);
  wireEvents();

  ui.shippingState.value = state.shipping.shippingState;
  ui.shippingCity.value = state.shipping.shippingCity;

  loadCart();
  await Promise.all([loadPublicConfig(), loadProducts()]);
  await sanitizeCartAgainstInventory();
  renderCart();
  syncCheckoutPaymentUI();
  await refreshShippingQuote({ force: true });
  await trackCartSession("open");
  await handleMoniepointRedirect();
  await handlePaystackRedirect();
}

init().catch((error) => {
  console.error(error);
  setToast("Failed to load checkout page.");
});
