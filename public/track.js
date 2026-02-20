const ORDER_STATUS_LABELS = {
  pending_payment: "Pending Payment",
  paid: "Paid",
  processing: "Processing",
  shipped: "Shipped",
  delivered: "Delivered",
  cancelled: "Cancelled",
  refunded: "Refunded",
};

const currency = new Intl.NumberFormat("en-NG", {
  style: "currency",
  currency: "NGN",
  maximumFractionDigits: 0,
});

const ui = {
  themeToggle: document.getElementById("track-theme-toggle"),
  form: document.getElementById("track-form"),
  submit: document.getElementById("track-submit"),
  orderNumber: document.getElementById("track-order-number"),
  customerPhone: document.getElementById("track-customer-phone"),
  message: document.getElementById("track-message"),
  result: document.getElementById("track-result"),
  orderId: document.getElementById("track-order-id"),
  statusPill: document.getElementById("track-status-pill"),
  summary: document.getElementById("track-summary"),
  items: document.getElementById("track-items"),
  history: document.getElementById("track-history"),
  proofPanel: document.getElementById("track-proof-panel"),
  proofForm: document.getElementById("track-proof-form"),
  proofFile: document.getElementById("track-proof-file"),
  proofUrl: document.getElementById("track-proof-url"),
  proofNote: document.getElementById("track-proof-note"),
  proofSubmit: document.getElementById("track-proof-submit"),
  proofExisting: document.getElementById("track-proof-existing"),
  proofLink: document.getElementById("track-proof-link"),
  proofNoteView: document.getElementById("track-proof-note-view"),
  whatsapp: document.getElementById("track-whatsapp"),
  toast: document.getElementById("track-toast"),
};

const state = {
  lookup: {
    orderNumber: "",
    customerPhone: "",
  },
  order: null,
  publicConfig: {
    whatsappNumber: "2348101653634",
  },
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatMoney(kobo = 0) {
  return currency.format(Number(kobo || 0) / 100);
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString("en-NG");
}

function normalizePhone(value) {
  return String(value || "").replace(/[^\d]/g, "");
}

function setToast(message) {
  ui.toast.textContent = message;
  ui.toast.classList.add("show");
  setTimeout(() => ui.toast.classList.remove("show"), 2600);
}

function setMessage(message, isError = false) {
  ui.message.textContent = message;
  ui.message.style.color = isError ? "var(--danger-text)" : "var(--gold-soft)";
}

function applyTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.body.setAttribute("data-theme", next);
  ui.themeToggle.textContent = next === "light" ? "Dark Mode" : "Light Mode";
  localStorage.setItem("storeTheme", next);
}

function setStatusPill(status) {
  const normalized = String(status || "").trim().toLowerCase();
  ui.statusPill.className = "track-status-pill";
  if (normalized) {
    ui.statusPill.classList.add(normalized);
  }
  ui.statusPill.textContent = ORDER_STATUS_LABELS[normalized] || normalized || "-";
}

function buildStoreWhatsAppUrl(order) {
  const phone = normalizePhone(state.publicConfig.whatsappNumber || "2348101653634");
  const message = order
    ? `Hello, I need help with order ${order.orderNumber}.`
    : "Hello, I need help with my order.";
  return `https://wa.me/${phone}?text=${encodeURIComponent(message)}`;
}

function renderList(container, rows) {
  container.innerHTML = "";
  if (!rows.length) {
    const item = document.createElement("li");
    item.textContent = "No records.";
    container.appendChild(item);
    return;
  }
  for (const row of rows) {
    const item = document.createElement("li");
    item.innerHTML = row;
    container.appendChild(item);
  }
}

function renderOrder(data) {
  const order = data.order || null;
  if (!order) return;

  state.order = order;
  ui.result.hidden = false;
  ui.orderId.textContent = `#${order.orderNumber}`;
  setStatusPill(order.status);

  ui.summary.innerHTML = `
    <article>
      <small>Total</small>
      <strong>${escapeHtml(formatMoney(order.totalKobo || 0))}</strong>
    </article>
    <article>
      <small>Payment</small>
      <strong>${escapeHtml(order.paymentChannel || "-")}</strong>
    </article>
    <article>
      <small>Shipping</small>
      <strong>${escapeHtml(order.shippingState || "-")}${
        order.shippingCity ? `, ${escapeHtml(order.shippingCity)}` : ""
      }</strong>
    </article>
    <article>
      <small>Updated</small>
      <strong>${escapeHtml(formatDate(order.updatedAt))}</strong>
    </article>
  `;

  renderList(
    ui.items,
    (data.items || []).map(
      (item) =>
        `<strong>${Number(item.qty || 0)} x ${escapeHtml(item.productName || "-")}${
          item.variantLabel ? ` <em>(${escapeHtml(item.variantLabel)})</em>` : ""
        }</strong><br /><span class="muted">${escapeHtml(formatMoney(item.lineTotalKobo || 0))}</span>`
    )
  );

  renderList(
    ui.history,
    (data.history || []).map(
      (item) =>
        `<strong>${escapeHtml(formatDate(item.createdAt))}</strong><br /><span>${escapeHtml(
          `${item.previousStatus || "none"} -> ${item.newStatus}`
        )}</span><br /><span class="muted">${escapeHtml(item.note || "")}</span>`
    )
  );

  const canUploadProof = Boolean(order.canUploadProof);
  ui.proofPanel.hidden = !canUploadProof;

  if (order.paymentProofUrl) {
    ui.proofExisting.hidden = false;
    ui.proofLink.href = order.paymentProofUrl;
    ui.proofNoteView.textContent = order.paymentProofNote
      ? `Note: ${order.paymentProofNote}`
      : `Uploaded: ${formatDate(order.paymentProofUploadedAt)}`;
  } else {
    ui.proofExisting.hidden = true;
    ui.proofLink.href = "#";
    ui.proofNoteView.textContent = "";
  }

  ui.whatsapp.href = buildStoreWhatsAppUrl(order);
}

async function fetchPublicConfig() {
  const response = await fetch("/api/public-config");
  if (!response.ok) return;
  const body = await response.json().catch(() => ({}));
  state.publicConfig = {
    ...state.publicConfig,
    ...body,
  };
  ui.whatsapp.href = buildStoreWhatsAppUrl(state.order);
}

async function trackOrder(orderNumber, customerPhone, { silent = false } = {}) {
  const response = await fetch("/api/track/order", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      orderNumber,
      customerPhone,
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (!silent) {
      ui.result.hidden = true;
      setMessage(body.error || "Order not found.", true);
      setToast(body.error || "Order not found.");
    }
    throw new Error(body.error || "Order not found.");
  }
  state.lookup.orderNumber = orderNumber;
  state.lookup.customerPhone = customerPhone;
  setMessage("Order found.");
  renderOrder(body);
  return body;
}

async function submitPaymentProof(event) {
  event.preventDefault();
  if (!state.lookup.orderNumber || !state.lookup.customerPhone) {
    setToast("Track your order first.");
    return;
  }

  const file = ui.proofFile.files?.[0] || null;
  const proofUrl = ui.proofUrl.value.trim();
  const note = ui.proofNote.value.trim();
  if (!file && !proofUrl) {
    setToast("Upload an image file or provide proof URL.");
    return;
  }

  const fd = new FormData();
  fd.append("orderNumber", state.lookup.orderNumber);
  fd.append("customerPhone", state.lookup.customerPhone);
  fd.append("note", note);
  if (file) fd.append("proof", file);
  if (proofUrl) fd.append("proofUrl", proofUrl);

  const oldText = ui.proofSubmit.textContent;
  ui.proofSubmit.disabled = true;
  ui.proofSubmit.textContent = "Submitting...";

  try {
    const response = await fetch("/api/track/order/payment-proof", {
      method: "POST",
      body: fd,
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || "Failed to submit payment proof.");
    }
    setToast("Payment proof uploaded.");
    ui.proofForm.reset();
    await trackOrder(state.lookup.orderNumber, state.lookup.customerPhone, { silent: true });
  } catch (error) {
    setToast(error.message);
  } finally {
    ui.proofSubmit.disabled = false;
    ui.proofSubmit.textContent = oldText;
  }
}

function initReveal() {
  const items = Array.from(document.querySelectorAll(".reveal"));
  items.forEach((item, index) => {
    setTimeout(() => item.classList.add("revealed"), 70 * index);
  });
}

function initEvents() {
  ui.themeToggle.addEventListener("click", () => {
    const current = document.body.getAttribute("data-theme") || "dark";
    applyTheme(current === "dark" ? "light" : "dark");
  });

  ui.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const orderNumber = ui.orderNumber.value.trim();
    const customerPhone = ui.customerPhone.value.trim();
    if (!orderNumber || !customerPhone) {
      setToast("Order number and phone are required.");
      return;
    }
    const oldText = ui.submit.textContent;
    ui.submit.disabled = true;
    ui.submit.textContent = "Checking...";
    try {
      await trackOrder(orderNumber, customerPhone);
    } catch (_error) {
      // handled in trackOrder
    } finally {
      ui.submit.disabled = false;
      ui.submit.textContent = oldText;
    }
  });

  ui.proofForm.addEventListener("submit", submitPaymentProof);
}

async function init() {
  const storedTheme = localStorage.getItem("storeTheme") || "dark";
  applyTheme(storedTheme);
  initEvents();
  initReveal();
  await fetchPublicConfig();
}

init().catch((error) => {
  console.error(error);
  setToast("Failed to load tracking page.");
});
