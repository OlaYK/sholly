const money = new Intl.NumberFormat("en-NG", {
  style: "currency",
  currency: "NGN",
  maximumFractionDigits: 0,
});

const state = {
  authenticated: false,
  csrfToken: "",
  sessionId: "",
  customer: null,
  orders: [],
  addresses: [],
  wishlist: [],
};

const ui = {
  themeToggle: document.getElementById("theme-toggle"),
  toast: document.getElementById("toast"),
  authPanel: document.getElementById("auth-panel"),
  profilePanel: document.getElementById("profile-panel"),
  ordersPanel: document.getElementById("orders-panel"),
  addressesPanel: document.getElementById("addresses-panel"),
  wishlistPanel: document.getElementById("wishlist-panel"),
  modeLogin: document.getElementById("mode-login"),
  modeRegister: document.getElementById("mode-register"),
  loginForm: document.getElementById("login-form"),
  registerForm: document.getElementById("register-form"),
  loginEmail: document.getElementById("login-email"),
  loginPassword: document.getElementById("login-password"),
  registerFullName: document.getElementById("register-full-name"),
  registerPhone: document.getElementById("register-phone"),
  registerEmail: document.getElementById("register-email"),
  registerPassword: document.getElementById("register-password"),
  logoutBtn: document.getElementById("logout-btn"),
  profileName: document.getElementById("profile-name"),
  profileEmail: document.getElementById("profile-email"),
  profilePhone: document.getElementById("profile-phone"),
  profileCreated: document.getElementById("profile-created"),
  refreshOrders: document.getElementById("refresh-orders"),
  refreshAddresses: document.getElementById("refresh-addresses"),
  refreshWishlist: document.getElementById("refresh-wishlist"),
  ordersList: document.getElementById("orders-list"),
  addressesList: document.getElementById("addresses-list"),
  wishlistList: document.getElementById("wishlist-list"),
  addressForm: document.getElementById("address-form"),
  addressLabel: document.getElementById("address-label"),
  addressRecipient: document.getElementById("address-recipient"),
  addressPhone: document.getElementById("address-phone"),
  addressState: document.getElementById("address-state"),
  addressLine1: document.getElementById("address-line1"),
  addressLine2: document.getElementById("address-line2"),
  addressCity: document.getElementById("address-city"),
  addressCountry: document.getElementById("address-country"),
  addressPostal: document.getElementById("address-postal"),
  addressDefault: document.getElementById("address-default"),
};

function formatMoney(kobo = 0) {
  return money.format(Number(kobo || 0) / 100);
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : date.toLocaleString("en-NG");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setToast(message) {
  ui.toast.textContent = message;
  ui.toast.classList.add("show");
  setTimeout(() => ui.toast.classList.remove("show"), 2600);
}

function setListMessage(container, message) {
  container.innerHTML = `<p class="list-empty">${escapeHtml(message)}</p>`;
}

function applyTheme(theme) {
  const nextTheme = theme === "light" ? "light" : "dark";
  document.body.setAttribute("data-theme", nextTheme);
  const label = nextTheme === "light" ? "Switch to dark mode" : "Switch to light mode";
  ui.themeToggle.setAttribute("aria-label", label);
  ui.themeToggle.setAttribute("title", label);
  localStorage.setItem("accountTheme", nextTheme);
}

function setAuthMode(mode) {
  const login = mode !== "register";
  ui.modeLogin.classList.toggle("active", login);
  ui.modeRegister.classList.toggle("active", !login);
  ui.loginForm.hidden = !login;
  ui.registerForm.hidden = login;
}

function resetAddressForm() {
  ui.addressForm.reset();
  ui.addressLabel.value = "Home";
  ui.addressCountry.value = "Nigeria";
  ui.addressDefault.checked = false;
}

function setAuthState(authenticated, payload = {}) {
  state.authenticated = Boolean(authenticated);
  if (state.authenticated) {
    state.csrfToken = payload.csrfToken || state.csrfToken || "";
    state.sessionId = payload.sessionId || state.sessionId || "";
    state.customer = payload.customer || state.customer || null;
  } else {
    state.csrfToken = "";
    state.sessionId = "";
    state.customer = null;
    state.orders = [];
    state.addresses = [];
    state.wishlist = [];
  }

  ui.authPanel.hidden = state.authenticated;
  ui.profilePanel.hidden = !state.authenticated;
  ui.ordersPanel.hidden = !state.authenticated;
  ui.addressesPanel.hidden = !state.authenticated;
  ui.wishlistPanel.hidden = !state.authenticated;

  renderProfile();
  renderOrders();
  renderAddresses();
  renderWishlist();
}

async function fetchCustomer(url, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };
  const isSafe = method === "GET" || method === "HEAD" || method === "OPTIONS";
  if (!isSafe && state.csrfToken && !headers["x-customer-csrf-token"]) {
    headers["x-customer-csrf-token"] = state.csrfToken;
  }

  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) {
    setAuthState(false);
    throw new Error("Session expired. Please login again.");
  }
  if (!response.ok) {
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return body;
}

function renderProfile() {
  if (!state.authenticated || !state.customer) {
    ui.profileName.textContent = "-";
    ui.profileEmail.textContent = "-";
    ui.profilePhone.textContent = "-";
    ui.profileCreated.textContent = "-";
    return;
  }
  ui.profileName.textContent = state.customer.fullName || "-";
  ui.profileEmail.textContent = state.customer.email || "-";
  ui.profilePhone.textContent = state.customer.phone || "-";
  ui.profileCreated.textContent = formatDate(state.customer.createdAt);
}

function renderOrders() {
  if (!state.authenticated) return setListMessage(ui.ordersList, "Login to view your orders.");
  if (!state.orders.length) return setListMessage(ui.ordersList, "No orders yet.");

  ui.ordersList.innerHTML = "";
  for (const order of state.orders) {
    const node = document.createElement("article");
    node.className = "item";
    node.innerHTML = `
      <strong>${escapeHtml(order.orderNumber || "Order")}</strong>
      <span class="tag">${escapeHtml(order.status || "pending")}</span>
      <p class="item-meta">${formatMoney(order.totalKobo || 0)} | ${formatDate(order.createdAt)}</p>
      <p class="item-meta">Payment: ${escapeHtml(order.paymentChannel || "manual")} ${
      order.reference ? `| Ref: ${escapeHtml(order.reference)}` : ""
    }</p>
      <div class="item-row">
        <button class="btn btn-small reorder-btn" type="button">
          <span class="label-with-icon">
            <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="9" cy="20" r="1.5"></circle>
              <circle cx="17" cy="20" r="1.5"></circle>
              <path d="M3 4h2l2.4 11h10.8l2.1-8H7.2"></path>
            </svg>
            <span>Reorder to Cart</span>
          </span>
        </button>
        <a class="icon-btn btn-small" href="/track">
          <span class="label-with-icon">
            <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M12 21s7-6.5 7-12a7 7 0 0 0-14 0c0 5.5 7 12 7 12z"></path>
              <circle cx="12" cy="9" r="2.4"></circle>
            </svg>
            <span>Track Order</span>
          </span>
        </a>
      </div>
    `;
    const reorderBtn = node.querySelector(".reorder-btn");
    reorderBtn.addEventListener("click", async () => {
      await reorderOrder(order.id);
    });
    ui.ordersList.appendChild(node);
  }
}

function renderAddresses() {
  if (!state.authenticated) return setListMessage(ui.addressesList, "Login to manage addresses.");
  if (!state.addresses.length) return setListMessage(ui.addressesList, "No saved addresses yet.");

  ui.addressesList.innerHTML = "";
  for (const address of state.addresses) {
    const node = document.createElement("article");
    node.className = "item";
    node.innerHTML = `
      <strong>${escapeHtml(address.label || "Address")}</strong>
      ${address.isDefault ? '<span class="tag">Default</span>' : ""}
      <p class="item-meta">${escapeHtml(address.recipientName || "-")} | ${escapeHtml(address.recipientPhone || "-")}</p>
      <p class="item-meta">${escapeHtml(address.line1 || "-")}${address.line2 ? `, ${escapeHtml(address.line2)}` : ""}</p>
      <p class="item-meta">${escapeHtml(address.city || "-")}, ${escapeHtml(address.state || "-")} ${escapeHtml(
      address.country || "Nigeria"
    )}</p>
      <div class="item-row">
        <button class="btn btn-small default-address-btn" type="button" ${
          address.isDefault ? "disabled" : ""
        }>
          <span class="label-with-icon">
            <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M20 6v5h-5"></path>
              <path d="M4 18v-5h5"></path>
              <path d="M6 9a7.5 7.5 0 0 1 12.6-2"></path>
              <path d="M18 15a7.5 7.5 0 0 1-12.6 2"></path>
            </svg>
            <span>Set Default</span>
          </span>
        </button>
        <button class="icon-btn btn-small edit-address-btn" type="button">
          <span class="label-with-icon">
            <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M3 17.3V21h3.7L18 9.7 14.3 6 3 17.3z"></path>
              <path d="m13.5 6.8 3.7 3.7"></path>
            </svg>
            <span>Edit</span>
          </span>
        </button>
        <button class="icon-btn btn-small delete-address-btn danger" type="button">
          <span class="label-with-icon">
            <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M3 6h18"></path>
              <path d="M8 6V4h8v2"></path>
              <path d="M7 6l1 14h8l1-14"></path>
            </svg>
            <span>Delete</span>
          </span>
        </button>
      </div>
    `;
    node.querySelector(".default-address-btn").addEventListener("click", async () => {
      await setDefaultAddress(address.id);
    });
    node.querySelector(".edit-address-btn").addEventListener("click", async () => {
      await editAddress(address);
    });
    node.querySelector(".delete-address-btn").addEventListener("click", async () => {
      await deleteAddress(address.id);
    });
    ui.addressesList.appendChild(node);
  }
}

function variantText(variant) {
  if (!variant) return "";
  const parts = [variant.optionSize, variant.optionColor, variant.optionStyle].filter(Boolean);
  return parts.join(" / ") || variant.sku || "";
}

function renderWishlist() {
  if (!state.authenticated) return setListMessage(ui.wishlistList, "Login to view wishlist.");
  if (!state.wishlist.length) return setListMessage(ui.wishlistList, "Wishlist is empty.");

  ui.wishlistList.innerHTML = "";
  for (const entry of state.wishlist) {
    const product = entry.product || {};
    const variant = entry.variant || null;
    const priceKobo =
      variant && variant.priceOverrideKobo != null
        ? Number(variant.priceOverrideKobo)
        : Number(product.priceKobo || 0);
    const node = document.createElement("article");
    node.className = "item";
    node.innerHTML = `
      <strong>${escapeHtml(product.name || "Product")}</strong>
      <span class="tag">${escapeHtml(product.brand === "apex-apparel" ? "Apex" : "Sholly")}</span>
      <p class="item-meta">${formatMoney(priceKobo)}${variantText(variant) ? ` | ${escapeHtml(variantText(variant))}` : ""}</p>
      <p class="item-meta">${escapeHtml(product.category || "-")}</p>
      <div class="item-row">
        <a class="icon-btn btn-small" href="/">
          <span class="label-with-icon">
            <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M10 6l-6 6 6 6"></path>
              <path d="M4 12h16"></path>
            </svg>
            <span>Open Store</span>
          </span>
        </a>
        <button class="icon-btn btn-small remove-wishlist-btn danger" type="button">
          <span class="label-with-icon">
            <svg class="btn-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M3 6h18"></path>
              <path d="M8 6V4h8v2"></path>
              <path d="M7 6l1 14h8l1-14"></path>
            </svg>
            <span>Remove</span>
          </span>
        </button>
      </div>
    `;
    node.querySelector(".remove-wishlist-btn").addEventListener("click", async () => {
      await removeWishlistItem(entry.id);
    });
    ui.wishlistList.appendChild(node);
  }
}

async function fetchOrders() {
  const body = await fetchCustomer("/api/customer/orders?limit=50");
  state.orders = Array.isArray(body.orders) ? body.orders : [];
  renderOrders();
}

async function fetchAddresses() {
  const body = await fetchCustomer("/api/customer/addresses");
  state.addresses = Array.isArray(body.addresses) ? body.addresses : [];
  renderAddresses();
}

async function fetchWishlist() {
  const body = await fetchCustomer("/api/customer/wishlist");
  state.wishlist = Array.isArray(body.items) ? body.items : [];
  renderWishlist();
}

async function loadCustomerData({ silent = false } = {}) {
  if (!state.authenticated) return;
  try {
    await Promise.all([fetchOrders(), fetchAddresses(), fetchWishlist()]);
  } catch (error) {
    if (!silent) setToast(error.message);
  }
}

async function checkSession() {
  try {
    const response = await fetch("/api/customer/me", { credentials: "same-origin" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.authenticated) {
      setAuthState(false);
      return;
    }
    setAuthState(true, {
      csrfToken: body.csrfToken || "",
      sessionId: body.sessionId || "",
      customer: body.customer || null,
    });
    await loadCustomerData({ silent: true });
  } catch (_error) {
    setAuthState(false);
  }
}

async function login(event) {
  event.preventDefault();
  try {
    const email = ui.loginEmail.value.trim();
    const password = ui.loginPassword.value;
    if (!email || !password) throw new Error("Email and password are required.");
    const response = await fetch("/api/customer/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Login failed.");
    setAuthState(true, {
      csrfToken: body.csrfToken || "",
      sessionId: body.sessionId || "",
      customer: body.customer || null,
    });
    ui.loginPassword.value = "";
    setToast("Logged in.");
    await loadCustomerData({ silent: true });
  } catch (error) {
    setToast(error.message);
  }
}

async function register(event) {
  event.preventDefault();
  try {
    const payload = {
      fullName: ui.registerFullName.value.trim(),
      phone: ui.registerPhone.value.trim(),
      email: ui.registerEmail.value.trim(),
      password: ui.registerPassword.value,
    };
    if (!payload.fullName || !payload.phone || !payload.email || !payload.password) {
      throw new Error("All registration fields are required.");
    }
    const response = await fetch("/api/customer/register", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Registration failed.");
    setAuthState(true, {
      csrfToken: body.csrfToken || "",
      sessionId: body.sessionId || "",
      customer: body.customer || null,
    });
    ui.registerPassword.value = "";
    setToast("Account created.");
    await loadCustomerData({ silent: true });
  } catch (error) {
    setToast(error.message);
  }
}

async function logout() {
  try {
    await fetchCustomer("/api/customer/logout", { method: "POST" });
  } catch (_error) {
    // ignore
  }
  setAuthState(false);
  setAuthMode("login");
  setToast("Logged out.");
}

async function handleAddressSubmit(event) {
  event.preventDefault();
  if (!state.authenticated) return setToast("Please login first.");
  const payload = {
    label: ui.addressLabel.value.trim() || "Home",
    recipientName: ui.addressRecipient.value.trim(),
    recipientPhone: ui.addressPhone.value.trim(),
    line1: ui.addressLine1.value.trim(),
    line2: ui.addressLine2.value.trim(),
    city: ui.addressCity.value.trim(),
    state: ui.addressState.value.trim(),
    country: ui.addressCountry.value.trim() || "Nigeria",
    postalCode: ui.addressPostal.value.trim(),
    isDefault: ui.addressDefault.checked,
  };
  if (!payload.recipientName || !payload.recipientPhone || !payload.line1 || !payload.city || !payload.state) {
    return setToast("Recipient, phone, line1, city and state are required.");
  }
  try {
    await fetchCustomer("/api/customer/addresses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    resetAddressForm();
    setToast("Address added.");
    await fetchAddresses();
  } catch (error) {
    setToast(error.message);
  }
}

async function setDefaultAddress(addressId) {
  try {
    await fetchCustomer(`/api/customer/addresses/${encodeURIComponent(addressId)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ isDefault: true }),
    });
    setToast("Default address updated.");
    await fetchAddresses();
  } catch (error) {
    setToast(error.message);
  }
}

async function editAddress(address) {
  const recipientName = window.prompt("Recipient name:", address.recipientName || "");
  if (recipientName === null) return;
  const recipientPhone = window.prompt("Recipient phone:", address.recipientPhone || "");
  if (recipientPhone === null) return;
  const line1 = window.prompt("Address line 1:", address.line1 || "");
  if (line1 === null) return;
  const city = window.prompt("City:", address.city || "");
  if (city === null) return;
  const stateText = window.prompt("State:", address.state || "");
  if (stateText === null) return;
  const label = window.prompt("Label:", address.label || "Home");
  if (label === null) return;
  const line2 = window.prompt("Address line 2 (optional):", address.line2 || "");
  if (line2 === null) return;
  const country = window.prompt("Country:", address.country || "Nigeria");
  if (country === null) return;
  const postalCode = window.prompt("Postal code (optional):", address.postalCode || "");
  if (postalCode === null) return;

  try {
    await fetchCustomer(`/api/customer/addresses/${encodeURIComponent(address.id)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: label.trim() || "Home",
        recipientName: recipientName.trim(),
        recipientPhone: recipientPhone.trim(),
        line1: line1.trim(),
        line2: line2.trim(),
        city: city.trim(),
        state: stateText.trim(),
        country: country.trim() || "Nigeria",
        postalCode: postalCode.trim(),
      }),
    });
    setToast("Address updated.");
    await fetchAddresses();
  } catch (error) {
    setToast(error.message);
  }
}

async function deleteAddress(addressId) {
  if (!window.confirm("Delete this address?")) return;
  try {
    await fetchCustomer(`/api/customer/addresses/${encodeURIComponent(addressId)}`, {
      method: "DELETE",
    });
    setToast("Address deleted.");
    await fetchAddresses();
  } catch (error) {
    setToast(error.message);
  }
}

async function removeWishlistItem(itemId) {
  try {
    await fetchCustomer(`/api/customer/wishlist/items/${encodeURIComponent(itemId)}`, {
      method: "DELETE",
    });
    setToast("Wishlist item removed.");
    await fetchWishlist();
  } catch (error) {
    setToast(error.message);
  }
}

async function reorderOrder(orderId) {
  try {
    const body = await fetchCustomer(`/api/customer/orders/${encodeURIComponent(orderId)}/reorder`, {
      method: "POST",
    });
    const items = Array.isArray(body.items) ? body.items : [];
    if (!items.length) throw new Error("No available items from this order.");
    const cart = items
      .map((item) => ({
        productId: Number(item.productId),
        variantId: item.variantId == null ? null : Number(item.variantId),
        qty: Number(item.qty || 0),
        variantLabel: "",
        snapshot: null,
      }))
      .filter((item) => Number.isInteger(item.productId) && item.productId > 0 && Number.isInteger(item.qty) && item.qty > 0);
    if (!cart.length) throw new Error("No valid reorder items found.");
    localStorage.setItem("storeCart", JSON.stringify(cart));
    setToast("Cart prepared. Redirecting to store...");
    setTimeout(() => {
      window.location.href = "/";
    }, 380);
  } catch (error) {
    setToast(error.message);
  }
}

function wireEvents() {
  ui.themeToggle.addEventListener("click", () => {
    const current = document.body.getAttribute("data-theme") || "dark";
    applyTheme(current === "dark" ? "light" : "dark");
  });
  ui.modeLogin.addEventListener("click", () => setAuthMode("login"));
  ui.modeRegister.addEventListener("click", () => setAuthMode("register"));
  ui.loginForm.addEventListener("submit", login);
  ui.registerForm.addEventListener("submit", register);
  ui.logoutBtn.addEventListener("click", logout);
  ui.refreshOrders.addEventListener("click", () => fetchOrders().catch((error) => setToast(error.message)));
  ui.refreshAddresses.addEventListener("click", () => fetchAddresses().catch((error) => setToast(error.message)));
  ui.refreshWishlist.addEventListener("click", () => fetchWishlist().catch((error) => setToast(error.message)));
  ui.addressForm.addEventListener("submit", handleAddressSubmit);
}

async function init() {
  const savedTheme = localStorage.getItem("accountTheme") || "dark";
  applyTheme(savedTheme);
  setAuthMode("login");
  setAuthState(false);
  resetAddressForm();
  wireEvents();
  await checkSession();
}

init().catch((error) => {
  console.error(error);
  setToast("Failed to initialize account page.");
});
