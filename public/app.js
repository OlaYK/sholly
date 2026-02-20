const currency = new Intl.NumberFormat("en-NG", {
  style: "currency",
  currency: "NGN",
  maximumFractionDigits: 0,
});

const BRAND_COPY = {
  "sholly-home": {
    label: "Currently Viewing: Sholly Home",
    title: "Curated Luxury For Elevated Living",
    description: "Luxury bedding and decor designed for comfort, depth and elegant interiors.",
    logoUrl: "/sholly.jpg",
    logoAlt: "Sholly and Shaddy's logo",
    headerMain: "SHOLLY & SHADDY'S",
    headerSub: "LUXURY BEDS",
  },
  "apex-apparel": {
    label: "Currently Viewing: Apex Apparel",
    title: "Premium Native Fashion, Tailored To Stand Out",
    description: "Modern traditionalwear and statement pieces crafted for ceremonies and everyday style.",
    logoUrl: "/apex.jpg",
    logoAlt: "Apex Apparel logo",
    headerMain: "APEX APPAREL",
    headerSub: "SIGNATURE FASHION",
  },
};

const state = {
  products: [],
  variantsByProduct: {},
  customerAuth: {
    authenticated: false,
    csrfToken: "",
  },
  activeBrand: localStorage.getItem("activeBrand") || "sholly-home",
  filters: {
    "sholly-home": { category: "all", query: "" },
    "apex-apparel": { category: "all", query: "" },
  },
  cart: [],
  modalProduct: null,
  modalVariants: [],
  modalVariantId: null,
  lastCatalogSignature: "",
  cartSessionId: localStorage.getItem("cartSessionId") || "",
  checkoutShipping: {
    shippingState: localStorage.getItem("checkoutShippingState") || "",
    shippingCity: localStorage.getItem("checkoutShippingCity") || "",
    shippingFeeKobo: 0,
    freeShippingApplied: false,
    signature: "",
    loading: false,
    errorSignature: "",
  },
  coupon: null,
  publicConfig: {
    paystackPublicKey: "",
    paystackEnabled: false,
    moniepointEnabled: false,
    instagramShollyUrl: "",
    instagramApexUrl: "",
    whatsappNumber: "2348101653634",
    bankName: "",
    bankAccountName: "",
    bankAccountNumber: "",
    bankTransferInstructions:
      "Complete transfer, then send your order number on WhatsApp for confirmation.",
    defaultShippingFeeKobo: 0,
    freeShippingThresholdKobo: 0,
  },
};

const ui = {
  topbar: document.getElementById("topbar"),
  sections: {
    "sholly-home": document.getElementById("sholly-section"),
    "apex-apparel": document.getElementById("apex-section"),
  },
  grids: {
    "sholly-home": document.getElementById("grid-sholly"),
    "apex-apparel": document.getElementById("grid-apex"),
  },
  categorySelects: {
    "sholly-home": document.getElementById("filter-sholly-category"),
    "apex-apparel": document.getElementById("filter-apex-category"),
  },
  searchInputs: {
    "sholly-home": document.getElementById("filter-sholly-search"),
    "apex-apparel": document.getElementById("filter-apex-search"),
  },
  switches: Array.from(document.querySelectorAll("[data-brand-switch]")),
  metrics: {
    products: document.getElementById("metric-products"),
    units: document.getElementById("metric-units"),
    value: document.getElementById("metric-value"),
  },
  heroLabel: document.getElementById("hero-brand-label"),
  heroTitle: document.getElementById("hero-title"),
  heroDescription: document.getElementById("hero-description"),
  menuToggle: document.getElementById("menu-toggle"),
  topbarActions: document.getElementById("topbar-actions"),
  brandLogo: document.getElementById("brandmark-logo"),
  brandMain: document.getElementById("brandmark-main"),
  brandSub: document.getElementById("brandmark-sub"),
  igSholly: document.getElementById("ig-sholly-link"),
  igApex: document.getElementById("ig-apex-link"),
  themeToggle: document.getElementById("theme-toggle"),
  template: document.getElementById("card-template"),
  toast: document.getElementById("toast"),
  modal: document.getElementById("product-modal"),
  modalName: document.getElementById("modal-name"),
  modalBrand: document.getElementById("modal-brand"),
  modalImage: document.getElementById("modal-image"),
  modalPrice: document.getElementById("modal-price"),
  modalCompare: document.getElementById("modal-compare"),
  modalDescription: document.getElementById("modal-description"),
  modalStock: document.getElementById("modal-stock"),
  modalVariantWrap: document.getElementById("modal-variant-wrap"),
  modalVariantSelect: document.getElementById("modal-variant-select"),
  modalVariantHint: document.getElementById("modal-variant-hint"),
  modalWhatsApp: document.getElementById("modal-whatsapp"),
  modalWishlist: document.getElementById("modal-wishlist"),
  modalAddCart: document.getElementById("modal-add-cart"),
  modalClose: document.getElementById("modal-close"),
  cartOpen: document.getElementById("cart-open"),
  cartClose: document.getElementById("cart-close"),
  cartBackdrop: document.getElementById("cart-backdrop"),
  cartDrawer: document.getElementById("cart-drawer"),
  cartItems: document.getElementById("cart-items"),
  cartSubtotal: document.getElementById("cart-subtotal"),
  cartDiscount: document.getElementById("cart-discount"),
  cartShipping: document.getElementById("cart-shipping"),
  cartTotal: document.getElementById("cart-total"),
  shippingNote: document.getElementById("shipping-note"),
  cartCount: document.getElementById("cart-count"),
  couponCode: document.getElementById("coupon-code"),
  applyCoupon: document.getElementById("apply-coupon"),
  couponNote: document.getElementById("coupon-note"),
  checkoutForm: document.getElementById("checkout-form"),
  checkoutName: document.getElementById("checkout-name"),
  checkoutPhone: document.getElementById("checkout-phone"),
  checkoutEmail: document.getElementById("checkout-email"),
  checkoutShippingState: document.getElementById("checkout-shipping-state"),
  checkoutShippingCity: document.getElementById("checkout-shipping-city"),
  checkoutPaymentMethod: document.getElementById("checkout-payment-method"),
  checkoutNotes: document.getElementById("checkout-notes"),
  checkoutBtn: document.getElementById("checkout-btn"),
  bankTransferPanel: document.getElementById("bank-transfer-panel"),
  bankTransferBankName: document.getElementById("bank-transfer-bank-name"),
  bankTransferAccountName: document.getElementById("bank-transfer-account-name"),
  bankTransferAccountNumber: document.getElementById("bank-transfer-account-number"),
  bankTransferNote: document.getElementById("bank-transfer-note"),
  waFloat: document.getElementById("wa-float"),
};

function formatMoney(kobo = 0) {
  return currency.format(kobo / 100);
}

function normalizePhone(value) {
  return String(value || "").replace(/[^\d]/g, "");
}

function buildWhatsAppUrl(message) {
  const phone = normalizePhone(state.publicConfig.whatsappNumber || "2348101653634");
  return `https://wa.me/${phone}?text=${encodeURIComponent(message)}`;
}

function applyPublicConfig() {
  const shollyLink = state.publicConfig.instagramShollyUrl || "#";
  const apexLink = state.publicConfig.instagramApexUrl || "#";

  if (ui.igSholly) {
    ui.igSholly.href = shollyLink;
    ui.igSholly.classList.toggle("disabled", shollyLink === "#");
  }
  if (ui.igApex) {
    ui.igApex.href = apexLink;
    ui.igApex.classList.toggle("disabled", apexLink === "#");
  }

  ui.waFloat.href = buildWhatsAppUrl(
    "Hello! I want to chat with Sholly & Shaddy's assistant."
  );

  if (ui.bankTransferBankName) {
    ui.bankTransferBankName.textContent = state.publicConfig.bankName || "Not set";
  }
  if (ui.bankTransferAccountName) {
    ui.bankTransferAccountName.textContent = state.publicConfig.bankAccountName || "Not set";
  }
  if (ui.bankTransferAccountNumber) {
    ui.bankTransferAccountNumber.textContent =
      state.publicConfig.bankAccountNumber || "Not set";
  }
  if (ui.bankTransferNote) {
    ui.bankTransferNote.textContent =
      state.publicConfig.bankTransferInstructions ||
      "Complete transfer, then send your order number on WhatsApp for confirmation.";
  }

  syncCheckoutPaymentUI();
}

async function fetchCustomerApi(url, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };
  const isSafe = method === "GET" || method === "HEAD" || method === "OPTIONS";
  if (!isSafe && state.customerAuth.csrfToken && !headers["x-customer-csrf-token"]) {
    headers["x-customer-csrf-token"] = state.customerAuth.csrfToken;
  }
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) {
    state.customerAuth.authenticated = false;
    state.customerAuth.csrfToken = "";
    throw new Error("Login on My Account to use this feature.");
  }
  if (!response.ok) {
    throw new Error(body.error || `Request failed (${response.status})`);
  }
  return body;
}

async function refreshCustomerAuth() {
  try {
    const response = await fetch("/api/customer/me", { credentials: "same-origin" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.authenticated) {
      state.customerAuth.authenticated = false;
      state.customerAuth.csrfToken = "";
      return false;
    }
    state.customerAuth.authenticated = true;
    state.customerAuth.csrfToken = body.csrfToken || "";
    return true;
  } catch (_error) {
    state.customerAuth.authenticated = false;
    state.customerAuth.csrfToken = "";
    return false;
  }
}

async function saveWishlistItem(productId, variantId = null) {
  if (!state.customerAuth.authenticated) {
    const activeSession = await refreshCustomerAuth();
    if (!activeSession) {
      showToast("Login on My Account to use wishlist.");
      return;
    }
  }
  try {
    await fetchCustomerApi("/api/customer/wishlist/items", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        productId: Number(productId),
        variantId: variantId == null ? null : Number(variantId),
      }),
    });
    showToast("Saved to wishlist.");
  } catch (error) {
    showToast(error.message || "Failed to save wishlist item.");
  }
}

function syncCheckoutPaymentUI() {
  if (!ui.checkoutPaymentMethod) return;

  const paystackConfigured =
    Boolean(state.publicConfig.paystackEnabled) &&
    Boolean(state.publicConfig.paystackPublicKey);
  const moniepointConfigured = Boolean(state.publicConfig.moniepointEnabled);
  const hasBankDetails =
    Boolean(state.publicConfig.bankName) &&
    Boolean(state.publicConfig.bankAccountName) &&
    Boolean(state.publicConfig.bankAccountNumber);

  const paystackOption = ui.checkoutPaymentMethod.querySelector('option[value="paystack"]');
  const moniepointOption = ui.checkoutPaymentMethod.querySelector('option[value="moniepoint"]');
  const bankOption = ui.checkoutPaymentMethod.querySelector('option[value="bank_transfer"]');
  if (paystackOption) {
    paystackOption.disabled = !paystackConfigured;
  }
  if (moniepointOption) {
    moniepointOption.disabled = !moniepointConfigured;
  }
  if (bankOption) {
    bankOption.disabled = !hasBankDetails && (paystackConfigured || moniepointConfigured);
  }

  const enabledMethods = [];
  if (paystackConfigured) enabledMethods.push("paystack");
  if (moniepointConfigured) enabledMethods.push("moniepoint");
  if (hasBankDetails || (!paystackConfigured && !moniepointConfigured)) {
    enabledMethods.push("bank_transfer");
  }
  if (!enabledMethods.includes(ui.checkoutPaymentMethod.value)) {
    ui.checkoutPaymentMethod.value = enabledMethods[0] || "bank_transfer";
  }

  const selected = ui.checkoutPaymentMethod.value || enabledMethods[0] || "bank_transfer";
  const isBankTransfer = selected === "bank_transfer";
  const requiresEmail = selected === "paystack" || selected === "moniepoint";
  ui.checkoutEmail.required = requiresEmail;
  if (selected === "moniepoint") {
    ui.checkoutBtn.textContent = "Pay with Moniepoint";
  } else if (isBankTransfer) {
    ui.checkoutBtn.textContent = "Place Bank Transfer Order";
  } else {
    ui.checkoutBtn.textContent = "Pay with Paystack";
  }

  if (ui.bankTransferPanel) {
    ui.bankTransferPanel.hidden = !isBankTransfer;
  }
}

function productSignature(products) {
  return products
    .map((product) => `${product.id}:${product.updatedAt}:${product.stockQty}:${product.priceKobo}`)
    .sort()
    .join("|");
}

function getProductById(productId) {
  return state.products.find((item) => item.id === productId) || null;
}

function getProductImage(product) {
  return product?.imageUrlOptimized || product?.imageUrl || "";
}

function getProductImageThumb(product) {
  return product?.imageUrlThumb || product?.imageUrlOptimized || product?.imageUrl || "";
}

function cartItemKey(productId, variantId = null) {
  return `${Number(productId)}:${variantId == null ? 0 : Number(variantId)}`;
}

function variantLabel(variant) {
  if (!variant) return "";
  const parts = [variant.optionSize, variant.optionColor, variant.optionStyle]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  return parts.join(" / ");
}

async function ensureProductVariants(productId, { force = false } = {}) {
  const key = String(Number(productId));
  if (!force && Array.isArray(state.variantsByProduct[key])) {
    return state.variantsByProduct[key];
  }
  const response = await fetch(`/api/products/${encodeURIComponent(productId)}/variants`);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error || "Failed to load product variants.");
  }
  const variants = Array.isArray(body.variants) ? body.variants : [];
  state.variantsByProduct[key] = variants;
  return variants;
}

function getVariantForProduct(productId, variantId) {
  if (variantId == null) return null;
  const variants = state.variantsByProduct[String(Number(productId))] || [];
  return variants.find((item) => Number(item.id) === Number(variantId)) || null;
}

function saveCart() {
  localStorage.setItem("storeCart", JSON.stringify(state.cart));
}

function loadCart() {
  try {
    const parsed = JSON.parse(localStorage.getItem("storeCart") || "[]");
    if (Array.isArray(parsed)) {
      state.cart = parsed
        .map((item) => ({
          productId: Number(item.productId),
          variantId:
            item.variantId === undefined || item.variantId === null || item.variantId === ""
              ? null
              : Number(item.variantId),
          variantLabel: item.variantLabel || "",
          qty: Number(item.qty),
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

function applyTheme(theme) {
  const nextTheme = theme === "light" ? "light" : "dark";
  document.body.setAttribute("data-theme", nextTheme);
  if (ui.themeToggle) {
    const label = nextTheme === "light" ? "Switch to dark mode" : "Switch to light mode";
    ui.themeToggle.setAttribute("aria-label", label);
    ui.themeToggle.setAttribute("title", label);
  }
  localStorage.setItem("storeTheme", nextTheme);
}

function setMobileMenuOpen(open) {
  if (!ui.topbarActions || !ui.menuToggle) return;
  const isOpen = Boolean(open);
  ui.topbarActions.classList.toggle("open", isOpen);
  ui.menuToggle.classList.toggle("active", isOpen);
  ui.menuToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
  ui.menuToggle.setAttribute("aria-label", isOpen ? "Close header menu" : "Open header menu");
  ui.menuToggle.setAttribute("title", isOpen ? "Close menu" : "Open menu");
}

function setActiveBrand(brand, { persist = true } = {}) {
  if (!BRAND_COPY[brand]) {
    return;
  }
  state.activeBrand = brand;
  if (persist) {
    localStorage.setItem("activeBrand", brand);
  }

  for (const [key, section] of Object.entries(ui.sections)) {
    section.classList.toggle("brand-hidden", key !== brand);
  }

  for (const button of ui.switches) {
    button.classList.toggle("active", button.dataset.brandSwitch === brand);
  }

  ui.heroLabel.textContent = BRAND_COPY[brand].label;
  ui.heroTitle.textContent = BRAND_COPY[brand].title;
  ui.heroDescription.textContent = BRAND_COPY[brand].description;
  if (ui.brandMain) {
    ui.brandMain.textContent = BRAND_COPY[brand].headerMain;
  }
  if (ui.brandSub) {
    ui.brandSub.textContent = BRAND_COPY[brand].headerSub;
  }
  if (ui.brandLogo) {
    ui.brandLogo.src = BRAND_COPY[brand].logoUrl;
    ui.brandLogo.alt = BRAND_COPY[brand].logoAlt;
  }
  document.title =
    brand === "apex-apparel"
      ? "Apex Apparel | Luxury Collections"
      : "Sholly & Shaddy's | Luxury Collections";

  loadSummary(brand).catch(() => {});
}

function getFilteredProducts(brand) {
  const brandProducts = state.products.filter((product) => product.brand === brand);
  const { category, query } = state.filters[brand];
  const lower = query.trim().toLowerCase();

  return brandProducts.filter((product) => {
    const categoryMatch = category === "all" || product.category === category;
    const textMatch =
      !lower ||
      product.name.toLowerCase().includes(lower) ||
      product.category.toLowerCase().includes(lower) ||
      product.description.toLowerCase().includes(lower);
    return categoryMatch && textMatch;
  });
}

function renderCategoryFilters(brand) {
  const select = ui.categorySelects[brand];
  if (!select) return;

  const categories = Array.from(
    new Set(
      state.products
        .filter((product) => product.brand === brand)
        .map((product) => product.category)
    )
  ).sort();

  select.innerHTML = "";
  const all = document.createElement("option");
  all.value = "all";
  all.textContent = "All categories";
  select.appendChild(all);

  for (const category of categories) {
    const option = document.createElement("option");
    option.value = category;
    option.textContent = category;
    select.appendChild(option);
  }

  select.value = state.filters[brand].category;
}

function resolveModalSelection(product) {
  const selectedVariant =
    state.modalVariantId == null ? null : getVariantForProduct(product.id, state.modalVariantId);
  const unitPriceKobo =
    selectedVariant && selectedVariant.priceOverrideKobo != null
      ? Number(selectedVariant.priceOverrideKobo)
      : Number(product.priceKobo || 0);
  const stockQty = selectedVariant ? Number(selectedVariant.stockQty || 0) : Number(product.stockQty || 0);
  const imageUrl = selectedVariant?.imageUrlOptimized || selectedVariant?.imageUrl || getProductImage(product);
  const compareAtKobo = selectedVariant ? null : product.compareAtKobo;
  const selectedLabel = selectedVariant ? variantLabel(selectedVariant) : "";
  return {
    selectedVariant,
    unitPriceKobo,
    stockQty,
    imageUrl,
    compareAtKobo,
    selectedLabel,
  };
}

function renderModalSelection() {
  const product = state.modalProduct;
  if (!product) return;
  const selection = resolveModalSelection(product);
  const requiresVariant = Boolean(product.hasVariants);
  const variantChosen = !requiresVariant || Boolean(selection.selectedVariant);
  const effectiveStockQty = variantChosen ? selection.stockQty : 0;

  ui.modalName.textContent = product.name;
  ui.modalBrand.textContent = product.brand === "sholly-home" ? "Sholly Home Luxury" : "Apex Apparel";
  ui.modalImage.src = selection.imageUrl || getProductImage(product);
  ui.modalImage.alt = product.name;
  ui.modalPrice.textContent = formatMoney(selection.unitPriceKobo);
  ui.modalCompare.textContent = selection.compareAtKobo ? formatMoney(selection.compareAtKobo) : "";
  ui.modalCompare.style.display = selection.compareAtKobo ? "inline" : "none";
  ui.modalDescription.textContent = product.description;
  if (!variantChosen) {
    ui.modalStock.textContent = "Select a variant to continue.";
  } else {
    ui.modalStock.textContent =
      effectiveStockQty > 0 ? `${effectiveStockQty} units available` : "Currently out of stock";
  }
  ui.modalAddCart.disabled = !variantChosen || effectiveStockQty < 1;
  ui.modalAddCart.textContent =
    !variantChosen ? "Select Variant" : effectiveStockQty < 1 ? "Out of Stock" : "Add to Cart";
  if (ui.modalWishlist) {
    ui.modalWishlist.disabled = requiresVariant && !selection.selectedVariant;
  }

  if (ui.modalVariantHint) {
    ui.modalVariantHint.textContent = selection.selectedLabel ? `Selected: ${selection.selectedLabel}` : "";
  }
  ui.modalWhatsApp.href = buildWhatsAppUrl(
    `Hello Sholly & Shaddy's, I want to order: ${product.name}${
      selection.selectedLabel ? ` (${selection.selectedLabel})` : ""
    } (${formatMoney(selection.unitPriceKobo)}).`
  );
}

function renderModalVariants(product, variants) {
  if (!ui.modalVariantWrap || !ui.modalVariantSelect) return;
  const activeVariants = Array.isArray(variants) ? variants.filter((item) => item.isActive !== false) : [];
  if (!product.hasVariants || !activeVariants.length) {
    ui.modalVariantWrap.hidden = true;
    ui.modalVariantSelect.innerHTML = "";
    state.modalVariantId = null;
    return;
  }

  ui.modalVariantWrap.hidden = false;
  ui.modalVariantSelect.innerHTML = "";
  for (const variant of activeVariants) {
    const option = document.createElement("option");
    option.value = String(variant.id);
    const label = variantLabel(variant) || variant.sku || `Variant #${variant.id}`;
    const price = variant.priceOverrideKobo != null ? Number(variant.priceOverrideKobo) : Number(product.priceKobo);
    option.textContent = `${label} - ${formatMoney(price)} - ${Number(variant.stockQty || 0)} in stock`;
    ui.modalVariantSelect.appendChild(option);
  }

  const inStock = activeVariants.find((item) => Number(item.stockQty || 0) > 0) || activeVariants[0];
  state.modalVariantId = inStock ? Number(inStock.id) : Number(activeVariants[0].id);
  ui.modalVariantSelect.value = String(state.modalVariantId);
}

async function openModal(product) {
  state.modalProduct = product;
  state.modalVariants = [];
  state.modalVariantId = null;

  try {
    const variants = await ensureProductVariants(product.id);
    state.modalVariants = variants;
    renderModalVariants(product, variants);
  } catch (_error) {
    renderModalVariants(product, []);
  }
  renderModalSelection();
  ui.modal.showModal();
}

function renderProducts(brand) {
  const grid = ui.grids[brand];
  grid.innerHTML = "";
  const products = getFilteredProducts(brand);

  if (!products.length) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No products match this filter yet.";
    grid.appendChild(empty);
    revealNewElements();
    return;
  }

  for (const product of products) {
    const fragment = ui.template.content.cloneNode(true);
    const root = fragment.querySelector(".product-card");
    const image = fragment.querySelector(".card-image");
    const featured = fragment.querySelector(".pill-featured");
    const category = fragment.querySelector(".card-category");
    const name = fragment.querySelector(".card-name");
    const description = fragment.querySelector(".card-description");
    const now = fragment.querySelector(".now");
    const old = fragment.querySelector(".old");
    const stock = fragment.querySelector(".pill-stock");
    const wishlistButton = fragment.querySelector(".card-wishlist");
    const viewButton = fragment.querySelector(".card-view");
    const addButton = fragment.querySelector(".card-add");

    image.src = getProductImageThumb(product);
    if (product.imageSrcSet) {
      image.srcset = product.imageSrcSet;
      image.sizes = "(max-width: 720px) 100vw, 33vw";
    } else {
      image.removeAttribute("srcset");
      image.removeAttribute("sizes");
    }
    image.alt = product.name;
    featured.style.display = product.isFeatured ? "inline-flex" : "none";
    category.textContent = product.category;
    name.textContent = product.name;
    description.textContent = product.description;
    now.textContent = formatMoney(product.priceKobo);
    old.textContent = product.compareAtKobo ? formatMoney(product.compareAtKobo) : "";
    old.style.display = product.compareAtKobo ? "inline" : "none";

    if (product.hasVariants) {
      const variants = state.variantsByProduct[String(product.id)] || [];
      if (variants.length) {
        const totalVariantStock = variants
          .filter((item) => item.isActive !== false)
          .reduce((sum, item) => sum + Number(item.stockQty || 0), 0);
        if (totalVariantStock > 0) {
          stock.textContent = `${totalVariantStock} variant units`;
          stock.classList.remove("out");
        } else {
          stock.textContent = "Out of stock";
          stock.classList.add("out");
        }
      } else {
        stock.textContent = "Select variant";
        stock.classList.remove("out");
      }
    } else if (product.stockQty > 0) {
      stock.textContent = `${product.stockQty} in stock`;
      stock.classList.remove("out");
    } else {
      stock.textContent = "Out of stock";
      stock.classList.add("out");
    }

    viewButton.addEventListener("click", (event) => {
      event.stopPropagation();
      openModal(product);
    });
    wishlistButton.addEventListener("click", async (event) => {
      event.stopPropagation();
      await saveWishlistItem(product.id, null);
    });

    const variantsReady = Array.isArray(state.variantsByProduct[String(product.id)]);
    const hasVariantStock = variantsReady
      ? (state.variantsByProduct[String(product.id)] || [])
          .filter((item) => item.isActive !== false)
          .some((item) => Number(item.stockQty || 0) > 0)
      : true;
    const productAvailable = product.hasVariants ? hasVariantStock : product.stockQty > 0;
    addButton.disabled = !productAvailable;
    addButton.textContent = !productAvailable ? "Out of Stock" : product.hasVariants ? "Choose Variant" : "Add to Cart";
    addButton.addEventListener("click", (event) => {
      event.stopPropagation();
      if (product.hasVariants) {
        openModal(product);
        return;
      }
      addToCart(product.id, 1);
    });

    root.addEventListener("click", () => openModal(product));
    grid.appendChild(fragment);
  }

  revealNewElements();
}

function renderAllProducts() {
  renderCategoryFilters("sholly-home");
  renderCategoryFilters("apex-apparel");
  renderProducts("sholly-home");
  renderProducts("apex-apparel");
}

function updateCartBadge() {
  const total = state.cart.reduce((sum, item) => sum + item.qty, 0);
  ui.cartCount.textContent = String(total);
}

function cartSubtotalKobo() {
  let subtotal = 0;
  for (const item of state.cart) {
    const product = getProductById(item.productId);
    const variant = getVariantForProduct(item.productId, item.variantId);
    let unit = item.snapshot?.priceKobo || 0;
    if (item.variantId != null) {
      if (variant && variant.priceOverrideKobo != null) {
        unit = Number(variant.priceOverrideKobo);
      } else if (product) {
        unit = Number(product.priceKobo || 0);
      }
    } else if (product) {
      unit = Number(product.priceKobo || 0);
    }
    subtotal += unit * item.qty;
  }
  return subtotal;
}

function cartDiscountKobo(subtotalKobo = cartSubtotalKobo()) {
  if (!state.coupon) return 0;
  return Math.min(Number(state.coupon.discountKobo || 0), subtotalKobo);
}

function cartDiscountedSubtotalKobo(subtotalKobo = cartSubtotalKobo()) {
  return Math.max(subtotalKobo - cartDiscountKobo(subtotalKobo), 0);
}

function computeCartTotals() {
  const subtotalKobo = cartSubtotalKobo();
  const discountKobo = cartDiscountKobo(subtotalKobo);
  const discountedSubtotalKobo = Math.max(subtotalKobo - discountKobo, 0);
  const shippingFeeKobo = Number(state.checkoutShipping.shippingFeeKobo || 0);
  const totalKobo = discountedSubtotalKobo + shippingFeeKobo;
  return {
    subtotalKobo,
    discountKobo,
    discountedSubtotalKobo,
    shippingFeeKobo,
    totalKobo,
  };
}

function shippingNoteText() {
  if (state.checkoutShipping.loading) {
    return "Calculating shipping...";
  }
  const shippingState = (ui.checkoutShippingState?.value || "").trim();
  const shippingCity = (ui.checkoutShippingCity?.value || "").trim();
  if (!shippingState) {
    return "Enter your delivery state to get shipping fee.";
  }
  if (state.checkoutShipping.freeShippingApplied) {
    return "Free shipping applied to this order.";
  }
  const location = shippingCity ? `${shippingCity}, ${shippingState}` : shippingState;
  return `Shipping estimate for ${location}.`;
}

function renderCartTotals() {
  const totals = computeCartTotals();
  ui.cartSubtotal.textContent = formatMoney(totals.subtotalKobo);
  if (ui.cartDiscount) {
    ui.cartDiscount.textContent = formatMoney(totals.discountKobo);
  }
  if (ui.cartShipping) {
    ui.cartShipping.textContent = formatMoney(totals.shippingFeeKobo);
  }
  if (ui.cartTotal) {
    ui.cartTotal.textContent = formatMoney(totals.totalKobo);
  }
  if (ui.shippingNote) {
    ui.shippingNote.textContent = shippingNoteText();
  }
}

function cartBrands() {
  const brands = new Set();
  for (const item of state.cart) {
    const product = getProductById(item.productId);
    if (product?.brand) {
      brands.add(product.brand);
    }
  }
  return Array.from(brands);
}

function clearCoupon(message = "") {
  state.coupon = null;
  if (ui.couponNote) {
    ui.couponNote.textContent = message;
  }
}

async function applyCouponCode() {
  if (!state.cart.length) {
    showToast("Add items to cart before applying coupon.");
    return;
  }

  const code = (ui.couponCode.value || "").trim().toUpperCase();
  if (!code) {
    clearCoupon("Enter a coupon code.");
    renderCart();
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
    if (!response.ok) {
      throw new Error(body.error || "Coupon not valid.");
    }

    state.coupon = {
      code,
      discountKobo: Number(body.discountKobo || 0),
      totalKobo: Number(body.totalKobo || 0),
      details: body.coupon || null,
    };
    if (ui.couponNote) {
      ui.couponNote.textContent = `${code} applied successfully.`;
    }
    showToast("Coupon applied.");
    renderCart();
  } catch (error) {
    clearCoupon(error.message || "Coupon not valid.");
    renderCart();
  }
}

let cartTrackTimer = null;
let shippingQuoteTimer = null;
let shippingQuoteRequestId = 0;

function scheduleCartTracking(status = null) {
  if (cartTrackTimer) {
    clearTimeout(cartTrackTimer);
  }
  cartTrackTimer = setTimeout(() => {
    trackCartSession(status).catch(() => {});
  }, 450);
}

function scheduleShippingQuote({ force = false } = {}) {
  if (shippingQuoteTimer) {
    clearTimeout(shippingQuoteTimer);
  }
  shippingQuoteTimer = setTimeout(() => {
    refreshShippingQuote({ force }).catch(() => {});
  }, 320);
}

async function refreshShippingQuote({ force = false } = {}) {
  const shippingState = (ui.checkoutShippingState?.value || "").trim();
  const shippingCity = (ui.checkoutShippingCity?.value || "").trim();

  state.checkoutShipping.shippingState = shippingState;
  state.checkoutShipping.shippingCity = shippingCity;
  localStorage.setItem("checkoutShippingState", shippingState);
  localStorage.setItem("checkoutShippingCity", shippingCity);

  const discountedSubtotalKobo = cartDiscountedSubtotalKobo();
  const signature = `${shippingState.toLowerCase()}|${shippingCity.toLowerCase()}|${discountedSubtotalKobo}`;
  if (!force && signature === state.checkoutShipping.signature) {
    return;
  }
  state.checkoutShipping.signature = signature;

  if (!shippingState || !state.cart.length) {
    state.checkoutShipping.shippingFeeKobo = 0;
    state.checkoutShipping.freeShippingApplied = false;
    state.checkoutShipping.loading = false;
    renderCartTotals();
    return;
  }

  const requestId = ++shippingQuoteRequestId;
  state.checkoutShipping.loading = true;
  renderCartTotals();

  try {
    const params = new URLSearchParams({
      state: shippingState,
      city: shippingCity,
      subtotalKobo: String(discountedSubtotalKobo),
    });
    const response = await fetch(`/api/shipping/quote?${params.toString()}`);
    const body = await response.json().catch(() => ({}));
    if (requestId !== shippingQuoteRequestId) {
      return;
    }
    if (!response.ok) {
      throw new Error(body.error || "Failed to calculate shipping.");
    }
    state.checkoutShipping.shippingFeeKobo = Number(body.shippingFeeKobo || 0);
    state.checkoutShipping.freeShippingApplied = Boolean(body.freeShippingApplied);
    state.checkoutShipping.errorSignature = "";
  } catch (error) {
    if (requestId === shippingQuoteRequestId) {
      state.checkoutShipping.shippingFeeKobo = Number(state.publicConfig.defaultShippingFeeKobo || 0);
      state.checkoutShipping.freeShippingApplied = false;
      if (state.checkoutShipping.errorSignature !== signature) {
        state.checkoutShipping.errorSignature = signature;
        showToast(error.message || "Unable to calculate shipping. Using default estimate.");
      }
    }
  } finally {
    if (requestId === shippingQuoteRequestId) {
      state.checkoutShipping.loading = false;
      renderCartTotals();
    }
  }
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
      customerName: ui.checkoutName?.value?.trim() || null,
      customerPhone: ui.checkoutPhone?.value?.trim() || null,
      customerEmail: ui.checkoutEmail?.value?.trim() || null,
      status: statusOverride || (items.length ? "open" : "converted"),
      items,
    }),
  });

  if (!response.ok) return;
  const body = await response.json().catch(() => ({}));
  if (body.sessionId) {
    state.cartSessionId = body.sessionId;
    localStorage.setItem("cartSessionId", body.sessionId);
  }
}

function sanitizeCartAgainstInventory({ showNotice = false } = {}) {
  let changed = false;
  const nextCart = [];

  for (const item of state.cart) {
    const product = getProductById(item.productId);
    const variant = getVariantForProduct(item.productId, item.variantId);
    if (!product) {
      changed = true;
      continue;
    }
    if (item.variantId != null) {
      if (variant && Number(variant.isActive) === 0) {
        changed = true;
        continue;
      }
      const knownVariantStock = variant ? Number(variant.stockQty || 0) : Number(item.snapshot?.stockQty || 0);
      if (knownVariantStock <= 0) {
        changed = true;
        continue;
      }
      const qty = Math.min(item.qty, knownVariantStock);
      if (qty !== item.qty) changed = true;
      const unitPrice =
        variant && variant.priceOverrideKobo != null
          ? Number(variant.priceOverrideKobo)
          : Number(item.snapshot?.priceKobo || product.priceKobo || 0);
      const resolvedVariantLabel = item.variantLabel || variantLabel(variant) || "";
      nextCart.push({
        productId: item.productId,
        variantId: item.variantId,
        variantLabel: resolvedVariantLabel,
        qty,
        snapshot: {
          name: product.name,
          imageUrl:
            variant?.imageUrlThumb ||
            variant?.imageUrlOptimized ||
            variant?.imageUrl ||
            item.snapshot?.imageUrl ||
            getProductImageThumb(product),
          priceKobo: unitPrice,
          stockQty: knownVariantStock,
        },
      });
      continue;
    }

    if (product.stockQty <= 0) {
      changed = true;
      continue;
    }
    const qty = Math.min(item.qty, Number(product.stockQty || 0));
    if (qty !== item.qty) {
      changed = true;
    }
    nextCart.push({
      productId: item.productId,
      variantId: null,
      variantLabel: "",
      qty,
      snapshot: {
        name: product.name,
        imageUrl: getProductImageThumb(product),
        priceKobo: Number(product.priceKobo || 0),
        stockQty: Number(product.stockQty || 0),
      },
    });
  }

  if (changed) {
    state.cart = nextCart;
    clearCoupon("Coupon removed because cart changed.");
    saveCart();
    if (showNotice) {
      showToast("Cart adjusted due to stock updates.");
    }
  }
}

function findCartItem(productId, variantId = null) {
  const key = cartItemKey(productId, variantId);
  return state.cart.find((item) => cartItemKey(item.productId, item.variantId) === key) || null;
}

function renderCart() {
  ui.cartItems.innerHTML = "";

  if (!state.cart.length) {
    const empty = document.createElement("div");
    empty.className = "cart-empty";
    empty.textContent = "Your cart is currently empty.";
    ui.cartItems.appendChild(empty);
    ui.checkoutBtn.disabled = true;
  } else {
    for (const item of state.cart) {
      const product = getProductById(item.productId);
      const variant = getVariantForProduct(item.productId, item.variantId);
      const variantName = item.variantLabel || variantLabel(variant) || "";
      const name = product ? product.name : item.snapshot?.name || "Unavailable product";
      const title = variantName ? `${name} (${variantName})` : name;
      const imageUrl =
        variant?.imageUrlThumb ||
        variant?.imageUrlOptimized ||
        variant?.imageUrl ||
        (product ? getProductImageThumb(product) : item.snapshot?.imageUrl || "");
      const unitPrice =
        variant && variant.priceOverrideKobo != null
          ? Number(variant.priceOverrideKobo)
          : product
            ? Number(product.priceKobo || 0)
            : Number(item.snapshot?.priceKobo || 0);
      const lineTotal = unitPrice * item.qty;
      const maxStock = variant
        ? Number(variant.stockQty || 0)
        : product
          ? Number(product.stockQty || 0)
          : Number(item.snapshot?.stockQty || item.qty);

      const card = document.createElement("article");
      card.className = "cart-item";
      card.innerHTML = `
        <div class="cart-item-top">
          <img src="${imageUrl}" alt="${name}" />
          <div>
            <h5>${title}</h5>
            <p class="cart-item-meta">${formatMoney(unitPrice)} each</p>
            <p class="cart-item-stock">In stock: ${Math.max(maxStock, 0)}</p>
          </div>
        </div>
        <div class="cart-controls">
          <div class="qty-controls">
            <button type="button" data-action="minus" aria-label="Decrease quantity">-</button>
            <span>${item.qty}</span>
            <button type="button" data-action="plus" aria-label="Increase quantity">+</button>
          </div>
          <div class="cart-line-total">
            <small>Item Total</small>
            <strong>${formatMoney(lineTotal)}</strong>
          </div>
          <button type="button" class="remove-item">Delete</button>
        </div>
      `;

      card.querySelector('[data-action="minus"]').addEventListener("click", () => {
        changeCartQty(item.productId, item.variantId, -1);
      });
      card.querySelector('[data-action="plus"]').addEventListener("click", () => {
        if (!maxStock || item.qty >= maxStock) {
          showToast("Cannot exceed available stock.");
          return;
        }
        changeCartQty(item.productId, item.variantId, 1);
      });
      card.querySelector(".remove-item").addEventListener("click", () => {
        removeCartItem(item.productId, item.variantId);
      });

      ui.cartItems.appendChild(card);
    }
    ui.checkoutBtn.disabled = false;
  }

  renderCartTotals();
  if (ui.couponNote && !ui.couponNote.textContent && state.coupon) {
    ui.couponNote.textContent = `${state.coupon.code} applied successfully.`;
  }
  updateCartBadge();
  scheduleCartTracking();
  scheduleShippingQuote();
}

function addToCart(productId, qty = 1, { variantId = null, variantData = null } = {}) {
  const product = getProductById(productId);
  if (!product) {
    showToast("Product unavailable.");
    return;
  }
  if (product.hasVariants && variantId == null) {
    showToast("Select a variant first.");
    return;
  }
  const variant = variantId == null ? null : variantData || getVariantForProduct(productId, variantId);
  const maxStock = variant ? Number(variant.stockQty || 0) : Number(product.stockQty || 0);
  if (maxStock < 1) {
    showToast("This product is out of stock.");
    return;
  }

  const existing = findCartItem(productId, variantId);
  const currentQty = existing ? existing.qty : 0;
  if (currentQty + qty > maxStock) {
    showToast("Cannot exceed available stock.");
    return;
  }

  const unitPrice =
    variant && variant.priceOverrideKobo != null ? Number(variant.priceOverrideKobo) : Number(product.priceKobo || 0);
  const selectedVariantLabel = variantLabel(variant) || "";
  const selectedImage =
    variant?.imageUrlThumb || variant?.imageUrlOptimized || variant?.imageUrl || getProductImageThumb(product);

  if (existing) {
    existing.qty += qty;
    existing.snapshot = {
      name: product.name,
      imageUrl: selectedImage,
      priceKobo: unitPrice,
      stockQty: maxStock,
    };
    existing.variantLabel = selectedVariantLabel;
  } else {
    state.cart.push({
      productId,
      variantId: variant ? Number(variant.id) : null,
      variantLabel: selectedVariantLabel,
      qty,
      snapshot: {
        name: product.name,
        imageUrl: selectedImage,
        priceKobo: unitPrice,
        stockQty: maxStock,
      },
    });
  }

  clearCoupon("Coupon removed because cart changed.");
  saveCart();
  renderCart();
  showToast(`${product.name}${selectedVariantLabel ? ` (${selectedVariantLabel})` : ""} added to cart.`);
}

function changeCartQty(productId, variantId, delta) {
  const item = findCartItem(productId, variantId);
  if (!item) return;
  const product = getProductById(productId);
  const variant = getVariantForProduct(productId, variantId);
  const maxStock =
    variant ? Number(variant.stockQty || 0) : product ? Number(product.stockQty || 0) : Number(item.snapshot?.stockQty || item.qty);

  item.qty = Math.max(1, Math.min(item.qty + delta, maxStock));
  clearCoupon("Coupon removed because cart changed.");
  saveCart();
  renderCart();
}

function removeCartItem(productId, variantId = null) {
  const key = cartItemKey(productId, variantId);
  state.cart = state.cart.filter((item) => cartItemKey(item.productId, item.variantId) !== key);
  clearCoupon("Coupon removed because cart changed.");
  saveCart();
  renderCart();
}

function openCart() {
  ui.cartBackdrop.classList.add("open");
  ui.cartDrawer.classList.add("open");
}

function closeCart() {
  ui.cartBackdrop.classList.remove("open");
  ui.cartDrawer.classList.remove("open");
}

function resetCheckoutState() {
  ui.checkoutForm.reset();
  state.checkoutShipping.shippingState = "";
  state.checkoutShipping.shippingCity = "";
  state.checkoutShipping.shippingFeeKobo = 0;
  state.checkoutShipping.freeShippingApplied = false;
  state.checkoutShipping.signature = "";
  state.checkoutShipping.loading = false;
  state.checkoutShipping.errorSignature = "";
  localStorage.removeItem("checkoutShippingState");
  localStorage.removeItem("checkoutShippingCity");
  renderCartTotals();
  syncCheckoutPaymentUI();
}

async function handleCheckout(event) {
  event.preventDefault();
  if (!state.cart.length) {
    showToast("Cart is empty.");
    return;
  }

  const customerName = ui.checkoutName.value.trim();
  const customerPhone = ui.checkoutPhone.value.trim();
  const customerEmail = ui.checkoutEmail.value.trim();
  const shippingState = ui.checkoutShippingState.value.trim();
  const shippingCity = ui.checkoutShippingCity.value.trim();
  const notes = ui.checkoutNotes.value.trim();
  const paymentMethod = ui.checkoutPaymentMethod?.value || "paystack";

  if (!customerName || !customerPhone) {
    showToast("Name and phone are required.");
    return;
  }
  if (!shippingState) {
    showToast("Delivery state is required.");
    return;
  }
  if ((paymentMethod === "paystack" || paymentMethod === "moniepoint") && !customerEmail) {
    showToast("Email is required for online payment.");
    return;
  }

  const payload = {
    customerName,
    customerPhone,
    customerEmail: customerEmail || null,
    shippingState,
    shippingCity: shippingCity || null,
    notes,
    couponCode: state.coupon?.code || null,
    items: state.cart.map((item) => ({
      productId: item.productId,
      variantId: item.variantId == null ? null : Number(item.variantId),
      qty: item.qty,
    })),
  };

  ui.checkoutBtn.disabled = true;
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
      if (!response.ok) {
        throw new Error(body.error || "Checkout failed");
      }

      state.cart = [];
      clearCoupon("");
      saveCart();
      renderCart();
      resetCheckoutState();
      closeCart();
      showToast(`Order created: ${body.order.orderNumber}`);
      await trackCartSession("converted");
      await Promise.all([loadProducts({ silent: true }), loadSummary(state.activeBrand)]);
    } else if (paymentMethod === "moniepoint") {
      const response = await fetch("/api/moniepoint/initialize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(body.error || "Payment initialization failed");
      }

      const checkoutUrl = body?.payment?.checkoutUrl;
      if (!checkoutUrl) {
        throw new Error("Moniepoint checkout URL is missing.");
      }
      window.location.href = checkoutUrl;
    } else {
      const response = await fetch("/api/paystack/initialize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(body.error || "Payment initialization failed");
      }

      const payment = body.payment || {};
      const reference = payment.reference;
      const amountKobo = Number(payment.amountKobo || 0);
      const publicKey = payment.publicKey || state.publicConfig.paystackPublicKey;

      if (!reference || !amountKobo || !publicKey) {
        throw new Error("Paystack configuration is incomplete. Contact support.");
      }

      if (window.PaystackPop && typeof window.PaystackPop.setup === "function") {
        const handler = window.PaystackPop.setup({
          key: publicKey,
          email: customerEmail,
          amount: amountKobo,
          ref: reference,
          callback: async (paystackResponse) => {
            const paidReference = paystackResponse.reference || reference;
            await verifyPaystackPayment(paidReference);
          },
          onClose: () => {
            showToast("Payment window closed.");
          },
        });
        handler.openIframe();
      } else if (payment.authorizationUrl) {
        window.location.href = payment.authorizationUrl;
      } else {
        throw new Error("Unable to open Paystack payment dialog.");
      }
    }
  } catch (error) {
    showToast(error.message);
  } finally {
    ui.checkoutBtn.disabled = false;
    syncCheckoutPaymentUI();
  }
}

async function verifyPaystackPayment(reference) {
  if (!reference) {
    showToast("Missing payment reference.");
    return;
  }

  try {
    const response = await fetch("/api/paystack/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reference }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || "Payment verification failed.");
    }

    state.cart = [];
    clearCoupon("");
    saveCart();
    renderCart();
    resetCheckoutState();
    closeCart();
    showToast(`Payment confirmed. Order: ${body.order.orderNumber}`);
    await trackCartSession("converted");
    await Promise.all([loadProducts({ silent: true }), loadSummary(state.activeBrand)]);
  } catch (error) {
    showToast(error.message);
  }
}

async function verifyMoniepointPayment({ paymentReference = "", transactionReference = "" } = {}) {
  const payload = {};
  if (paymentReference) payload.paymentReference = paymentReference;
  if (transactionReference) payload.transactionReference = transactionReference;
  if (!payload.paymentReference && !payload.transactionReference) {
    showToast("Missing Moniepoint payment reference.");
    return;
  }

  try {
    const response = await fetch("/api/moniepoint/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || "Moniepoint verification failed.");
    }

    state.cart = [];
    clearCoupon("");
    saveCart();
    renderCart();
    resetCheckoutState();
    closeCart();
    showToast(`Payment confirmed. Order: ${body.order.orderNumber}`);
    await trackCartSession("converted");
    await Promise.all([loadProducts({ silent: true }), loadSummary(state.activeBrand)]);
  } catch (error) {
    showToast(error.message);
  }
}

async function handlePaystackRedirect() {
  const params = new URLSearchParams(window.location.search);
  const trxref = String(params.get("trxref") || "").trim();
  const referenceParam = String(params.get("reference") || "").trim();
  const reference =
    trxref || (referenceParam.startsWith("SSPAY-") ? referenceParam : "");
  if (!reference) return;

  await verifyPaystackPayment(reference);

  params.delete("reference");
  params.delete("trxref");
  const query = params.toString();
  const newUrl = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
  window.history.replaceState({}, "", newUrl);
}

async function handleMoniepointRedirect() {
  const params = new URLSearchParams(window.location.search);
  const referenceParam = String(params.get("reference") || "").trim();
  const paymentReference = String(params.get("paymentReference") || "").trim() ||
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
  const newUrl = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
  window.history.replaceState({}, "", newUrl);
}

async function loadProducts({ silent = false } = {}) {
  const response = await fetch("/api/products?limit=500");
  if (!response.ok) {
    throw new Error("Failed to load products");
  }
  const body = await response.json();
  const incoming = Array.isArray(body.products) ? body.products : [];
  const newSignature = productSignature(incoming);
  const hasChanged = state.lastCatalogSignature && newSignature !== state.lastCatalogSignature;

  state.products = incoming;
  state.lastCatalogSignature = newSignature;
  const validProductIds = new Set(incoming.map((item) => String(item.id)));
  for (const key of Object.keys(state.variantsByProduct || {})) {
    if (!validProductIds.has(key)) {
      delete state.variantsByProduct[key];
    }
  }

  sanitizeCartAgainstInventory({ showNotice: hasChanged && silent });
  renderAllProducts();
  renderCart();

  if (hasChanged && silent) {
    showToast("Store updated from admin changes.");
  }
}

async function loadPublicConfig() {
  const response = await fetch("/api/public-config");
  if (!response.ok) {
    return;
  }
  const body = await response.json();
  state.publicConfig = {
    ...state.publicConfig,
    ...body,
  };
  applyPublicConfig();
  scheduleShippingQuote({ force: true });
}

async function loadSummary(brand = state.activeBrand) {
  const response = await fetch(`/api/inventory/summary?brand=${encodeURIComponent(brand)}`);
  if (!response.ok) {
    return;
  }

  const body = await response.json();
  const summary = body.summary;
  if (!summary) return;

  ui.metrics.products.textContent = Number(summary.total_products || 0).toLocaleString("en-NG");
  ui.metrics.units.textContent = Number(summary.total_units || 0).toLocaleString("en-NG");
  ui.metrics.value.textContent = formatMoney(Number(summary.stock_value_kobo || 0));
}

function showToast(message) {
  ui.toast.textContent = message;
  ui.toast.classList.add("show");
  setTimeout(() => ui.toast.classList.remove("show"), 2800);
}

function wireFilters() {
  for (const brand of ["sholly-home", "apex-apparel"]) {
    ui.categorySelects[brand].addEventListener("change", (event) => {
      state.filters[brand].category = event.target.value;
      renderProducts(brand);
    });

    ui.searchInputs[brand].addEventListener("input", (event) => {
      state.filters[brand].query = event.target.value;
      renderProducts(brand);
    });
  }
}

function wireThemeToggle() {
  ui.themeToggle.addEventListener("click", () => {
    const current = document.body.getAttribute("data-theme") || "dark";
    applyTheme(current === "dark" ? "light" : "dark");
  });
}

function wireMobileHeader() {
  if (!ui.menuToggle || !ui.topbarActions) return;

  ui.menuToggle.addEventListener("click", () => {
    const nextOpen = !ui.topbarActions.classList.contains("open");
    setMobileMenuOpen(nextOpen);
  });

  ui.topbarActions.querySelectorAll("a, button").forEach((node) => {
    node.addEventListener("click", () => {
      if (window.matchMedia("(max-width: 860px)").matches) {
        setMobileMenuOpen(false);
      }
    });
  });

  window.addEventListener("resize", () => {
    if (!window.matchMedia("(max-width: 860px)").matches) {
      setMobileMenuOpen(false);
    }
  });

  document.addEventListener("click", (event) => {
    if (!window.matchMedia("(max-width: 860px)").matches) return;
    if (!ui.topbarActions.classList.contains("open")) return;
    const target = event.target;
    if (ui.topbar && target instanceof Node && !ui.topbar.contains(target)) {
      setMobileMenuOpen(false);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && ui.topbarActions.classList.contains("open")) {
      setMobileMenuOpen(false);
    }
  });
}

function wireBrandSwitches() {
  for (const button of ui.switches) {
    button.addEventListener("click", () => {
      const brand = button.dataset.brandSwitch;
      setActiveBrand(brand);
      if (window.matchMedia("(max-width: 860px)").matches) {
        setMobileMenuOpen(false);
      }
      document.getElementById(`${brand === "sholly-home" ? "sholly" : "apex"}-section`).scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });
  }
}

function wireModal() {
  ui.modalClose.addEventListener("click", () => ui.modal.close());
  ui.modal.addEventListener("click", (event) => {
    const rect = ui.modal.getBoundingClientRect();
    const inside =
      event.clientX >= rect.left &&
      event.clientX <= rect.right &&
      event.clientY >= rect.top &&
      event.clientY <= rect.bottom;
    if (!inside) {
      ui.modal.close();
    }
  });
  ui.modalAddCart.addEventListener("click", () => {
    if (!state.modalProduct) return;
    const selection = resolveModalSelection(state.modalProduct);
    addToCart(state.modalProduct.id, 1, {
      variantId: selection.selectedVariant ? Number(selection.selectedVariant.id) : null,
      variantData: selection.selectedVariant || null,
    });
  });
  if (ui.modalWishlist) {
    ui.modalWishlist.addEventListener("click", async () => {
      if (!state.modalProduct) return;
      const selection = resolveModalSelection(state.modalProduct);
      if (state.modalProduct.hasVariants && !selection.selectedVariant) {
        showToast("Select a variant first.");
        return;
      }
      await saveWishlistItem(
        state.modalProduct.id,
        selection.selectedVariant ? Number(selection.selectedVariant.id) : null
      );
    });
  }
  if (ui.modalVariantSelect) {
    ui.modalVariantSelect.addEventListener("change", () => {
      const value = Number.parseInt(ui.modalVariantSelect.value || "", 10);
      state.modalVariantId = Number.isInteger(value) ? value : null;
      renderModalSelection();
    });
  }
}

function wireCart() {
  ui.cartOpen.addEventListener("click", openCart);
  ui.cartClose.addEventListener("click", closeCart);
  ui.cartBackdrop.addEventListener("click", closeCart);
  ui.checkoutForm.addEventListener("submit", handleCheckout);
  ui.checkoutPaymentMethod.addEventListener("change", syncCheckoutPaymentUI);
  ui.checkoutShippingState.addEventListener("input", () => scheduleShippingQuote({ force: true }));
  ui.checkoutShippingCity.addEventListener("input", () => scheduleShippingQuote({ force: true }));
  ui.applyCoupon.addEventListener("click", applyCouponCode);
  ui.couponCode.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      applyCouponCode();
    }
  });
  [ui.checkoutName, ui.checkoutPhone, ui.checkoutEmail, ui.checkoutShippingState, ui.checkoutShippingCity].forEach((input) => {
    input.addEventListener("change", () => scheduleCartTracking());
  });
}

function revealNewElements() {
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("revealed");
          observer.unobserve(entry.target);
        }
      }
    },
    { threshold: 0.12 }
  );

  document.querySelectorAll(".reveal:not(.revealed)").forEach((element) => observer.observe(element));
}

function startLivePolling() {
  setInterval(async () => {
    try {
      await Promise.all([loadProducts({ silent: true }), loadSummary(state.activeBrand)]);
    } catch (_error) {
      // Keep silent during polling.
    }
  }, 12000);

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      Promise.all([loadProducts({ silent: true }), loadSummary(state.activeBrand)]).catch(() => {});
    }
  });
}

async function init() {
  document.getElementById("year").textContent = String(new Date().getFullYear());

  loadCart();
  renderCart();

  const storedTheme = localStorage.getItem("storeTheme") || "dark";
  applyTheme(storedTheme);
  setMobileMenuOpen(false);
  wireThemeToggle();
  wireMobileHeader();
  wireBrandSwitches();
  wireFilters();
  wireModal();
  wireCart();
  ui.checkoutShippingState.value = state.checkoutShipping.shippingState;
  ui.checkoutShippingCity.value = state.checkoutShipping.shippingCity;
  applyPublicConfig();

  setActiveBrand(state.activeBrand, { persist: false });

  try {
    await Promise.all([loadPublicConfig(), loadProducts(), loadSummary(state.activeBrand), refreshCustomerAuth()]);
    await handleMoniepointRedirect();
    await handlePaystackRedirect();
    await refreshShippingQuote({ force: true });
  } catch (error) {
    console.error(error);
    showToast("Could not load live products.");
  }

  revealNewElements();
  startLivePolling();
}

init();
