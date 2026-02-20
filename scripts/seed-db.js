const fs = require("fs/promises");
const path = require("path");
const { Client } = require("pg");
require("dotenv").config();

const seedProducts = [
  {
    name: "Imperial Velvet Duvet Set",
    slug: "imperial-velvet-duvet-set",
    brand: "sholly-home",
    category: "Bedding",
    description: "Soft-touch velvet duvet cover set with rich drape and hotel-grade finish.",
    priceKobo: 2450000,
    compareAtKobo: 2950000,
    stockQty: 18,
    imageUrl:
      "https://images.unsplash.com/photo-1616594039964-3dd3c1f0f4f9?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [
      "https://images.unsplash.com/photo-1616627561839-074385245ff6?auto=format&fit=crop&w=1200&q=80",
      "https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=1200&q=80",
    ],
    isFeatured: true,
  },
  {
    name: "Monaco Egyptian Cotton Sheets",
    slug: "monaco-egyptian-cotton-sheets",
    brand: "sholly-home",
    category: "Sheets",
    description: "Luxury 800-thread-count cotton sheets tailored for cool and breathable sleep.",
    priceKobo: 1350000,
    compareAtKobo: 1650000,
    stockQty: 32,
    imageUrl:
      "https://images.unsplash.com/photo-1505693416388-ac5ce068fe85?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [
      "https://images.unsplash.com/photo-1484101403633-562f891dc89a?auto=format&fit=crop&w=1200&q=80",
    ],
    isFeatured: true,
  },
  {
    name: "Sahara Gold Throw Pillows",
    slug: "sahara-gold-throw-pillows",
    brand: "sholly-home",
    category: "Decor",
    description: "Hand-finished accent pillows designed to elevate neutral and warm interiors.",
    priceKobo: 420000,
    compareAtKobo: null,
    stockQty: 50,
    imageUrl:
      "https://images.unsplash.com/photo-1555041469-a586c61ea9bc?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [],
    isFeatured: false,
  },
  {
    name: "Noir Luxe Bed Runner",
    slug: "noir-luxe-bed-runner",
    brand: "sholly-home",
    category: "Bedding",
    description: "Textured bed runner with metallic thread work and anti-slip backing.",
    priceKobo: 390000,
    compareAtKobo: 520000,
    stockQty: 26,
    imageUrl:
      "https://images.unsplash.com/photo-1566669437685-8157e1863f24?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [],
    isFeatured: false,
  },
  {
    name: "Signature Marble Scented Candles",
    slug: "signature-marble-scented-candles",
    brand: "sholly-home",
    category: "Decor",
    description: "Premium soy wax candles in refillable marble vessels with layered scents.",
    priceKobo: 280000,
    compareAtKobo: null,
    stockQty: 45,
    imageUrl:
      "https://images.unsplash.com/photo-1603006905393-3500b1f2f5b6?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [],
    isFeatured: true,
  },
  {
    name: "Regal Agbada Ensemble",
    slug: "regal-agbada-ensemble",
    brand: "apex-apparel",
    category: "Men",
    description: "Three-piece embroidered agbada tailored with premium brocade lining.",
    priceKobo: 6800000,
    compareAtKobo: 7900000,
    stockQty: 12,
    imageUrl:
      "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [
      "https://images.unsplash.com/photo-1521572267360-ee0c2909d518?auto=format&fit=crop&w=1200&q=80",
    ],
    isFeatured: true,
  },
  {
    name: "Ankara Muse Two-Piece",
    slug: "ankara-muse-two-piece",
    brand: "apex-apparel",
    category: "Women",
    description: "Modern Ankara set with structured shoulder line and fluid silhouette.",
    priceKobo: 4600000,
    compareAtKobo: 5200000,
    stockQty: 19,
    imageUrl:
      "https://images.unsplash.com/photo-1529626455594-4ff0802cfb7e?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [],
    isFeatured: true,
  },
  {
    name: "Midnight Kaftan Classic",
    slug: "midnight-kaftan-classic",
    brand: "apex-apparel",
    category: "Unisex",
    description: "Relaxed fit kaftan with hand-stitched neckline and matte satin trim.",
    priceKobo: 3800000,
    compareAtKobo: null,
    stockQty: 22,
    imageUrl:
      "https://images.unsplash.com/photo-1571513722275-4b41940f54b8?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [],
    isFeatured: false,
  },
  {
    name: "Aso-Oke Ceremony Set",
    slug: "aso-oke-ceremony-set",
    brand: "apex-apparel",
    category: "Couples",
    description: "Matching celebration set woven with traditional aso-oke in modern cuts.",
    priceKobo: 9200000,
    compareAtKobo: null,
    stockQty: 9,
    imageUrl:
      "https://images.unsplash.com/photo-1590330297626-d7aff25a0431?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [],
    isFeatured: true,
  },
  {
    name: "Royal Bubu Flow Dress",
    slug: "royal-bubu-flow-dress",
    brand: "apex-apparel",
    category: "Women",
    description: "Statement bubu gown with flowing hemline and subtle metallic detailing.",
    priceKobo: 4100000,
    compareAtKobo: 4800000,
    stockQty: 15,
    imageUrl:
      "https://images.unsplash.com/photo-1515886657613-9f3515b0c78f?auto=format&fit=crop&w=1200&q=80",
    galleryUrls: [],
    isFeatured: false,
  },
];

async function run() {
  if (!process.env.DATABASE_URL) {
    throw new Error("Missing DATABASE_URL in environment");
  }

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl:
      process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false },
  });

  await client.connect();

  const schema = await fs.readFile(path.join(__dirname, "..", "db", "schema.sql"), "utf8");
  await client.query(schema);

  for (const product of seedProducts) {
    await client.query(
      `INSERT INTO products
        (name, slug, brand, category, description, price_kobo, compare_at_kobo, stock_qty, image_url, gallery_urls, is_featured)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text[], $11)
       ON CONFLICT (slug) DO UPDATE SET
        name = EXCLUDED.name,
        brand = EXCLUDED.brand,
        category = EXCLUDED.category,
        description = EXCLUDED.description,
        price_kobo = EXCLUDED.price_kobo,
        compare_at_kobo = EXCLUDED.compare_at_kobo,
        stock_qty = EXCLUDED.stock_qty,
        image_url = EXCLUDED.image_url,
        gallery_urls = EXCLUDED.gallery_urls,
        is_featured = EXCLUDED.is_featured,
        updated_at = NOW()`,
      [
        product.name,
        product.slug,
        product.brand,
        product.category,
        product.description,
        product.priceKobo,
        product.compareAtKobo,
        product.stockQty,
        product.imageUrl,
        product.galleryUrls,
        product.isFeatured,
      ]
    );
  }

  await client.end();
  console.log(`Seeded ${seedProducts.length} products.`);
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

