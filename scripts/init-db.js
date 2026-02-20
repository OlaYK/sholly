const fs = require("fs/promises");
const path = require("path");
const { Client } = require("pg");
require("dotenv").config();

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
  await client.end();
  console.log("Database schema initialized.");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

