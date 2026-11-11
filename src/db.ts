import { Pool } from "pg";
import dotenv from "dotenv";
dotenv.config();
export * from "./db.ts";

const useSsl = process.env.DB_SSL === "true";

export const pool = new Pool({
  user: process.env.DB_USERNAME,
  host: process.env.DB_HOSTNAME,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: 5432,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
});
