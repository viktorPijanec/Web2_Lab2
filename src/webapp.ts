import express from "express";
import path from "path";
import * as auth from "./auth-middleware.ts";
import dotenv from "dotenv";
import session from "express-session";
import bcrypt from "bcrypt";
import { pool } from "./db.ts";
import crypto from "node:crypto";
dotenv.config();

const app = express();
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // Set to true if using HTTPS
    },
  }),
);

app.use(express.static(path.join(import.meta.dirname, "public")));
app.use(auth.setUserInfo);
app.set("views", path.join(import.meta.dirname, "views"));
app.set("view engine", "pug");

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port =
  externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 4080;
const baseURL = externalUrl || `http://localhost:${port}`;

app.get("/", auth.requiresAuthentication, async function (req, res) {
  const username = req.user?.username;

  // const usersResult = await pool.query("SELECT username, balance FROM users");

  // const users = usersResult.rows;

  res.render("index", {
    username,
    csrfToken: getCsrfToken(req),
    vulnerability1Enabled: req.session.vulnerability1Enabled ?? false,
    vulnerability2Enabled: req.session.vulnerability2Enabled ?? false,
  });
});

app.get("/show_users", auth.requiresAuthentication, async function (req, res) {
  const username = req.user?.username;
  const { checkbox1, username: inputUsername } = req.query;

  if (typeof inputUsername !== "string") {
    res.status(400).send("Username is required");
    return;
  }

  const vulnerability1Enabled = checkbox1 === "true";
  req.session.vulnerability1Enabled = vulnerability1Enabled;

  let usersResult;

  if (vulnerability1Enabled) {
    usersResult = await pool.query(
      `SELECT username, balance FROM users where username = '${inputUsername}'`,
    );
  } else {
    usersResult = await pool.query(
      `SELECT username, balance FROM users where username = $1`,
      [inputUsername],
    );
  }

  const users = usersResult.rows;
  const vulnerability2Enabled = req.session.vulnerability2Enabled ?? false;

  res.render("index", {
    username,
    users,
    csrfToken: getCsrfToken(req),
    vulnerability1Enabled,
    vulnerability2Enabled,
  });
});

app.post(
  "/toggle_crsf_vulnerability",
  auth.requiresAuthentication,
  (req, res) => {
    const { checkbox2 } = req.body;
    const vulnerability2Enabled = checkbox2 === "true";
    req.session.vulnerability2Enabled = vulnerability2Enabled;
    res.redirect("/");
  },
);

app.get("/transfer", auth.requiresAuthentication, async (req, res, next) => {
  try {
    const { to, amount, token } = req.query;

    if (!req.session.vulnerability2Enabled) {
      if (typeof token !== "string" || token !== req.session.csrfToken) {
        res.status(403).send("Invalid CSRF token");
        return;
      }
    }

    if (
      typeof to !== "string" ||
      typeof amount !== "string" ||
      !to ||
      !amount
    ) {
      res.status(400).send("Invalid transfer");
      return;
    }
    if (Number(amount) <= 0) {
      res.status(400).send("Invalid transfer");
      return;
    }
    if (to === req.user?.username) {
      res.status(400).send("Invalid transfer");
      return;
    }
    const result1 = await pool.query(
      "SELECT balance FROM users WHERE username = $1",
      [req.user?.username],
    );

    if (result1.rows.length !== 1) {
      res.status(400).send("Invalid transfer");
      return;
    }

    const user = result1.rows[0];
    if (Number(amount) > user.balance) {
      res.status(400).send("Invalid transfer");
      return;
    }

    const result2 = await pool.query(
      "SELECT balance FROM users WHERE username = $1",
      [to],
    );
    if (result2.rows.length !== 1) {
      res.status(400).send("Invalid transfer");
      return;
    }

    const username = req.user?.username;
    await pool.query(
      `UPDATE users
         SET balance = balance - $1
         WHERE username = $2`,
      [Number(amount), username],
    );

    await pool.query(
      `UPDATE users
         SET balance = balance + $1
         WHERE username = $2`,
      [Number(amount), to],
    );

    res.redirect("/");
  } catch (error) {
    next(error);
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: undefined });
});

app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT username, password_hash FROM users WHERE username = $1",
      [username],
    );

    if (result.rows.length !== 1) {
      res.status(401).render("login", {
        error: "Invalid username or password",
      });
      return;
    }

    const user = result.rows[0];

    const passwordIsValid = await bcrypt.compare(password, user.password_hash);

    if (!passwordIsValid) {
      res.status(401).render("login", {
        error: "Invalid username or password",
      });
      return;
    }

    req.session.username = user.username;
    res.redirect("/");
  } catch (error) {
    next(error);
  }
});

app.get("/sign-up", (req, res) => {
  res.render("signup", { error: undefined });
});

app.post("/sign-up", async (req, res, next) => {
  try {
    const { username, password, confirmPassword } = req.body;

    if (!username || !password || !confirmPassword) {
      res.status(400).render("signup", {
        error: "All fields are required",
      });
      return;
    }

    if (password !== confirmPassword) {
      res.status(400).render("signup", {
        error: "Passwords do not match",
      });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users (username, password_hash)
       VALUES ($1, $2)`,
      [username, passwordHash],
    );

    res.redirect("/login");
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "23505"
    ) {
      res.status(409).render("signup", {
        error: "That username is already taken",
      });
      return;
    }

    next(error);
  }
});

app.post("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      next(err);
      return;
    }
    res.redirect("/login");
  });
});

const hostname = externalUrl ? "0.0.0.0" : "localhost";

app.listen(port, hostname, () => {
  console.log(`Server locally running at http://${hostname}:${port}/`);
  if (externalUrl) {
    console.log(`External URL: ${externalUrl}/`);
  }
});

function getCsrfToken(req: express.Request): string {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  return req.session.csrfToken;
}

function hasValidCsrfToken(req: express.Request): boolean {
  const submittedToken = req.body.csrfToken;
  const sessionToken = req.session.csrfToken;

  return (
    typeof submittedToken === "string" &&
    typeof sessionToken === "string" &&
    submittedToken === sessionToken
  );
}
