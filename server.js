// ============================================================
// SLX NETWORK v1.8.2
// Node.js 22+ / Express 5
// ============================================================

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 3000;
const VERSION = "1.8.2";
const NETWORK = "SLX-Testnet";
const FEE = 0.1;
const FAUCET_AMOUNT = 10;

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "SLX_NETWORK_TESTNET_1_8_2_SECRET";

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// ============================================================
// DATABASE
// ============================================================

let pool = null;
let useDatabase = false;

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl:
      process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false,
  });

  useDatabase = true;
}

// ============================================================
// MEMORY DATABASE FALLBACK
// ============================================================

const memory = {
  users: [],
  wallets: [],
  transactions: [],
  blocks: [
    {
      id: 1,
      block_index: 0,
      timestamp: new Date().toISOString(),
      hash: "SLX_GENESIS_1_8_2",
      previous_hash: null,
      transaction_count: 0,
    },
  ],
  faucetClaims: [],
  nextUser: 1,
  nextWallet: 1,
  nextTransaction: 1,
  nextBlock: 2,
};

// ============================================================
// HELPERS
// ============================================================

function walletAddress() {
  return (
    "SLXC" +
    crypto.randomBytes(16).toString("hex").toUpperCase()
  );
}

function txHash() {
  return (
    "SLX" +
    crypto.randomBytes(24).toString("hex").toUpperCase()
  );
}

function blockHash() {
  return (
    "SLXB" +
    crypto.randomBytes(28).toString("hex").toUpperCase()
  );
}

function recoveryCode() {
  return crypto.randomBytes(6).toString("hex").toUpperCase();
}

function validAddress(address) {
  return /^SLXC[A-F0-9]{32}$/.test(
    String(address || "").trim().toUpperCase()
  );
}

function tokenFor(user) {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username,
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    created_at: user.created_at,
  };
}

function authToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7);
}

// ============================================================
// AUTH
// ============================================================

async function auth(req, res, next) {
  try {
    const token = authToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    if (useDatabase) {
      const result = await pool.query(
        `
        SELECT id, username, created_at
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [decoded.userId]
      );

      if (!result.rows.length) {
        return res.status(401).json({
          error: "User not found",
        });
      }

      req.user = result.rows[0];
    } else {
      const user = memory.users.find(
        (u) => u.id === Number(decoded.userId)
      );

      if (!user) {
        return res.status(401).json({
          error: "User not found",
        });
      }

      req.user = user;
    }

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

// ============================================================
// DATABASE INIT
// ============================================================

async function initDatabase() {
  if (!useDatabase) {
    console.log(
      "DATABASE_URL not found."
    );
    console.log(
      "SLX Network will use temporary memory storage."
    );
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(64) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      recovery_code_hash TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      address VARCHAR(36) UNIQUE NOT NULL,
      name VARCHAR(100) DEFAULT 'SLX Wallet',
      balance NUMERIC(30,8) DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      tx_hash VARCHAR(100) UNIQUE NOT NULL,
      type VARCHAR(30) NOT NULL,
      from_wallet INTEGER,
      to_wallet INTEGER,
      amount NUMERIC(30,8) DEFAULT 0,
      fee NUMERIC(30,8) DEFAULT 0,
      block_id INTEGER,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS blocks (
      id SERIAL PRIMARY KEY,
      block_index INTEGER UNIQUE NOT NULL,
      timestamp TIMESTAMPTZ DEFAULT NOW(),
      hash VARCHAR(120) UNIQUE NOT NULL,
      previous_hash VARCHAR(120),
      transaction_count INTEGER DEFAULT 0
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS faucet_claims (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      wallet_id INTEGER NOT NULL,
      claimed_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  const genesis = await pool.query(`
    SELECT id
    FROM blocks
    WHERE block_index = 0
    LIMIT 1
  `);

  if (!genesis.rows.length) {
    await pool.query(
      `
      INSERT INTO blocks
      (block_index, hash, previous_hash, transaction_count)
      VALUES (0, $1, NULL, 0)
      `,
      ["SLX_GENESIS_1_8_2"]
    );
  }

  console.log(
    "PostgreSQL database initialized."
  );
}

// ============================================================
// CREATE BLOCK
// ============================================================

async function createMemoryBlock(
  transactionCount
) {
  const previous =
    memory.blocks[memory.blocks.length - 1];

  const block = {
    id: memory.nextBlock++,
    block_index:
      previous.block_index + 1,
    timestamp:
      new Date().toISOString(),
    hash: blockHash(),
    previous_hash:
      previous.hash,
    transaction_count:
      transactionCount,
  };

  memory.blocks.push(block);

  return block;
}

async function createDbBlock(
  client,
  transactionCount
) {
  const previous =
    await client.query(`
      SELECT block_index, hash
      FROM blocks
      ORDER BY block_index DESC
      LIMIT 1
    `);

  const last =
    previous.rows[0];

  const index =
    Number(last.block_index) + 1;

  const result =
    await client.query(
      `
      INSERT INTO blocks
      (
        block_index,
        hash,
        previous_hash,
        transaction_count
      )
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [
        index,
        blockHash(),
        last.hash,
        transactionCount,
      ]
    );

  return result.rows[0];
}

// ============================================================
// ROOT
// ============================================================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// ============================================================
// HEALTH
// ============================================================

app.get("/health", async (req, res) => {
  res.json({
    status: "ok",
    version: VERSION,
    network: NETWORK,
    database: useDatabase
      ? "postgresql"
      : "memory",
  });
});

// ============================================================
// STATUS
// ============================================================

app.get("/api/status", async (req, res) => {
  try {
    let height = 0;

    if (useDatabase) {
      const result = await pool.query(`
        SELECT block_index
        FROM blocks
        ORDER BY block_index DESC
        LIMIT 1
      `);

      if (result.rows.length) {
        height =
          Number(result.rows[0].block_index);
      }
    } else {
      height =
        memory.blocks[
          memory.blocks.length - 1
        ].block_index;
    }

    res.json({
      name: "SLX Network",
      version: VERSION,
      network: NETWORK,
      status: "online",
      message:
        "SLX Network server is running",

      networkInfo: {
        version: VERSION,
        height,
        transferFee: FEE,
      },

      network_info: {
        version: VERSION,
        height,
        transferFee: FEE,
      },
    });
  } catch (error) {
    res.status(500).json({
      error: error.message,
    });
  }
});

// ============================================================
// REGISTER
// ============================================================

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const username =
        String(req.body.username || "")
          .trim();

      const password =
        String(req.body.password || "");

      if (username.length < 3) {
        return res.status(400).json({
          error:
            "Username must contain at least 3 characters",
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Password must contain at least 6 characters",
        });
      }

      const recovery =
        recoveryCode();

      const passwordHash =
        await bcrypt.hash(password, 10);

      const recoveryHash =
        await bcrypt.hash(recovery, 10);

      if (useDatabase) {
        const exists =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE LOWER(username) =
                  LOWER($1)
            `,
            [username]
          );

        if (exists.rows.length) {
          return res.status(409).json({
            error:
              "Username already exists",
          });
        }

        const userResult =
          await pool.query(
            `
            INSERT INTO users
            (
              username,
              password_hash,
              recovery_code_hash
            )
            VALUES ($1, $2, $3)
            RETURNING id, username, created_at
            `,
            [
              username,
              passwordHash,
              recoveryHash,
            ]
          );

        const user =
          userResult.rows[0];

        const walletResult =
          await pool.query(
            `
            INSERT INTO wallets
            (
              user_id,
              address,
              name,
              balance
            )
            VALUES
            ($1, $2, 'Main Wallet', 0)
            RETURNING *
            `,
            [
              user.id,
              walletAddress(),
            ]
          );

        const token =
          tokenFor(user);

        return res.status(201).json({
          success: true,
          token,
          accessToken: token,
          recoveryCode: recovery,
          recovery_code: recovery,
          user:
            publicUser(user),
          wallet:
            walletResult.rows[0],
        });
      }

      const exists =
        memory.users.find(
          (u) =>
            u.username.toLowerCase() ===
            username.toLowerCase()
        );

      if (exists) {
        return res.status(409).json({
          error:
            "Username already exists",
        });
      }

      const user = {
        id: memory.nextUser++,
        username,
        password_hash:
          passwordHash,
        recovery_code_hash:
          recoveryHash,
        created_at:
          new Date().toISOString(),
      };

      memory.users.push(user);

      const wallet = {
        id: memory.nextWallet++,
        user_id: user.id,
        address:
          walletAddress(),
        name: "Main Wallet",
        balance: 0,
        created_at:
          new Date().toISOString(),
      };

      memory.wallets.push(wallet);

      const token =
        tokenFor(user);

      res.status(201).json({
        success: true,
        token,
        accessToken: token,
        recoveryCode: recovery,
        recovery_code: recovery,
        user:
          publicUser(user),
        wallet,
      });
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Registration failed",
        message:
          error.message,
      });
    }
  }
);

// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      let user;

      if (useDatabase) {
        const result =
          await pool.query(
            `
            SELECT *
            FROM users
            WHERE LOWER(username) =
                  LOWER($1)
            LIMIT 1
            `,
            [username]
          );

        if (!result.rows.length) {
          return res.status(401).json({
            error:
              "Invalid username or password",
          });
        }

        user =
          result.rows[0];
      } else {
        user =
          memory.users.find(
            (u) =>
              u.username.toLowerCase() ===
              username.toLowerCase()
          );

        if (!user) {
          return res.status(401).json({
            error:
              "Invalid username or password",
          });
        }
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid username or password",
        });
      }

      const token =
        tokenFor(user);

      res.json({
        success: true,
        token,
        accessToken: token,
        user:
          publicUser(user),
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Login failed",
      });
    }
  }
);

// ============================================================
// ME
// ============================================================

app.get(
  "/api/auth/me",
  auth,
  async (req, res) => {
    let wallets;

    if (useDatabase) {
      const result =
        await pool.query(
          `
          SELECT *
          FROM wallets
          WHERE user_id = $1
          ORDER BY id
          `,
          [req.user.id]
        );

      wallets =
        result.rows;
    } else {
      wallets =
        memory.wallets.filter(
          (w) =>
            w.user_id ===
            req.user.id
        );
    }

    res.json({
      success: true,
      user:
        publicUser(req.user),
      wallets,
    });
  }
);

// ============================================================
// WALLETS
// ============================================================

app.get(
  "/api/wallets",
  auth,
  async (req, res) => {
    try {
      let wallets;

      if (useDatabase) {
        const result =
          await pool.query(
            `
            SELECT *
            FROM wallets
            WHERE user_id = $1
            ORDER BY id
            `,
            [req.user.id]
          );

        wallets =
          result.rows;
      } else {
        wallets =
          memory.wallets.filter(
            (w) =>
              w.user_id ===
              req.user.id
          );
      }

      res.json({
        success: true,
        wallets,
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Failed to load wallets",
      });
    }
  }
);

// ============================================================
// CREATE WALLET
// ============================================================

app.post(
  "/api/wallet/create",
  auth,
  async (req, res) => {
    try {
      const address =
        walletAddress();

      if (useDatabase) {
        const result =
          await pool.query(
            `
            INSERT INTO wallets
            (
              user_id,
              address,
              name,
              balance
            )
            VALUES
            ($1, $2, 'SLX Wallet', 0)
            RETURNING *
            `,
            [
              req.user.id,
              address,
            ]
          );

        return res.status(201).json({
          success: true,
          wallet:
            result.rows[0],
        });
      }

      const wallet = {
        id: memory.nextWallet++,
        user_id:
          req.user.id,
        address,
        name:
          "SLX Wallet",
        balance: 0,
        created_at:
          new Date().toISOString(),
      };

      memory.wallets.push(
        wallet
      );

      res.status(201).json({
        success: true,
        wallet,
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Failed to create wallet",
      });
    }
  }
);

// ============================================================
// SELECT WALLET
// ============================================================

app.post(
  "/api/wallet/select",
  auth,
  async (req, res) => {
    const walletId =
      Number(
        req.body.walletId ||
          req.body.wallet_id
      );

    let wallet;

    if (useDatabase) {
      const result =
        await pool.query(
          `
          SELECT *
          FROM wallets
          WHERE id = $1
            AND user_id = $2
          LIMIT 1
          `,
          [
            walletId,
            req.user.id,
          ]
        );

      wallet =
        result.rows[0];
    } else {
      wallet =
        memory.wallets.find(
          (w) =>
            w.id === walletId &&
            w.user_id ===
              req.user.id
        );
    }

    if (!wallet) {
      return res.status(404).json({
        error:
          "Wallet not found",
      });
    }

    res.json({
      success: true,
      wallet,
    });
  }
);

// ============================================================
// WALLET DETAILS
// ============================================================

app.get(
  "/api/wallet/:id",
  auth,
  async (req, res) => {
    const walletId =
      Number(req.params.id);

    let wallet;
    let transactions;

    if (useDatabase) {
      const walletResult =
        await pool.query(
          `
          SELECT *
          FROM wallets
          WHERE id = $1
            AND user_id = $2
          LIMIT 1
          `,
          [
            walletId,
            req.user.id,
          ]
        );

      wallet =
        walletResult.rows[0];

      if (!wallet) {
        return res.status(404).json({
          error:
            "Wallet not found",
        });
      }

      const txResult =
        await pool.query(
          `
          SELECT *
          FROM transactions
          WHERE from_wallet = $1
             OR to_wallet = $1
          ORDER BY created_at DESC
          LIMIT 100
          `,
          [walletId]
        );

      transactions =
        txResult.rows;
    } else {
      wallet =
        memory.wallets.find(
          (w) =>
            w.id === walletId &&
            w.user_id ===
              req.user.id
        );

      if (!wallet) {
        return res.status(404).json({
          error:
            "Wallet not found",
        });
      }

      transactions =
        memory.transactions.filter(
          (t) =>
            t.from_wallet ===
              walletId ||
            t.to_wallet ===
              walletId
        );
    }

    res.json({
      ...wallet,
      transactions,
    });
  }
);

// ============================================================
// FAUCET
// ============================================================

app.post(
  "/api/faucet",
  auth,
  async (req, res) => {
    const walletId =
      Number(
        req.body.walletId ||
          req.body.wallet_id
      );

    try {
      if (useDatabase) {
        const walletResult =
          await pool.query(
            `
            SELECT *
            FROM wallets
            WHERE id = $1
              AND user_id = $2
            LIMIT 1
            `,
            [
              walletId,
              req.user.id,
            ]
          );

        if (
          !walletResult.rows.length
        ) {
          return res.status(404).json({
            error:
              "Wallet not found",
          });
        }

        const recent =
          await pool.query(
            `
            SELECT claimed_at
            FROM faucet_claims
            WHERE user_id = $1
            ORDER BY claimed_at DESC
            LIMIT 1
            `,
            [req.user.id]
          );

        if (recent.rows.length) {
          const last =
            new Date(
              recent.rows[0]
                .claimed_at
            );

          if (
            Date.now() -
              last.getTime() <
              24 * 60 * 60 * 1000
          ) {
            return res.status(429).json({
              error:
                "Faucet cooldown active",
            });
          }
        }

        const client =
          await pool.connect();

        try {
          await client.query(
            "BEGIN"
          );

          await client.query(
            `
            UPDATE wallets
            SET balance =
              balance + $1
            WHERE id = $2
            `,
            [
              FAUCET_AMOUNT,
              walletId,
            ]
          );

          const hash =
            txHash();

          const tx =
            await client.query(
              `
              INSERT INTO transactions
              (
                tx_hash,
                type,
                from_wallet,
                to_wallet,
                amount,
                fee
              )
              VALUES
              ($1, 'FAUCET', NULL, $2, $3, 0)
              RETURNING *
              `,
              [
                hash,
                walletId,
                FAUCET_AMOUNT,
              ]
            );

          const block =
            await createDbBlock(
              client,
              1
            );

          await client.query(
            `
            UPDATE transactions
            SET block_id = $1
            WHERE id = $2
            `,
            [
              block.id,
              tx.rows[0].id,
            ]
          );

          await client.query(
            `
            INSERT INTO faucet_claims
            (user_id, wallet_id)
            VALUES ($1, $2)
            `,
            [
              req.user.id,
              walletId,
            ]
          );

          await client.query(
            "COMMIT"
          );

          return res.json({
            success: true,
            amount:
              FAUCET_AMOUNT,
            transaction:
              tx.rows[0],
            block,
          });
        } catch (e) {
          await client.query(
            "ROLLBACK"
          );
          throw e;
        } finally {
          client.release();
        }
      }

      const wallet =
        memory.wallets.find(
          (w) =>
            w.id === walletId &&
            w.user_id ===
              req.user.id
        );

      if (!wallet) {
        return res.status(404).json({
          error:
            "Wallet not found",
        });
      }

      const lastClaim =
        memory.faucetClaims
          .filter(
            (x) =>
              x.user_id ===
              req.user.id
          )
          .sort(
            (a, b) =>
              new Date(b.claimed_at) -
              new Date(a.claimed_at)
          )[0];

      if (lastClaim) {
        if (
          Date.now() -
            new Date(
              lastClaim.claimed_at
            ).getTime() <
            24 *
              60 *
              60 *
              1000
        ) {
          return res.status(429).json({
            error:
              "Faucet cooldown active",
          });
        }
      }

      wallet.balance =
        Number(wallet.balance) +
        FAUCET_AMOUNT;

      const tx = {
        id:
          memory.nextTransaction++,
        tx_hash:
          txHash(),
        type:
          "FAUCET",
        from_wallet:
          null,
        to_wallet:
          wallet.id,
        amount:
          FAUCET_AMOUNT,
        fee: 0,
        block_id:
          null,
        created_at:
          new Date().toISOString(),
      };

      memory.transactions.push(
        tx
      );

      const block =
        await createMemoryBlock(1);

      tx.block_id =
        block.id;

      memory.faucetClaims.push({
        user_id:
          req.user.id,
        wallet_id:
          wallet.id,
        claimed_at:
          new Date().toISOString(),
      });

      res.json({
        success: true,
        amount:
          FAUCET_AMOUNT,
        transaction:
          tx,
        block,
        wallet,
      });
    } catch (error) {
      console.error(
        "FAUCET ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Faucet failed",
      });
    }
  }
);

// ============================================================
// SEND
// ============================================================

app.post(
  "/api/send",
  auth,
  async (req, res) => {
    const fromWalletId =
      Number(
        req.body.fromWalletId ||
          req.body.from_wallet_id
      );

    const toAddress =
      String(
        req.body.toAddress ||
          req.body.to_address ||
          ""
      )
        .trim()
        .toUpperCase();

    const amount =
      Number(req.body.amount);

    if (
      !Number.isFinite(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error:
          "Invalid amount",
      });
    }

    if (
      !validAddress(toAddress)
    ) {
      return res.status(400).json({
        error:
          "Invalid SLX address",
      });
    }

    try {
      if (useDatabase) {
        const client =
          await pool.connect();

        try {
          await client.query(
            "BEGIN"
          );

          const senderResult =
            await client.query(
              `
              SELECT *
              FROM wallets
              WHERE id = $1
                AND user_id = $2
              FOR UPDATE
              `,
              [
                fromWalletId,
                req.user.id,
              ]
            );

          if (
            !senderResult.rows.length
          ) {
            await client.query(
              "ROLLBACK"
            );

            return res.status(404).json({
              error:
                "Sender wallet not found",
            });
          }

          const sender =
            senderResult.rows[0];

          const recipientResult =
            await client.query(
              `
              SELECT *
              FROM wallets
              WHERE address = $1
              FOR UPDATE
              `,
              [toAddress]
            );

          if (
            !recipientResult.rows.length
          ) {
            await client.query(
              "ROLLBACK"
            );

            return res.status(404).json({
              error:
                "Recipient wallet not found",
            });
          }

          const recipient =
            recipientResult.rows[0];

          if (
            sender.id ===
            recipient.id
          ) {
            await client.query(
              "ROLLBACK"
            );

            return res.status(400).json({
              error:
                "Cannot send to same wallet",
            });
          }

          const total =
            amount + FEE;

          if (
            Number(sender.balance) <
            total
          ) {
            await client.query(
              "ROLLBACK"
            );

            return res.status(400).json({
              error:
                "Insufficient balance",
            });
          }

          await client.query(
            `
            UPDATE wallets
            SET balance =
              balance - $1
            WHERE id = $2
            `,
            [
              total,
              sender.id,
            ]
          );

          await client.query(
            `
            UPDATE wallets
            SET balance =
              balance + $1
            WHERE id = $2
            `,
            [
              amount,
              recipient.id,
            ]
          );

          const hash =
            txHash();

          const tx =
            await client.query(
              `
              INSERT INTO transactions
              (
                tx_hash,
                type,
                from_wallet,
                to_wallet,
                amount,
                fee
              )
              VALUES
              (
                $1,
                'TRANSFER',
                $2,
                $3,
                $4,
                $5
              )
              RETURNING *
              `,
              [
                hash,
                sender.id,
                recipient.id,
                amount,
                FEE,
              ]
            );

          const block =
            await createDbBlock(
              client,
              1
            );

          await client.query(
            `
            UPDATE transactions
            SET block_id = $1
            WHERE id = $2
            `,
            [
              block.id,
              tx.rows[0].id,
            ]
          );

          await client.query(
            "COMMIT"
          );

          return res.json({
            success: true,
            transaction:
              tx.rows[0],
            block,
            fee: FEE,
          });
        } catch (e) {
          await client.query(
            "ROLLBACK"
          );
          throw e;
        } finally {
          client.release();
        }
      }

      const sender =
        memory.wallets.find(
          (w) =>
            w.id ===
              fromWalletId &&
            w.user_id ===
              req.user.id
        );

      const recipient =
        memory.wallets.find(
          (w) =>
            w.address ===
            toAddress
        );

      if (!sender) {
        return res.status(404).json({
          error:
            "Sender wallet not found",
        });
      }

      if (!recipient) {
        return res.status(404).json({
          error:
            "Recipient wallet not found",
        });
      }

      if (
        sender.id ===
        recipient.id
      ) {
        return res.status(400).json({
          error:
            "Cannot send to same wallet",
        });
      }

      const total =
        amount + FEE;

      if (
        Number(sender.balance) <
        total
      ) {
        return res.status(400).json({
          error:
            "Insufficient balance",
        });
      }

      sender.balance =
        Number(sender.balance) -
        total;

      recipient.balance =
        Number(recipient.balance) +
        amount;

      const tx = {
        id:
          memory.nextTransaction++,
        tx_hash:
          txHash(),
        type:
          "TRANSFER",
        from_wallet:
          sender.id,
        to_wallet:
          recipient.id,
        amount,
        fee: FEE,
        block_id:
          null,
        created_at:
          new Date().toISOString(),
      };

      memory.transactions.push(
        tx
      );

      const block =
        await createMemoryBlock(1);

      tx.block_id =
        block.id;

      res.json({
        success: true,
        transaction:
          tx,
        block,
        fee: FEE,
      });
    } catch (error) {
      console.error(
        "SEND ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Transaction failed",
      });
    }
  }
);

// ============================================================
// BLOCKS
// ============================================================

app.get(
  "/api/blocks",
  auth,
  async (req, res) => {
    try {
      let blocks;

      if (useDatabase) {
        const result =
          await pool.query(`
            SELECT *
            FROM blocks
            ORDER BY block_index DESC
            LIMIT 50
          `);

        blocks =
          result.rows;
      } else {
        blocks =
          [...memory.blocks]
            .reverse()
            .slice(0, 50);
      }

      res.json({
        success: true,
        blocks,
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Failed to load blocks",
      });
    }
  }
);

// ============================================================
// ECONOMY
// ============================================================

app.get(
  "/api/economy",
  auth,
  async (req, res) => {
    try {
      let supply = 0;

      if (useDatabase) {
        const result =
          await pool.query(`
            SELECT
              COALESCE(
                SUM(balance),
                0
              ) AS supply
            FROM wallets
          `);

        supply =
          Number(
            result.rows[0].supply
          );
      } else {
        supply =
          memory.wallets.reduce(
            (sum, w) =>
              sum +
              Number(w.balance),
            0
          );
      }

      res.json({
        success: true,
        totalSupply: supply,
        total_supply: supply,
        supply,
        maxSupply: 1000000000,
        max_supply: 1000000000,
        transferFee: FEE,
        transfer_fee: FEE,
        faucetAmount:
          FAUCET_AMOUNT,
        faucet_amount:
          FAUCET_AMOUNT,
        version: VERSION,
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Failed to load economy",
      });
    }
  }
);

// ============================================================
// CHAIN VERIFY
// ============================================================

app.post(
  "/api/chain/verify",
  auth,
  async (req, res) => {
    try {
      let valid = true;

      if (useDatabase) {
        const result =
          await pool.query(`
            SELECT *
            FROM blocks
            ORDER BY block_index ASC
          `);

        const blocks =
          result.rows;

        for (
          let i = 1;
          i < blocks.length;
          i++
        ) {
          if (
            blocks[i]
              .previous_hash !==
            blocks[i - 1].hash
          ) {
            valid = false;
            break;
          }
        }
      } else {
        for (
          let i = 1;
          i < memory.blocks.length;
          i++
        ) {
          if (
            memory.blocks[i]
              .previous_hash !==
            memory.blocks[i - 1].hash
          ) {
            valid = false;
            break;
          }
        }
      }

      res.json({
        success: true,
        valid,
        verified: valid,
        status:
          valid
            ? "valid"
            : "invalid",
        version: VERSION,
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Chain verification failed",
        valid: false,
        verified: false,
        status: "invalid",
      });
    }
  }
);

// ============================================================
// PASSWORD CHANGE
// ============================================================

app.post(
  "/api/auth/password/change",
  auth,
  async (req, res) => {
    const currentPassword =
      String(
        req.body.currentPassword ||
          ""
      );

    const newPassword =
      String(
        req.body.newPassword ||
          ""
      );

    if (newPassword.length < 6) {
      return res.status(400).json({
        error:
          "Password must contain at least 6 characters",
      });
    }

    let valid;

    if (useDatabase) {
      const result =
        await pool.query(
          `
          SELECT password_hash
          FROM users
          WHERE id = $1
          `,
          [req.user.id]
        );

      valid =
        await bcrypt.compare(
          currentPassword,
          result.rows[0]
            .password_hash
        );

      if (!valid) {
        return res.status(400).json({
          error:
            "Current password is incorrect",
        });
      }

      const hash =
        await bcrypt.hash(
          newPassword,
          10
        );

      await pool.query(
        `
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        `,
        [
          hash,
          req.user.id,
        ]
      );
    } else {
      valid =
        await bcrypt.compare(
          currentPassword,
          req.user.password_hash
        );

      if (!valid) {
        return res.status(400).json({
          error:
            "Current password is incorrect",
        });
      }

      req.user.password_hash =
        await bcrypt.hash(
          newPassword,
          10
        );
    }

    const token =
      tokenFor(req.user);

    res.json({
      success: true,
      token,
      accessToken: token,
    });
  }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
  "/api/auth/logout",
  auth,
  (req, res) => {
    res.json({
      success: true,
      message:
        "Logged out successfully",
    });
  }
);

// ============================================================
// RECOVERY RESET
// ============================================================

app.post(
  "/api/auth/recovery/reset",
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ""
        ).trim();

      const code =
        String(
          req.body.recoveryCode ||
            req.body.recovery_code ||
            ""
        )
          .trim()
          .toUpperCase();

      const newPassword =
        String(
          req.body.newPassword || ""
        );

      let user;

      if (useDatabase) {
        const result =
          await pool.query(
            `
            SELECT *
            FROM users
            WHERE LOWER(username) =
                  LOWER($1)
            LIMIT 1
            `,
            [username]
          );

        user =
          result.rows[0];
      } else {
        user =
          memory.users.find(
            (u) =>
              u.username.toLowerCase() ===
              username.toLowerCase()
          );
      }

      if (!user) {
        return res.status(400).json({
          error:
            "Invalid recovery data",
        });
      }

      const valid =
        await bcrypt.compare(
          code,
          user.recovery_code_hash
        );

      if (!valid) {
        return res.status(400).json({
          error:
            "Invalid recovery data",
        });
      }

      const hash =
        await bcrypt.hash(
          newPassword,
          10
        );

      if (useDatabase) {
        await pool.query(
          `
          UPDATE users
          SET password_hash = $1
          WHERE id = $2
          `,
          [
            hash,
            user.id,
          ]
        );
      } else {
        user.password_hash =
          hash;
      }

      const token =
        tokenFor(user);

      res.json({
        success: true,
        token,
        accessToken: token,
        user:
          publicUser(user),
      });
    } catch (error) {
      res.status(500).json({
        error:
          "Recovery failed",
      });
    }
  }
);

// ============================================================
// API 404
// ============================================================

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      error:
        "API endpoint not found",
      version: VERSION,
    });
  }
);

// ============================================================
// FRONTEND FALLBACK
// EXPRESS 5 SAFE
// ============================================================

app.use(
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "index.html"
      )
    );
  }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      error:
        "Internal server error",
    });
  }
);

// ============================================================
// START
// ============================================================

async function start() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          "===================================="
        );
        console.log(
          "SLX NETWORK v1.8.2"
        );
        console.log(
          "Network:",
          NETWORK
        );
        console.log(
          "Port:",
          PORT
        );
        console.log(
          "Node:",
          process.version
        );
        console.log(
          "Storage:",
          useDatabase
            ? "PostgreSQL"
            : "Memory"
        );
        console.log(
          "Status: ONLINE"
        );
        console.log(
          "===================================="
        );
      }
    );
  } catch (error) {
    console.error(
      "STARTUP ERROR:",
      error
    );

    process.exit(1);
  }
}

process.on(
  "SIGTERM",
  async () => {
    if (pool) {
      await pool.end();
    }

    process.exit(0);
  }
);

process.on(
  "SIGINT",
  async () => {
    if (pool) {
      await pool.end();
    }

    process.exit(0);
  }
);

start();