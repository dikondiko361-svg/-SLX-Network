const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

const DATA_FILE = path.join(__dirname, "slx-data.json");

let database = {
  users: {},
  wallets: {}
};

const sessions = new Map();

/* =========================
   DATABASE
========================= */

function loadDatabase() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      saveDatabase();
      console.log("SLX database created.");
      return;
    }

    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);

    database.users = data.users || {};
    database.wallets = data.wallets || {};

    // Совместимость со старыми аккаунтами
    for (const user of Object.values(database.users)) {
      if (!Array.isArray(user.walletIds)) {
        user.walletIds = [];

        if (user.walletId) {
          user.walletIds.push(user.walletId);
        }
      }
    }

    console.log(
      "Database loaded:",
      Object.keys(database.users).length,
      "users,",
      Object.keys(database.wallets).length,
      "wallets"
    );

  } catch (error) {
    console.error("Database load error:", error);
  }
}

function saveDatabase() {
  try {
    const tempFile = DATA_FILE + ".tmp";

    fs.writeFileSync(
      tempFile,
      JSON.stringify(database, null, 2),
      "utf8"
    );

    fs.renameSync(tempFile, DATA_FILE);

  } catch (error) {
    console.error("Database save error:", error);
  }
}

/* =========================
   IDS
========================= */

function makeWalletId() {
  let id;

  do {
    id =
      "SLX" +
      crypto
        .randomBytes(5)
        .toString("hex")
        .toUpperCase();
  } while (database.wallets[id]);

  return id;
}

function makeAddress() {
  return (
    "SLX-" +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );
}

function makeUserId() {
  return (
    "USR-" +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );
}

function makeSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

/* =========================
   PASSWORD
========================= */

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

/* =========================
   WALLET
========================= */

function createWallet(ownerId) {
  const id = makeWalletId();

  const wallet = {
    id,
    ownerId,
    name: "SLX Wallet",
    address: makeAddress(),
    balance: 1000,
    transactions: [],
    createdAt: new Date().toISOString()
  };

  database.wallets[id] = wallet;

  return wallet;
}

function getWallet(id) {
  const key = String(id || "")
    .trim()
    .toUpperCase();

  return database.wallets[key] || null;
}

function getUserWallets(user) {
  if (!user || !Array.isArray(user.walletIds)) {
    return [];
  }

  return user.walletIds
    .map(id => getWallet(id))
    .filter(Boolean);
}

/* =========================
   TRANSACTIONS
========================= */

function addTransaction(wallet, transaction) {
  wallet.transactions.unshift(transaction);

  if (wallet.transactions.length > 50) {
    wallet.transactions =
      wallet.transactions.slice(0, 50);
  }
}

/* =========================
   USERS
========================= */

function findUserByUsername(username) {
  const target = String(username || "")
    .trim()
    .toLowerCase();

  for (const user of Object.values(database.users)) {
    if (
      user.username.toLowerCase() === target
    ) {
      return user;
    }
  }

  return null;
}

/* =========================
   AUTH
========================= */

function getToken(req) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.substring(7).trim();
}

function getUserByToken(req) {
  const token = getToken(req);

  if (!token) {
    return null;
  }

  const userId = sessions.get(token);

  if (!userId) {
    return null;
  }

  return database.users[userId] || null;
}

/* =========================
   JSON
========================= */

function sendJSON(res, data, status = 200) {
  res.writeHead(status, {
    "Content-Type":
      "application/json; charset=utf-8",

    "Access-Control-Allow-Origin": "*",

    "Access-Control-Allow-Headers":
      "Content-Type, Authorization"
  });

  res.end(JSON.stringify(data));
}

/* =========================
   BODY
========================= */

function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;
    });

    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

/* =========================
   HTML
========================= */

function sendHTML(res) {
  fs.readFile(
    path.join(__dirname, "index.html"),
    "utf8",
    (error, html) => {
      if (error) {
        res.writeHead(500, {
          "Content-Type":
            "text/plain; charset=utf-8"
        });

        res.end("index.html not found");
        return;
      }

      res.writeHead(200, {
        "Content-Type":
          "text/html; charset=utf-8"
      });

      res.end(html);
    }
  );
}

/* =========================
   SERVER
========================= */

const server = http.createServer(
  async (req, res) => {

    try {

      /* =========================
         MAIN PAGE
      ========================= */

      if (
        req.method === "GET" &&
        req.url === "/"
      ) {
        sendHTML(res);
        return;
      }


      /* =========================
         REGISTER
      ========================= */

      if (
        req.method === "POST" &&
        req.url === "/api/auth/register"
      ) {

        const body = await getBody(req);

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        if (
          username.length < 3 ||
          username.length > 20
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Имя должно содержать от 3 до 20 символов."
            },
            400
          );

          return;
        }

        if (
          !/^[a-zA-Z0-9_]+$/.test(username)
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Имя может содержать только буквы, цифры и _."
            },
            400
          );

          return;
        }

        if (password.length < 6) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Пароль должен содержать минимум 6 символов."
            },
            400
          );

          return;
        }

        if (
          findUserByUsername(username)
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Это имя уже зарегистрировано."
            },
            409
          );

          return;
        }

        const userId = makeUserId();

        const user = {
          id: userId,
          username,
          passwordHash:
            hashPassword(password),

          walletIds: [],

          createdAt:
            new Date().toISOString()
        };

        database.users[userId] = user;

        const wallet =
          createWallet(userId);

        user.walletIds.push(wallet.id);

        // Первый кошелёк считаем главным
        user.walletId = wallet.id;

        saveDatabase();

        const token =
          makeSessionToken();

        sessions.set(
          token,
          user.id
        );

        sendJSON(res, {
          success: true,

          token,

          user: {
            id: user.id,
            username: user.username,
            walletId: user.walletId,
            walletIds: user.walletIds
          },

          wallet: {
            id: wallet.id,
            address: wallet.address,
            balance: wallet.balance
          }
        });

        return;
      }


      /* =========================
         LOGIN
      ========================= */

      if (
        req.method === "POST" &&
        req.url === "/api/auth/login"
      ) {

        const body = await getBody(req);

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        const user =
          findUserByUsername(username);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Неверное имя или пароль."
            },
            401
          );

          return;
        }

        const passwordHash =
          hashPassword(password);

        if (
          user.passwordHash !==
          passwordHash
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Неверное имя или пароль."
            },
            401
          );

          return;
        }

        // Совместимость
        if (!Array.isArray(user.walletIds)) {
          user.walletIds = [];

          if (user.walletId) {
            user.walletIds.push(
              user.walletId
            );
          }
        }

        const token =
          makeSessionToken();

        sessions.set(
          token,
          user.id
        );

        const wallet =
          getWallet(user.walletId);

        sendJSON(res, {
          success: true,

          token,

          user: {
            id: user.id,
            username: user.username,
            walletId: user.walletId,
            walletIds: user.walletIds
          },

          wallet: wallet
            ? {
                id: wallet.id,
                address: wallet.address,
                balance: wallet.balance
              }
            : null
        });

        return;
      }


      /* =========================
         CURRENT USER
      ========================= */

      if (
        req.method === "GET" &&
        req.url === "/api/auth/me"
      ) {

        const user =
          getUserByToken(req);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Не авторизован."
            },
            401
          );

          return;
        }

        if (!Array.isArray(user.walletIds)) {
          user.walletIds = [];

          if (user.walletId) {
            user.walletIds.push(
              user.walletId
            );
          }

          saveDatabase();
        }

        const wallet =
          getWallet(user.walletId);

        sendJSON(res, {
          success: true,

          user: {
            id: user.id,
            username: user.username,
            walletId: user.walletId,
            walletIds: user.walletIds
          },

          wallet: wallet
            ? {
                id: wallet.id,
                address: wallet.address,
                balance: wallet.balance
              }
            : null
        });

        return;
      }


      /* =========================
         LOGOUT
      ========================= */

      if (
        req.method === "POST" &&
        req.url === "/api/auth/logout"
      ) {

        const token =
          getToken(req);

        if (token) {
          sessions.delete(token);
        }

        sendJSON(res, {
          success: true
        });

        return;
      }


      /* =========================
         CREATE NEW WALLET
      ========================= */

      if (
        req.method === "POST" &&
        req.url === "/api/wallet/create"
      ) {

        const user =
          getUserByToken(req);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Необходимо войти в аккаунт."
            },
            401
          );

          return;
        }

        if (!Array.isArray(user.walletIds)) {
          user.walletIds = [];
        }

        const wallet =
          createWallet(user.id);

        user.walletIds.push(
          wallet.id
        );

        saveDatabase();

        sendJSON(res, {
          success: true,

          wallet: {
            id: wallet.id,
            address: wallet.address,
            balance: wallet.balance,
            transactions:
              wallet.transactions
          },

          walletIds:
            user.walletIds
        });

        return;
      }


      /* =========================
         MY WALLETS
      ========================= */

      if (
        req.method === "GET" &&
        req.url === "/api/wallets"
      ) {

        const user =
          getUserByToken(req);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Необходимо войти в аккаунт."
            },
            401
          );

          return;
        }

        const wallets =
          getUserWallets(user);

        sendJSON(res, {
          success: true,

          wallets:
            wallets.map(wallet => ({
              id: wallet.id,
              name: wallet.name,
              address: wallet.address,
              balance: wallet.balance,
              createdAt:
                wallet.createdAt
            }))
        });

        return;
      }


      /* =========================
         SELECT WALLET
      ========================= */

      if (
        req.method === "POST" &&
        req.url === "/api/wallet/select"
      ) {

        const user =
          getUserByToken(req);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Необходимо войти в аккаунт."
            },
            401
          );

          return;
        }

        const body =
          await getBody(req);

        const wallet =
          getWallet(body.id);

        if (!wallet) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Кошелёк не найден."
            },
            404
          );

          return;
        }

        if (
          wallet.ownerId !==
          user.id
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Этот кошелёк не принадлежит вашему аккаунту."
            },
            403
          );

          return;
        }

        user.walletId =
          wallet.id;

        saveDatabase();

        sendJSON(res, {
          success: true,

          wallet: {
            id: wallet.id,
            name: wallet.name,
            address: wallet.address,
            balance: wallet.balance,
            transactions:
              wallet.transactions
          }
        });

        return;
      }


      /* =========================
         GET WALLET
      ========================= */

      if (
        req.method === "GET" &&
        req.url.startsWith(
          "/api/wallet/"
        )
      ) {

        const user =
          getUserByToken(req);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Необходимо войти в аккаунт."
            },
            401
          );

          return;
        }

        const id =
          decodeURIComponent(
            req.url.replace(
              "/api/wallet/",
              ""
            )
          );

        const wallet =
          getWallet(id);

        if (!wallet) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "SLX-ID не найден."
            },
            404
          );

          return;
        }

        if (
          wallet.ownerId !==
          user.id
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Этот кошелёк вам не принадлежит."
            },
            403
          );

          return;
        }

        sendJSON(res, {
          success: true,

          wallet: {
            id: wallet.id,
            name: wallet.name,
            address: wallet.address,
            balance: wallet.balance,
            transactions:
              wallet.transactions
          }
        });

        return;
      }


      /* =========================
         FIND WALLET
      ========================= */

      if (
        req.method === "GET" &&
        req.url.startsWith(
          "/api/find/"
        )
      ) {

        const id =
          decodeURIComponent(
            req.url.replace(
              "/api/find/",
              ""
            )
          );

        const wallet =
          getWallet(id);

        if (!wallet) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Получатель не найден."
            },
            404
          );

          return;
        }

        sendJSON(res, {
          success: true,

          recipient: {
            id: wallet.id,
            address: wallet.address
          }
        });

        return;
      }


      /* =========================
         FAUCET
      ========================= */

      if (
        req.method === "POST" &&
        req.url === "/api/faucet"
      ) {

        const user =
          getUserByToken(req);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Необходимо войти в аккаунт."
            },
            401
          );

          return;
        }

        const body =
          await getBody(req);

        const wallet =
          getWallet(body.id);

        if (!wallet) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Кошелёк не найден."
            },
            404
          );

          return;
        }

        if (
          wallet.ownerId !==
          user.id
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Этот кошелёк вам не принадлежит."
            },
            403
          );

          return;
        }

        const amount = 100;

        wallet.balance += amount;

        const transaction = {
          id:
            "TX-" +
            Date.now(),

          type:
            "faucet",

          amount,

          from:
            "FAUCET",

          to:
            wallet.id,

          time:
            new Date().toISOString()
        };

        addTransaction(
          wallet,
          transaction
        );

        saveDatabase();

        sendJSON(res, {
          success: true,
          transaction,
          balance:
            wallet.balance
        });

        return;
      }


      /* =========================
         SEND SLX
      ========================= */

      if (
        req.method === "POST" &&
        req.url === "/api/send"
      ) {

        const user =
          getUserByToken(req);

        if (!user) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Необходимо войти в аккаунт."
            },
            401
          );

          return;
        }

        const body =
          await getBody(req);

        const sender =
          getWallet(body.sender);

        const recipient =
          getWallet(body.recipient);

        const amount =
          Number(body.amount);

        if (!sender) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Ваш кошелёк не найден."
            },
            404
          );

          return;
        }

        if (
          sender.ownerId !==
          user.id
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Этот кошелёк не принадлежит вашему аккаунту."
            },
            403
          );

          return;
        }

        if (!recipient) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Получатель не найден."
            },
            404
          );

          return;
        }

        if (
          sender.id ===
          recipient.id
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Нельзя отправить самому себе."
            },
            400
          );

          return;
        }

        if (
          !Number.isFinite(amount) ||
          amount <= 0
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Неверная сумма."
            },
            400
          );

          return;
        }

        if (
          amount >
          sender.balance
        ) {
          sendJSON(
            res,
            {
              success: false,
              error:
                "Недостаточно SLX."
            },
            400
          );

          return;
        }

        sender.balance -= amount;
        recipient.balance += amount;

        const transactionId =
          "TX-" +
          Date.now() +
          "-" +
          crypto
            .randomBytes(3)
            .toString("hex");

        const time =
          new Date().toISOString();

        addTransaction(
          sender,
          {
            id:
              transactionId,

            type:
              "send",

            amount,

            from:
              sender.id,

            to:
              recipient.id,

            time
          }
        );

        addTransaction(
          recipient,
          {
            id:
              transactionId,

            type:
              "receive",

            amount,

            from:
              sender.id,

            to:
              recipient.id,

            time
          }
        );

        saveDatabase();

        sendJSON(res, {
          success: true,

          transaction: {
            id:
              transactionId,

            amount,

            from:
              sender.id,

            to:
              recipient.id,

            time
          },

          senderBalance:
            sender.balance,

          recipientBalance:
            recipient.balance
        });

        return;
      }


      /* =========================
         NETWORK STATUS
      ========================= */

      if (
        req.method === "GET" &&
        req.url === "/api/status"
      ) {

        const wallets =
          Object.values(
            database.wallets
          );

        sendJSON(res, {
          success: true,

          network:
            "SLX Testnet",

          version:
            "1.3",

          status:
            "online",

          accounts:
            Object.keys(
              database.users
            ).length,

          wallets:
            wallets.length
        });

        return;
      }


      /* =========================
         NOT FOUND
      ========================= */

      sendJSON(
        res,
        {
          success: false,
          error: "Not found"
        },
        404
      );

    } catch (error) {

      console.error(
        "SERVER ERROR:",
        error
      );

      sendJSON(
        res,
        {
          success: false,
          error:
            "Внутренняя ошибка сервера."
        },
        500
      );
    }
  }
);


/* =========================
   START
========================= */

loadDatabase();

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "=============================="
    );

    console.log(
      "SLX Network v1.3"
    );

    console.log(
      "Persistent Accounts + Multi-Wallet"
    );

    console.log(
      "Server is LIVE"
    );

    console.log(
      "=============================="
    );
  }
);