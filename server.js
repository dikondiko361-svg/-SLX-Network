const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

const wallets = new Map();
const users = new Map();
const sessions = new Map();

/* =========================
   HELPERS
========================= */

function makeId() {
  return "SLX" + crypto.randomBytes(5).toString("hex").toUpperCase();
}

function makeAddress() {
  return "SLX-" + crypto.randomBytes(8).toString("hex").toUpperCase();
}

function makeSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function createWallet() {
  let id;

  do {
    id = makeId();
  } while (wallets.has(id));

  const wallet = {
    id,
    address: makeAddress(),
    balance: 1000,
    transactions: [],
    createdAt: new Date().toISOString()
  };

  wallets.set(id, wallet);

  return wallet;
}

function getWallet(id) {
  return wallets.get(
    String(id || "").trim().toUpperCase()
  );
}

function addTransaction(wallet, transaction) {
  wallet.transactions.unshift(transaction);

  if (wallet.transactions.length > 50) {
    wallet.transactions =
      wallet.transactions.slice(0, 50);
  }
}

function sendJSON(res, data, status = 200) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  });

  res.end(JSON.stringify(data));
}

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

function getToken(req) {
  const header = req.headers.authorization || "";

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

  return users.get(userId) || null;
}

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

const server = http.createServer(async (req, res) => {

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

    try {
      const body = await getBody(req);

      const username =
        String(body.username || "")
          .trim();

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

      if (!/^[a-zA-Z0-9_]+$/.test(username)) {
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

      const usernameKey =
        username.toLowerCase();

      for (const user of users.values()) {
        if (
          user.username.toLowerCase() ===
          usernameKey
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
      }

      const wallet =
        createWallet();

      const userId =
        "USR-" +
        crypto
          .randomBytes(8)
          .toString("hex")
          .toUpperCase();

      const user = {
        id: userId,
        username,
        passwordHash:
          hashPassword(password),
        walletId: wallet.id,
        createdAt:
          new Date().toISOString()
      };

      users.set(
        userId,
        user
      );

      const token =
        makeSessionToken();

      sessions.set(
        token,
        userId
      );

      sendJSON(res, {
        success: true,
        token,

        user: {
          id: user.id,
          username: user.username,
          walletId: user.walletId
        },

        wallet: {
          id: wallet.id,
          address: wallet.address,
          balance: wallet.balance
        }
      });

    } catch {
      sendJSON(
        res,
        {
          success: false,
          error:
            "Ошибка регистрации."
        },
        400
      );
    }

    return;
  }


  /* =========================
     LOGIN
  ========================= */

  if (
    req.method === "POST" &&
    req.url === "/api/auth/login"
  ) {

    try {
      const body =
        await getBody(req);

      const username =
        String(body.username || "")
          .trim();

      const password =
        String(body.password || "");

      const passwordHash =
        hashPassword(password);

      let foundUser = null;

      for (const user of users.values()) {
        if (
          user.username.toLowerCase() ===
          username.toLowerCase()
        ) {
          foundUser = user;
          break;
        }
      }

      if (
        !foundUser ||
        foundUser.passwordHash !==
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

      const token =
        makeSessionToken();

      sessions.set(
        token,
        foundUser.id
      );

      const wallet =
        getWallet(
          foundUser.walletId
        );

      sendJSON(res, {
        success: true,
        token,

        user: {
          id: foundUser.id,
          username:
            foundUser.username,
          walletId:
            foundUser.walletId
        },

        wallet: wallet
          ? {
              id: wallet.id,
              address:
                wallet.address,
              balance:
                wallet.balance
            }
          : null
      });

    } catch {
      sendJSON(
        res,
        {
          success: false,
          error:
            "Ошибка входа."
        },
        400
      );
    }

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

    const wallet =
      getWallet(
        user.walletId
      );

    sendJSON(res, {
      success: true,

      user: {
        id: user.id,
        username:
          user.username,
        walletId:
          user.walletId
      },

      wallet: wallet
        ? {
            id: wallet.id,
            address:
              wallet.address,
            balance:
              wallet.balance
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
     NETWORK STATUS
  ========================= */

  if (
    req.method === "GET" &&
    req.url === "/api/status"
  ) {

    sendJSON(res, {
      success: true,
      network: "SLX Testnet",
      version: "1.1",
      status: "online",

      wallets:
        Array.from(
          wallets.values()
        ).map(wallet => ({
          id: wallet.id,
          address:
            wallet.address,
          balance:
            wallet.balance
        }))
    });

    return;
  }


  /* =========================
     CREATE WALLET
  ========================= */

  if (
    req.method === "POST" &&
    req.url === "/api/wallet/create"
  ) {

    const wallet =
      createWallet();

    sendJSON(res, {
      success: true,

      wallet: {
        id: wallet.id,
        address:
          wallet.address,
        balance:
          wallet.balance,
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
            "SLX-ID не найден"
        },
        404
      );

      return;
    }

    sendJSON(res, {
      success: true,

      wallet: {
        id: wallet.id,
        address:
          wallet.address,
        balance:
          wallet.balance,
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
            "Получатель не найден"
        },
        404
      );

      return;
    }

    sendJSON(res, {
      success: true,

      recipient: {
        id: wallet.id,
        address:
          wallet.address
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

    try {

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
              "Кошелёк не найден"
          },
          404
        );

        return;
      }

      const amount = 100;

      wallet.balance += amount;

      const transaction = {
        id:
          "TX-" +
          Date.now(),

        type: "faucet",
        amount,

        from: "FAUCET",
        to: wallet.id,

        time:
          new Date().toISOString()
      };

      addTransaction(
        wallet,
        transaction
      );

      sendJSON(res, {
        success: true,
        transaction,
        balance:
          wallet.balance
      });

    } catch {

      sendJSON(
        res,
        {
          success: false,
          error:
            "Ошибка запроса"
        },
        400
      );
    }

    return;
  }


  /* =========================
     SEND SLX
  ========================= */

  if (
    req.method === "POST" &&
    req.url === "/api/send"
  ) {

    try {

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
              "Ваш кошелёк не найден"
          },
          404
        );

        return;
      }

      if (!recipient) {
        sendJSON(
          res,
          {
            success: false,
            error:
              "Получатель не найден"
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
              "Нельзя отправить самому себе"
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
              "Неверная сумма"
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
              "Недостаточно SLX"
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
          type: "send",
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
          type: "receive",
          amount,
          from:
            sender.id,
          to:
            recipient.id,
          time
        }
      );

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

    } catch {

      sendJSON(
        res,
        {
          success: false,
          error:
            "Ошибка перевода"
        },
        400
      );
    }

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
});


/* =========================
   START
========================= */

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "=============================="
    );

    console.log(
      "SLX Network v1.1"
    );

    console.log(
      "Account + Wallet Testnet"
    );

    console.log(
      "Server is LIVE"
    );

    console.log(
      "=============================="
    );
  }
);