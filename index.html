const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

const wallets = new Map();

function makeAddress() {
  return "SLX-" + crypto.randomBytes(8).toString("hex").toUpperCase();
}

function createWallet() {
  const address = makeAddress();

  const wallet = {
    address,
    balance: 1000,
    transactions: []
  };

  wallets.set(address, wallet);
  return wallet;
}

function getWallet(address) {
  return wallets.get(String(address || "").trim());
}

function addTransaction(wallet, transaction) {
  wallet.transactions.unshift(transaction);
  wallet.transactions = wallet.transactions.slice(0, 50);
}

function sendJSON(res, data, status = 200) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*"
  });

  res.end(JSON.stringify(data));
}

function sendHTML(res) {
  fs.readFile(path.join(__dirname, "index.html"), "utf8", (err, html) => {
    if (err) {
      sendJSON(
        res,
        {
          success: false,
          error: "index.html not found"
        },
        500
      );
      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8"
    });

    res.end(html);
  });
}

function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (body.length > 100000) {
        req.destroy();
      }
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

const server = http.createServer(async (req, res) => {

  // Главная страница
  if (req.method === "GET" && req.url === "/") {
    sendHTML(res);
    return;
  }

  // Создание нового кошелька
  if (req.method === "POST" && req.url === "/api/wallet/create") {
    const wallet = createWallet();

    sendJSON(res, {
      success: true,
      wallet: {
        address: wallet.address,
        balance: wallet.balance,
        transactions: wallet.transactions
      }
    });

    return;
  }

  // Получение информации о кошельке
  if (req.method === "GET" && req.url.startsWith("/api/status")) {
    const url = new URL(
      req.url,
      `http://${req.headers.host || "localhost"}`
    );

    const address = url.searchParams.get("address");
    const wallet = getWallet(address);

    if (!wallet) {
      sendJSON(
        res,
        {
          success: false,
          error: "Wallet not found"
        },
        404
      );

      return;
    }

    sendJSON(res, {
      success: true,
      network: "SLX Testnet",
      version: "0.8",
      status: "online",
      wallet: wallet.address,
      balance: wallet.balance,
      transactions: wallet.transactions
    });

    return;
  }

  // Faucet +100 SLX
  if (req.method === "POST" && req.url === "/api/faucet") {
    try {
      const body = await getBody(req);
      const wallet = getWallet(body.address);

      if (!wallet) {
        sendJSON(
          res,
          {
            success: false,
            error: "Wallet not found"
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
          Date.now() +
          "-" +
          crypto.randomBytes(3).toString("hex"),

        type: "faucet",
        amount,
        from: "FAUCET",
        to: wallet.address,
        time: new Date().toISOString()
      };

      addTransaction(wallet, transaction);

      sendJSON(res, {
        success: true,
        transaction,
        balance: wallet.balance
      });

    } catch {
      sendJSON(
        res,
        {
          success: false,
          error: "Invalid request"
        },
        400
      );
    }

    return;
  }

  // Перевод SLX
  if (req.method === "POST" && req.url === "/api/send") {
    try {
      const body = await getBody(req);

      const sender = getWallet(body.sender);
      const recipient = getWallet(body.recipient);
      const amount = Number(body.amount);

      if (!sender) {
        sendJSON(
          res,
          {
            success: false,
            error: "Sender wallet not found"
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
            error: "Recipient wallet not found"
          },
          404
        );

        return;
      }

      if (sender.address === recipient.address) {
        sendJSON(
          res,
          {
            success: false,
            error: "Cannot send to the same wallet"
          },
          400
        );

        return;
      }

      if (!Number.isFinite(amount) || amount <= 0) {
        sendJSON(
          res,
          {
            success: false,
            error: "Invalid amount"
          },
          400
        );

        return;
      }

      if (amount > sender.balance) {
        sendJSON(
          res,
          {
            success: false,
            error: "Insufficient SLX balance"
          },
          400
        );

        return;
      }

      // Списываем у отправителя
      sender.balance -= amount;

      // Добавляем получателю
      recipient.balance += amount;

      const transaction = {
        id:
          "TX-" +
          Date.now() +
          "-" +
          crypto.randomBytes(3).toString("hex"),

        type: "send",
        amount,
        from: sender.address,
        to: recipient.address,
        time: new Date().toISOString()
      };

      addTransaction(sender, transaction);

      addTransaction(recipient, {
        ...transaction,
        type: "receive"
      });

      sendJSON(res, {
        success: true,
        transaction,
        senderBalance: sender.balance,
        recipientBalance: recipient.balance
      });

    } catch {
      sendJSON(
        res,
        {
          success: false,
          error: "Invalid request"
        },
        400
      );
    }

    return;
  }

  // Неизвестный адрес
  sendJSON(
    res,
    {
      success: false,
      error: "Not found"
    },
    404
  );
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`SLX Network v0.8 running on port ${PORT}`);
});