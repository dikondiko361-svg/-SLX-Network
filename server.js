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
  let address;

  do {
    address = makeAddress();
  } while (wallets.has(address));

  const wallet = {
    address,
    balance: 1000,
    transactions: []
  };

  wallets.set(address, wallet);

  return wallet;
}

function getWallet(address) {
  return wallets.get(String(address || ""));
}

function addTransaction(wallet, transaction) {
  wallet.transactions.unshift(transaction);

  if (wallet.transactions.length > 50) {
    wallet.transactions = wallet.transactions.slice(0, 50);
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

function sendHTML(res) {
  const file = path.join(__dirname, "index.html");

  fs.readFile(file, "utf8", (error, html) => {
    if (error) {
      res.writeHead(500, {
        "Content-Type": "text/plain; charset=utf-8"
      });

      res.end("index.html not found");
      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8"
    });

    res.end(html);
  });
}

const server = http.createServer(async (req, res) => {

  if (req.method === "GET" && req.url === "/") {
    sendHTML(res);
    return;
  }

  if (req.method === "GET" && req.url === "/api/status") {
    sendJSON(res, {
      success: true,
      network: "SLX Testnet",
      version: "0.9",
      status: "online",
      wallets: Array.from(wallets.values()).map(wallet => ({
        address: wallet.address,
        balance: wallet.balance
      }))
    });

    return;
  }

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

  if (req.method === "POST" && req.url === "/api/send") {
    try {
      const body = await getBody(req);

      const senderAddress = String(body.sender || "");
      const recipientAddress = String(body.recipient || "");
      const amount = Number(body.amount);

      const sender = getWallet(senderAddress);
      const recipient = getWallet(recipientAddress);

      if (!sender) {
        sendJSON(res, {
          success: false,
          error: "Кошелёк отправителя не найден"
        }, 404);
        return;
      }

      if (!recipient) {
        sendJSON(res, {
          success: false,
          error: "Кошелёк получателя не найден"
        }, 404);
        return;
      }

      if (sender.address === recipient.address) {
        sendJSON(res, {
          success: false,
          error: "Нельзя отправить самому себе"
        }, 400);
        return;
      }

      if (!Number.isFinite(amount) || amount <= 0) {
        sendJSON(res, {
          success: false,
          error: "Неверная сумма"
        }, 400);
        return;
      }

      if (amount > sender.balance) {
        sendJSON(res, {
          success: false,
          error: "Недостаточно SLX"
        }, 400);
        return;
      }

      sender.balance -= amount;
      recipient.balance += amount;

      const transactionId = "TX-" + Date.now();

      addTransaction(sender, {
        id: transactionId,
        type: "send",
        amount,
        from: sender.address,
        to: recipient.address,
        time: new Date().toISOString()
      });

      addTransaction(recipient, {
        id: transactionId,
        type: "receive",
        amount,
        from: sender.address,
        to: recipient.address,
        time: new Date().toISOString()
      });

      sendJSON(res, {
        success: true,
        transaction: {
          id: transactionId,
          amount,
          from: sender.address,
          to: recipient.address
        },
        senderBalance: sender.balance,
        recipientBalance: recipient.balance
      });

    } catch {
      sendJSON(res, {
        success: false,
        error: "Ошибка запроса"
      }, 400);
    }

    return;
  }

  if (req.method === "GET" && req.url.startsWith("/api/wallet/")) {
    const address = decodeURIComponent(
      req.url.replace("/api/wallet/", "")
    );

    const wallet = getWallet(address);

    if (!wallet) {
      sendJSON(res, {
        success: false,
        error: "Кошелёк не найден"
      }, 404);

      return;
    }

    sendJSON(res, {
      success: true,
      wallet
    });

    return;
  }

  sendJSON(res, {
    success: false,
    error: "Not found"
  }, 404);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("================================");
  console.log("SLX Network v0.9");
  console.log("Testnet server is LIVE");
  console.log("================================");
});