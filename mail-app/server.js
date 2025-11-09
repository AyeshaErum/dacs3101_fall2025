const multer = require('multer');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const crypto = require('crypto');



const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

// AES settings (fixed key + IV so messages can be decrypted later)
const AES_KEY = Buffer.from("12345678901234567890123456789012"); // 32 bytes = 256-bit key
const AES_IV = Buffer.from("1234567890123456"); // 16 bytes = 128-bit IV

function encrypt(text) {
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

function decrypt(encryptedText) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, AES_IV);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Setup storage for attachments
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + file.originalname;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Load users
let users = [];
if (fs.existsSync("users.json")) {
  try {
    const data = fs.readFileSync("users.json", "utf-8");
    users = data.trim() ? JSON.parse(data) : [];
  } catch {
    console.error("⚠️ Error reading users.json, resetting file.");
    users = [];
  }
} else {
  users = [{ email: "user@example.com", password: "1234" }];
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

// Register new user
app.post("/register", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  const exists = users.find(u => u.email === email);
  if (exists)
    return res.status(400).json({ message: "User already exists" });

  const newUser = { email, password };
  users.push(newUser);
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));

  res.json({ message: "Account created successfully!" });
});

// Load mails
let mails = [];
if (fs.existsSync("mails.json")) {
  try {
    const data = fs.readFileSync("mails.json", "utf-8");
    mails = data.trim() ? JSON.parse(data) : [];
  } catch {
    console.error("⚠️ Error reading mails.json, resetting file.");
    mails = [];
  }
}

// Login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  res.json({ message: "Login successful!" });
});

// ✅ Inbox route (decrypt messages)
app.get("/inbox/:email", (req, res) => {
  const inbox = mails
    .filter(m => m.to === req.params.email)
    .map(m => ({
      ...m,
      body: (() => {
        try {
          return decrypt(m.body);
        } catch {
          return "[theres error in decrypting message]";
        }
      })()
    }));
  res.json(inbox);
});

// ✅ Send mail (encrypt body before saving)
app.post("/send", upload.single("attachment"), (req, res) => {
  const { from, to, subject, body } = req.body;

  if (!from || !to || !subject || !body)
    return res.status(400).json({ message: "Missing required fields!" });

  const recipientExists = users.find(u => u.email === to);
  if (!recipientExists)
    return res.status(400).json({ message: "Recipient does not exist!" });

  const newMail = {
    from,
    to,
    subject,
    body: encrypt(body),
    date: new Date().toISOString(),
    attachment: req.file ? req.file.filename : null
  };

  mails.push(newMail);
  fs.writeFileSync("mails.json", JSON.stringify(mails, null, 2));

  res.json({ message: "Mail sent successfully!" });
});

app.listen(5000, () => console.log("✅ Server running on http://localhost:5000"));
