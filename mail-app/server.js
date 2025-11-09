const multer = require('multer');
const path = require('path');


let express = require('express')
let cors = require('cors')
let bodyParser = require('body-parser')
let fs = require('fs')





const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));




// Setup storage for attachments
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // folder to store files
  },
  filename: (req, file, cb) => {
    // Save file with unique timestamp to avoid name clashes
    const uniqueName = Date.now() + '-' + file.originalname;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));





// Load users or initialize default
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
  fs.writeFileSync("users.json", JSON.stringify([{ email: "user@example.com", password: "1234" }], null, 2));
  users = [{ email: "user@example.com", password: "1234" }];
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

// Load mails safely
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

// Inbox route — only return mails for this recipient
app.get("/inbox/:email", (req, res) => {
  const email = req.params.email;
  const inbox = mails.filter(m => m.to === email);
  res.json(inbox);
});

// Send mail route — attach 'from' and 'to'
app.post("/send", upload.single("attachment"), (req, res) => {
  const from = req.body.from;
  const to = req.body.to;
  const subject = req.body.subject;
  const body = req.body.body;

  if (!from || !to || !subject || !body)
    return res.status(400).json({ message: "Missing required fields" });

  // Check recipient exists
  const recipientExists = users.find(u => u.email === to);
  if (!recipientExists)
    return res.status(400).json({ message: "Recipient does not exist" });

  const newMail = {
    from,
    to,
    subject,
    body,
    date: new Date().toISOString(),
    attachment: req.file ? req.file.filename : null
  };

  mails.push(newMail);
  fs.writeFileSync("mails.json", JSON.stringify(mails, null, 2));

  res.json({ message: "Mail sent successfully!" });
});




// Login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  res.json({ message: "Login successful" });
});

// Inbox route
app.get("/inbox/:email", (req, res) => {
  const inbox = mails.filter(m => m.to === req.params.email);
  res.json(inbox);
});



app.post("/send", upload.single("attachment"), (req, res) => {
  const { from, to, subject, body } = req.body;

  const recipientExists = users.find(u => u.email === to);
  if (!recipientExists) return res.status(400).json({ message: "Recipient does not exist" });

  const newMail = {
    from,
    to,
    subject,
    body,
    date: new Date().toISOString(),
    attachment: req.file ? req.file.filename : null // store filename
  };

  mails.push(newMail);
  fs.writeFileSync("mails.json", JSON.stringify(mails, null, 2));

  res.json({ message: "Mail sent successfully!" });
});






app.listen(5000, () => console.log("✅ Server running on http://localhost:5000"));
