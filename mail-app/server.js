// server.js
// import express from "express";
// import cors from "cors";
// import bodyParser from "body-parser";
// import fs from "fs";

let express = require('express')
let cors = require('cors')
let bodyParser = require('body-parser')
let fs = require('fs')


const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

let users = [{ email: "user@example.com", password: "1234" }];

// Load saved mails or start empty
let mails = [];

if (fs.existsSync("mails.json")) {
  try {
    const data = fs.readFileSync("mails.json", "utf-8");
    mails = data.trim() ? JSON.parse(data) : [];
  } catch (err) {
    console.error("Error reading mails.json, resetting file.");
    mails = [];
  }
}


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

// Send mail route
app.post("/send", (req, res) => {
  const { from, to, subject, body } = req.body;
  const newMail = { from, to, subject, body, date: new Date().toISOString() };
  mails.push(newMail);
  fs.writeFileSync("mails.json", JSON.stringify(mails, null, 2));
  res.json({ message: "Mail sent successfully!" });
});

app.listen(5000, () => console.log("✅ Server running on http://localhost:5000"));
