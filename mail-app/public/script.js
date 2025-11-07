let currentUser = null;

function showTab(tab) {
  document.getElementById("inbox-tab").classList.add("hidden");
  document.getElementById("compose-tab").classList.add("hidden");
  document.getElementById(`${tab}-tab`).classList.remove("hidden");
  if (tab === "inbox") loadInbox();
}

async function login() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const res = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (res.ok) {
    currentUser = email;
    document.getElementById("user-email").textContent = email;
    document.getElementById("login-screen").classList.add("hidden");
    document.getElementById("mail-screen").classList.remove("hidden");
    loadInbox();
  } else {
    document.getElementById("login-msg").textContent = "Invalid credentials.";
  }
}

function logout() {
  currentUser = null;
  document.getElementById("login-screen").classList.remove("hidden");
  document.getElementById("mail-screen").classList.add("hidden");
}

async function loadInbox() {
  const res = await fetch(`/inbox/${currentUser}`);
  const mails = await res.json();
  const inboxDiv = document.getElementById("inbox");
  inboxDiv.innerHTML = "";

  if (mails.length === 0) {
    inboxDiv.innerHTML = "<p>No emails yet.</p>";
    return;
  }

  mails.forEach(mail => {
    const div = document.createElement("div");
    div.innerHTML = `<b>From:</b> ${mail.from}<br>
                     <b>Subject:</b> ${mail.subject}<br>
                     <p>${mail.body}</p>`;
    inboxDiv.appendChild(div);
  });
}

async function sendMail() {
  const to = document.getElementById("to").value;
  const subject = document.getElementById("subject").value;
  const body = document.getElementById("body").value;

  const res = await fetch("/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ from: currentUser, to, subject, body }),
  });

  if (res.ok) {
    document.getElementById("send-msg").textContent = "Email sent successfully!";
    document.getElementById("to").value = "";
    document.getElementById("subject").value = "";
    document.getElementById("body").value = "";
  } else {
    document.getElementById("send-msg").textContent = "Failed to send.";
  }
}
