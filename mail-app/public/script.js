let currentUser = localStorage.getItem("userEmail") || null;
localStorage.removeItem("userEmail");

window.onload = () => {
  if (currentUser) {
    document.getElementById("user-email").textContent = currentUser;
    document.getElementById("login-screen").classList.add("hidden");
    document.getElementById("mail-screen").classList.remove("hidden");
    loadInbox();
  } else {
    document.getElementById("login-screen").classList.remove("hidden");
    document.getElementById("mail-screen").classList.add("hidden");
  }
};


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
  localStorage.setItem("userEmail", email); // Save user session
  document.getElementById("user-email").textContent = email;
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("mail-screen").classList.remove("hidden");
  loadInbox();
}
else {
    document.getElementById("login-msg").textContent = "Invalid credentials.";
  }
}

/* function logout() {
  // Clear the stored user session
  localStorage.removeItem("userEmail");
  currentUser = null;

  // Clear any input fields from previous login
  document.getElementById("email").value = "";
  document.getElementById("password").value = "";

  // Hide mail interface and show login screen
  document.getElementById("mail-screen").classList.add("hidden");
  document.getElementById("login-screen").classList.remove("hidden");

  // Optional: Clear inbox and compose messages
  document.getElementById("inbox").innerHTML = "";
  document.getElementById("send-msg").textContent = "";
  document.getElementById("login-msg").textContent = "";
}
*/

function logout() {
  localStorage.removeItem("userEmail");
  location.reload();
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
  div.classList.add("mail-item");
  div.innerHTML = `
    <b>From:</b> ${mail.from} <br>
    <b>Subject:</b> ${mail.subject} <br>
    <small>${new Date(mail.date).toLocaleString()}</small>
    <p>${mail.body}</p>
    ${mail.attachment ? `<a href="/uploads/${mail.attachment}" target="_blank">Download Attachment</a>` : ''}
    <hr>
  `;
  inboxDiv.appendChild(div);
});



}

async function sendMail() {
  const to = document.getElementById("to").value;
  const subject = document.getElementById("subject").value;
  const body = document.getElementById("body").value;
  const fileInput = document.getElementById("attachment");
  const formData = new FormData();

  formData.append("from", currentUser);
  formData.append("to", to);
  formData.append("subject", subject);
  formData.append("body", body);

  if (fileInput.files.length > 0) {
    formData.append("attachment", fileInput.files[0]);
  }

  const res = await fetch("/send", {
    method: "POST",
    body: formData
  });

  if (res.ok) {
    document.getElementById("send-msg").textContent = "Email sent successfully!";
    document.getElementById("to").value = "";
    document.getElementById("subject").value = "";
    document.getElementById("body").value = "";
    fileInput.value = ""; // clear file input
  } else {
    document.getElementById("send-msg").textContent = "Failed to send.";
  }
}
