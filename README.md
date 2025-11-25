To Run the Project

Start the Server

Make sure Node.js is installed.

Run
node server.js

then enter http://localhost:5000/ into your browser 


How to Use the System

Step 1 - Register
•	Open the Register page
•	Enter email + password
•	Wait for the "Keys generated successfully" message
•	Your private key is now stored in your browser

Step 2 - Login
•	Use your email and password (that you registered)

Step 3 - Send Email
•	Go to Compose
•	Enter recipient’s email
•	Type message
•	Press Send
•	You will see "Message sent"

Step 4 - Check Inbox
•	Open Inbox
•	If private key exists: messages decrypt normally
•	If signature matches: message marked safe
•	If signature fails: message shows Signature Invalid Warning
•	If private key missing: shows [Cannot Decrypt]
