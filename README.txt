Secure chat (Double Ratchet) - web app with login

HOW TO RUN
1. Install Node.js (you already have it). No npm install is needed.
2. Open a terminal inside this folder (type cmd in the File Explorer address bar).
3. Run:  node server.js
4. Open http://localhost:3000 in your browser.
5. Create two accounts (for example alice and bob). Log in as alice in one tab
   and as bob in a second tab or a private window, then chat.
Stop the server with Ctrl+C.

IMPORTANT
- Your keys live only in the open browser tab. If you refresh or log out you get
  new keys, and old messages cannot be read again. Keep both tabs open while you demo.
- A user must have logged in since the server started before others can message them.
- Accounts are saved in users.json (passwords are hashed with scrypt, never stored as text).

FILES
server.js        accounts, login, signs certificates (trusted party), passes encrypted messages along

public/core.js   the cryptography (same steps as messenger.js)
public/app.js    the app page (dashboard, chat, profile, settings)
public/index.html  the login page
public/app.html    the app page after login
public/login.js    the login page code
public/style.css   the look
test.js          optional automatic test of the whole flow (node test.js)

PAGES (after logging in)
Dashboard  welcome, session statistics, recent activity
Chat       people list, encrypted conversation, network panel, attack demo
Profile    display name, about me, your key fingerprint
Settings   theme, show/hide network panel, change password
Log out    ends the session on the server and returns to the login screen