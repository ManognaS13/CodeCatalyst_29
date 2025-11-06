EduPlanner - Minimal Backend

This is a minimal Node.js + SQLite backend for the EduPlanner prototype. It provides:

- User registration and login (JWT)
- Endpoints to save/read study progress
- Weekly test retrieval and submission

Quick start (Windows PowerShell):

1. Open a terminal in the `server` folder

2. Install dependencies:

```powershell
npm install
```

3. Run the server:

```powershell
npm start
```

The server will run on http://localhost:4000 by default.

Notes & security:
- This is a prototype. The JWT secret is stored in plain text in `server.js` — replace with environment variable in production.
- Passwords are hashed with bcryptjs.
- The DB file is created at `server/eduplanner.db`.
- Admin resource management in `admin.html` currently uses localStorage; you can extend the server to include CRUD endpoints for resources and update admin code to call those endpoints.

Next steps (suggestions):
- Add HTTPS and secure cookie-based sessions
- Use migrations for DB schema
- Add proper validation and rate limiting
- Move resource management to server-side storage
