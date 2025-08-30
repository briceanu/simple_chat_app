# Simple Chat App

A **FastAPI** based chat application with WebSocket support, JWT authentication, and token management including login, logout, refresh tokens, and token blacklisting.

---

## Features

- **Real-time chat** using WebSockets.
- **JWT authentication** with access and refresh tokens.
- **Token management**:
  - Login
  - Logout
  - Refresh access token
  - Token blacklisting for security
- **CORS support** for frontend integration.
- Modular **FastAPI router structure** (`user_routes`).

---

## Requirements

- Python 3.10+
- FastAPI
- `pyjwt`
- `python-dotenv`
- `uvicorn`
- Any database for user management (if implemented in `user_routes`)

Install dependencies:

```bash
pip install fastapi uvicorn python-dotenv pyjwt
```
