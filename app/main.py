from fastapi import WebSocket, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import jwt
from jwt.exceptions import InvalidTokenError
from app.routes.user_routes import router as user_router
from dotenv import load_dotenv
import os
from typing import Annotated

app = FastAPI(
    title="Simple chat app",
    summary="This is a simple real-time chat application built with FastAPI. It supports WebSocket connections, allowing multiple clients to send and receive messages in real time. Users are authenticated using JWT tokens, and messages are broadcasted to all connected clients. The app also includes CORS middleware to allow cross-origin requests and integrates user-related routes via a FastAPI router.",
)
app.include_router(user_router)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


load_dotenv()


REFRESH_SECRET = os.getenv("REFRESH_SECRET")
SECRET = os.getenv("SECRET")
ALGORITHM = os.getenv("ALGORITHM")


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Annotated[str, Query()]):
    try:
        payload = jwt.decode(token, SECRET, algorithms=ALGORITHM)
        username: str = payload.get("sub")
    except InvalidTokenError:
        await websocket.close()
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"{username}: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
