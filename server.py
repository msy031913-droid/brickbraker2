#!/usr/bin/env python3
"""
다각형 순회 게임 서버
- 회원가입 / 로그인
- 진행도 저장/불러오기
- 랭킹 (돈, 회전수)
"""

import json
import os
import sqlite3
import hashlib
import hmac
import secrets
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

# ========== 설정 ==========
PORT = 8080
HOST = "0.0.0.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "game.db")
SECRET = secrets.token_hex(32)  # 서버 재시작 시 토큰 무효화
TOKEN_TTL = 60 * 60 * 24 * 7  # 7일

# ========== DB ==========
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS progress (
            user_id INTEGER PRIMARY KEY,
            money REAL DEFAULT 0,
            total_laps INTEGER DEFAULT 0,
            owned_polys TEXT DEFAULT '["tri"]',
            owned_chars TEXT DEFAULT '["turtle"]',
            owned_mults TEXT DEFAULT '[]',
            current_poly TEXT DEFAULT 'tri',
            current_char TEXT DEFAULT 'turtle',
            updated_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

# ========== 비밀번호 ==========
def hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return h.hex(), salt

def verify_password(password: str, password_hash: str, salt: str) -> bool:
    h, _ = hash_password(password, salt)
    return hmac.compare_digest(h, password_hash)

# ========== 토큰 ==========
def make_token(user_id: int, username: str) -> str:
    payload = {
        "uid": user_id,
        "u": username,
        "exp": int(time.time()) + TOKEN_TTL,
    }
    body = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + sig

def verify_token(token: str):
    try:
        body, sig = token.rsplit(".", 1)
        expected = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(body)
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# ========== HTTP 핸들러 ==========
class GameHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def _auth_user(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            return verify_token(token)
        return None

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            return self._send_json({"ok": True})

        if path == "/api/ranking":
            return self._handle_ranking()

        if path == "/api/me":
            return self._handle_me()

        # 정적 파일
        if path == "/" or path == "":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/register":
            return self._handle_register()
        if path == "/api/login":
            return self._handle_login()
        if path == "/api/save":
            return self._handle_save()

        self._send_json({"error": "Not found"}, 404)

    # ----- API 구현 -----
    def _handle_register(self):
        data = self._read_json()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        if len(username) < 3 or len(username) > 20:
            return self._send_json({"error": "아이디는 3~20자여야 합니다"}, 400)
        if not username.isalnum() and "_" not in username:
            # 영문/숫자/밑줄만
            if not all(c.isalnum() or c == "_" for c in username):
                return self._send_json({"error": "아이디는 영문, 숫자, _ 만 가능합니다"}, 400)
        if len(password) < 4:
            return self._send_json({"error": "비밀번호는 4자 이상이어야 합니다"}, 400)

        pw_hash, salt = hash_password(password)
        now = datetime.now(timezone.utc).isoformat()

        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                (username, pw_hash, salt, now),
            )
            user_id = cur.lastrowid
            cur.execute(
                "INSERT INTO progress (user_id, updated_at) VALUES (?, ?)",
                (user_id, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return self._send_json({"error": "이미 사용 중인 아이디입니다"}, 409)
        conn.close()

        token = make_token(user_id, username)
        return self._send_json({
            "ok": True,
            "token": token,
            "username": username,
            "user_id": user_id,
        })

    def _handle_login(self):
        data = self._read_json()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        conn.close()

        if not row or not verify_password(password, row["password_hash"], row["salt"]):
            return self._send_json({"error": "아이디 또는 비밀번호가 틀렸습니다"}, 401)

        token = make_token(row["id"], row["username"])
        return self._send_json({
            "ok": True,
            "token": token,
            "username": row["username"],
            "user_id": row["id"],
        })

    def _handle_me(self):
        payload = self._auth_user()
        if not payload:
            return self._send_json({"error": "로그인이 필요합니다"}, 401)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM progress WHERE user_id = ?", (payload["uid"],))
        row = cur.fetchone()
        conn.close()

        if not row:
            return self._send_json({"error": "진행도를 찾을 수 없습니다"}, 404)

        return self._send_json({
            "ok": True,
            "username": payload["u"],
            "progress": {
                "money": row["money"],
                "total_laps": row["total_laps"],
                "owned_polys": json.loads(row["owned_polys"]),
                "owned_chars": json.loads(row["owned_chars"]),
                "owned_mults": json.loads(row["owned_mults"]),
                "current_poly": row["current_poly"],
                "current_char": row["current_char"],
            },
        })

    def _handle_save(self):
        payload = self._auth_user()
        if not payload:
            return self._send_json({"error": "로그인이 필요합니다"}, 401)

        data = self._read_json()
        now = datetime.now(timezone.utc).isoformat()

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE progress SET
                money = ?,
                total_laps = ?,
                owned_polys = ?,
                owned_chars = ?,
                owned_mults = ?,
                current_poly = ?,
                current_char = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (
                float(data.get("money", 0)),
                int(data.get("total_laps", 0)),
                json.dumps(data.get("owned_polys", ["tri"])),
                json.dumps(data.get("owned_chars", ["turtle"])),
                json.dumps(data.get("owned_mults", [])),
                data.get("current_poly", "tri"),
                data.get("current_char", "turtle"),
                now,
                payload["uid"],
            ),
        )
        conn.commit()
        conn.close()
        return self._send_json({"ok": True})

    def _handle_ranking(self):
        qs = parse_qs(urlparse(self.path).query)
        sort = (qs.get("sort") or ["money"])[0]
        if sort not in ("money", "laps"):
            sort = "money"

        order_col = "p.money" if sort == "money" else "p.total_laps"

        conn = get_db()
        cur = conn.cursor()
        cur.execute(f"""
            SELECT u.username, p.money, p.total_laps, p.updated_at
            FROM progress p
            JOIN users u ON u.id = p.user_id
            ORDER BY {order_col} DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
        conn.close()

        ranking = [
            {
                "rank": i + 1,
                "username": r["username"],
                "money": r["money"],
                "total_laps": r["total_laps"],
                "updated_at": r["updated_at"],
            }
            for i, r in enumerate(rows)
        ]
        return self._send_json({"ok": True, "sort": sort, "ranking": ranking})


def main():
    init_db()
    server = HTTPServer((HOST, PORT), GameHandler)
    print(f"🚀 다각형 순회 서버 시작: http://localhost:{PORT}")
    print(f"   게임: http://localhost:{PORT}/")
    print(f"   랭킹: http://localhost:{PORT}/api/ranking")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n서버 종료")
        server.server_close()


if __name__ == "__main__":
    main()
