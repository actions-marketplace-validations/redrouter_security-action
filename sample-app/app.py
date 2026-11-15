"""Deliberately vulnerable local fixture. Do not deploy."""
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class App(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlsplit(self.path).query)
        if self.path.startswith("/lookup"):
            database = sqlite3.connect(":memory:")
            database.execute("CREATE TABLE notes (id INTEGER, body TEXT)")
            database.execute("INSERT INTO notes VALUES (1, 'seeded demo record')")
            rows = database.execute("SELECT body FROM notes WHERE id = " + query.get("id", ["1"])[0]).fetchall()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(repr(rows).encode())
        elif self.path.startswith("/download"):
            content = (Path(__file__).parent / "public" / query.get("file", ["readme.txt"])[0]).read_bytes()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), App).serve_forever()
