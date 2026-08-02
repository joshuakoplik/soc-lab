import http.server

STUB_NOTE = b"tool-svc stub -- milestone 8 replaces this with doc_search/ticket_lookup/customer_record/usage_calc"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(STUB_NOTE)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
