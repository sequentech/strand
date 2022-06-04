from http.server import HTTPServer, SimpleHTTPRequestHandler

class CrossOriginIsolation(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        
        return super(CrossOriginIsolation, self).end_headers()

handler = CrossOriginIsolation
handler.extensions_map.update({
    '.wasm': 'application/wasm',
    # '': 'application/octet-stream', # Default
})
httpd = HTTPServer(('localhost', 8080), handler)
httpd.serve_forever()
