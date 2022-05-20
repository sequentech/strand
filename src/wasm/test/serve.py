from http.server import HTTPServer, SimpleHTTPRequestHandler

class CrossOriginIsolation(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        
        return super(CrossOriginIsolation, self).end_headers()


httpd = HTTPServer(('localhost', 8080), CrossOriginIsolation)
httpd.serve_forever()