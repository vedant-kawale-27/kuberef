import http.server
import json
import re

class MockK8sHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Path for namespace: /api/v1/namespaces/<name>
        namespace_match = re.match(r'^/api/v1/namespaces/([^/]+)$', self.path)
        if namespace_match:
            ns = namespace_match.group(1)
            response = {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": ns
                }
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            return

        # Path for secret: /api/v1/namespaces/<ns>/secrets/<name>
        secret_match = re.match(r'^/api/v1/namespaces/([^/]+)/secrets/([^/]+)$', self.path)
        if secret_match:
            ns = secret_match.group(1)
            name = secret_match.group(2)
            
            # Secrets database
            secrets_database = {
                "db-secret": {
                    "password": "bW9jay1zZWNyZXQtcGFzc3dvcmQtcGxhY2Vob2xkZXI=" # "mock-secret-password-placeholder"
                },
                "registry-creds": {
                    ".dockerconfigjson": "eyJtb2NrIjoiY3JlZHMifQ==" # '{"mock":"creds"}' in base64
                },
                "api-keys": {
                    "API_KEY_1": "bW9jay1hcGkta2V5LTE=", # "mock-api-key-1"
                    "API_KEY_2": "bW9jay1hcGkta2V5LTI="  # "mock-api-key-2"
                },
                "ssl-certs": {
                    "tls.crt": "bW9jay1jZXJ0LWNydA==", # "mock-cert-crt"
                    "tls.key": "bW9jay1jZXJ0LWtleQ=="  # "mock-cert-key"
                },
                "controller-level-secret": {
                    "api-token": "bW9jay1jb250cm9sbGVyLXRva2Vu" # "mock-controller-token"
                }
            }
            
            if name in secrets_database:
                response = {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {
                        "name": name,
                        "namespace": ns
                    },
                    "data": secrets_database[name]
                }
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
            else:
                response = {
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": f"secrets \"{name}\" not found",
                    "reason": "NotFound",
                    "details": {
                        "name": name,
                        "kind": "secrets"
                    },
                    "code": 404
                }
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
            return

        # Path for configmap: /api/v1/namespaces/<ns>/configmaps/<name>
        configmap_match = re.match(r'^/api/v1/namespaces/([^/]+)/configmaps/([^/]+)$', self.path)
        if configmap_match:
            ns = configmap_match.group(1)
            name = configmap_match.group(2)
            
            # ConfigMaps database
            configmaps_database = {
                "valid-cm": {
                    "valid-key": "some-value"
                },
                "env-cm": {
                    "another-key": "another-value"
                }
            }
            
            if name in configmaps_database:
                response = {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": name,
                        "namespace": ns
                    },
                    "data": configmaps_database[name]
                }
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
            else:
                response = {
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "message": f"configmaps \"{name}\" not found",
                    "reason": "NotFound",
                    "details": {
                        "name": name,
                        "kind": "configmaps"
                    },
                    "code": 404
                }
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress logging to keep output clean
        pass

def run(port=8081):
    server_address = ('127.0.0.1', port)
    httpd = http.server.HTTPServer(server_address, MockK8sHandler)
    print(f"Mock Kubernetes API Server running on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
