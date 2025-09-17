#!/usr/bin/env python3
"""
RGW Proxy Server for RESTler Fuzzing
Forwards requests to RGW endpoint with special handling for bucket policy operations.
"""

import sys
import json
import logging
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests
import argparse
import os

# Configure logging
log_dir = "rgw_proxy_logs"
os.makedirs(log_dir, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{log_dir}/rgw_proxy.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class RGWProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler for RGW proxy"""
    
    def __init__(self, *args, rgw_endpoint=None, **kwargs):
        self.rgw_endpoint = rgw_endpoint
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests"""
        self._handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests"""
        self._handle_request('POST')
    
    def do_PUT(self):
        """Handle PUT requests"""
        self._handle_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        self._handle_request('DELETE')
    
    def do_HEAD(self):
        """Handle HEAD requests"""
        self._handle_request('HEAD')
    
    def _handle_request(self, method):
        """Main request handling logic"""
        try:
            # Parse the request
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            query = parsed_path.query
            
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            
            # Log incoming request
            self._log_request(method, path, query, body)
            
            # Check if this is a bucket policy operation
            is_policy_request = self._is_policy_request(path, query)
            
            if is_policy_request:
                logger.info(f"Detected bucket policy request: {path}?{query}")
                self._handle_policy_request(method, path, query, body)
            else:
                logger.info(f"Forwarding regular request: {method} {path}")
                self._forward_request(method, path, query, body)
                
        except Exception as e:
            logger.error(f"Error handling request: {str(e)}")
            self._send_error_response(500, f"Proxy error: {str(e)}")
    
    def _is_policy_request(self, path, query):
        """Check if request is for bucket policy endpoint"""
        # Check if query contains 'policy' parameter
        if 'policy' in query.lower():
            return True
        
        # Additional check for policy-related paths
        if 'policy' in path.lower():
            return True
            
        return False
    
    def _handle_policy_request(self, method, path, query, body):
        """Handle bucket policy requests by generating policy body from scratch"""
        try:
            # Extract bucket name from path
            bucket_name = self._extract_bucket_name(path)
            if not bucket_name:
                logger.error(f"Could not extract bucket name from path: {path}")
                self._send_error_response(400, "Invalid bucket path for policy request")
                return
            
            # Generate policy body from scratch
            policy_body = self._generate_policy_body(bucket_name)
            
            # Log the generated policy payload
            self._log_policy_payload(method, path, query, policy_body)
            
            # Convert policy to JSON bytes
            policy_json = json.dumps(policy_body, separators=(',', ':'))
            new_body = policy_json.encode('utf-8')
            
            logger.info(f"Generated policy body for bucket '{bucket_name}': {policy_json}")
            
            # Forward the request with the generated body
            self._forward_request(method, path, query, new_body)
            
        except Exception as e:
            logger.error(f"Error handling policy request: {str(e)}")
            self._send_error_response(500, f"Policy request error: {str(e)}")
    
    def _forward_request(self, method, path, query, body):
        """Forward request to RGW endpoint"""
        try:
            # Construct target URL
            target_url = f"{self.rgw_endpoint}{path}"
            if query:
                target_url += f"?{query}"
            
            # Prepare headers (exclude problematic ones)
            headers = {}
            for key, value in self.headers.items():
                if key.lower() not in ['host', 'content-length']:
                    headers[key] = value
            
            logger.info(f"Forwarding to: {target_url}")
            
            # Make request to RGW
            response = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                timeout=30,
                verify=False  # Disable SSL verification for testing
            )
            
            # Log response
            self._log_response(response)
            
            # Send response back to client
            self.send_response(response.status_code)
            
            # Forward response headers
            for key, value in response.headers.items():
                if key.lower() not in ['content-encoding', 'transfer-encoding']:
                    self.send_header(key, value)
            self.end_headers()
            
            # Send response body
            if response.content:
                self.wfile.write(response.content)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to RGW failed: {str(e)}")
            self._send_error_response(502, f"RGW request failed: {str(e)}")
        except Exception as e:
            logger.error(f"Error forwarding request: {str(e)}")
            self._send_error_response(500, f"Forward error: {str(e)}")
    
    def _log_request(self, method, path, query, body):
        """Log incoming request details"""
        timestamp = datetime.datetime.now().isoformat()
        
        request_data = {
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "query": query,
            "headers": dict(self.headers),
            "body_size": len(body),
            "body": body.decode('utf-8', errors='ignore') if body else None
        }
        
        # Log to request log file
        with open(f"{log_dir}/requests.jsonl", "a") as f:
            f.write(json.dumps(request_data) + "\n")
        
        logger.info(f"Request: {method} {path}?{query} (body: {len(body)} bytes)")
    
    def _log_policy_payload(self, method, path, query, payload):
        """Log policy-specific payloads to separate file"""
        timestamp = datetime.datetime.now().isoformat()
        
        policy_data = {
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "query": query,
            "payload": payload
        }
        
        # Log to policy-specific log file
        with open(f"{log_dir}/policy_payloads.jsonl", "a") as f:
            f.write(json.dumps(policy_data, indent=2) + "\n")
        
        logger.info(f"Policy payload logged for: {path}")
    
    def _log_response(self, response):
        """Log response details"""
        timestamp = datetime.datetime.now().isoformat()
        
        response_data = {
            "timestamp": timestamp,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body_size": len(response.content),
            "body": response.text if response.text else None
        }
        
        # Log to response log file
        with open(f"{log_dir}/responses.jsonl", "a") as f:
            f.write(json.dumps(response_data) + "\n")
        
        logger.info(f"Response: {response.status_code} ({len(response.content)} bytes)")
    
    def _extract_bucket_name(self, path):
        """Extract bucket name from the URL path"""
        # Remove leading slash and any trailing slash
        clean_path = path.strip('/')
        
        # For bucket policy requests, the path should be just the bucket name
        # Example: "/my-bucket" -> "my-bucket"
        if clean_path:
            return clean_path
        
        return None
    
    def _generate_policy_body(self, bucket_name):
        """Generate a policy body from scratch for the given bucket"""
        # Create a basic S3 bucket policy allowing public read access
        # This is a template that RESTler can then fuzz and modify
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:ListBucket",
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ]
                }
            ]
        }
        
        return policy

    def _send_error_response(self, code, message):
        """Send error response to client"""
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        error_response = {
            "error": message,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        self.wfile.write(json.dumps(error_response).encode('utf-8'))


def create_handler_class(rgw_endpoint):
    """Create handler class with RGW endpoint configuration"""
    class ConfiguredHandler(RGWProxyHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, rgw_endpoint=rgw_endpoint, **kwargs)
    
    return ConfiguredHandler


def main():
    """Main function to start the proxy server"""
    parser = argparse.ArgumentParser(description='RGW Proxy Server for RESTler Fuzzing')
    parser.add_argument('--port', type=int, default=8080, help='Proxy server port (default: 8080)')
    parser.add_argument('--rgw-endpoint', default="http://localhost:8000", help='RGW endpoint URL (e.g., http://rgw-server:8000)')
    parser.add_argument('--host', default='localhost', help='Proxy server host (default: localhost)')
    
    args = parser.parse_args()
    
    # Validate RGW endpoint
    if not args.rgw_endpoint.startswith(('http://', 'https://')):
        logger.error("RGW endpoint must start with http:// or https://")
        sys.exit(1)
    
    # Create handler class with configuration
    handler_class = create_handler_class(args.rgw_endpoint)
    
    # Start server
    server_address = (args.host, args.port)
    httpd = HTTPServer(server_address, handler_class)
    
    logger.info(f"Starting RGW Proxy Server on {args.host}:{args.port}")
    logger.info(f"Forwarding to RGW endpoint: {args.rgw_endpoint}")
    logger.info(f"Logs will be saved to: {log_dir}/")
    logger.info("Press Ctrl+C to stop the server")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    finally:
        httpd.server_close()


if __name__ == '__main__':
    main()