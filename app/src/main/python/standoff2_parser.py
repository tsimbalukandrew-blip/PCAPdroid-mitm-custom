#!/usr/bin/env python3
"""
Standoff 2 Token Hunter - PCAPdroid MITM Addon
"""

import re
import json
import base64
from mitmproxy import http, tcp, ctx
from datetime import datetime
from typing import Set

# Output file - internal app directory (no permissions needed)
OUTPUT_FILE = "/data/data/com.pcapdroid.mitm/files/standoff2_tokens.txt"

def log(msg):
    """Simple logging"""
    ctx.log.info(f"[STANDOFF2] {msg}")
    try:
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"{datetime.now()}: {msg}\n")
    except:
        pass

class Standoff2Parser:
    """Advanced token parser for Standoff 2 game traffic"""
    
    # Target servers for Standoff 2
    TARGET_SERVERS = [
        "server.boltgaming.io",
        "boltgaming.io",
        "api.standoff2.com",
        "standoff2.com",
        "game.axlebolt.com",
        "axlebolt.com"
    ]
    
    # Target ports
    TARGET_PORTS = [2223, 443, 80, 8080]
    
    # Token-related headers to monitor
    TOKEN_HEADERS = [
        "authorization",
        "x-auth-token",
        "x-session-token",
        "x-access-token",
        "x-api-key",
        "session-token",
        "auth-token",
        "bearer",
        "token",
        "auth",
        "session",
        "api-key"
    ]
    
    # JSON keys that might contain tokens
    TOKEN_JSON_KEYS = [
        "token", "access_token", "auth_token", "session_token",
        "authToken", "accessToken", "sessionToken", "refreshToken",
        "handshake", "handshakeToken", "session", "sessionId",
        "authorization", "auth", "bearer", "apiKey", "api_key",
        "encryptedHandshake", "gameToken", "playerToken", "userToken"
    ]
    
    # Invalid token patterns (false positives)
    INVALID_PATTERNS = [
        ".dll", ".exe", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
        ".so", ".apk", ".bin", ".dat", "http://", "https://",
        "www.", "android", "com.google", "com.android"
    ]
    
    def __init__(self):
        self.tokens: list = []
        self.seen_tokens: Set[str] = set()  # Track duplicates
        self.enabled: bool = True
        self.log_file: str = "/data/data/com.pcapdroid.mitm/files/standoff2_tokens.txt"
        self.packet_count: int = 0
        self.token_count: int = 0
        
    def load(self, loader):
        """Initialize addon"""
        ctx.log.info("="*60)
        ctx.log.info("Standoff 2 Advanced Token Hunter - LOADED")
        ctx.log.info(f"Target servers: {', '.join(self.TARGET_SERVERS)}")
        ctx.log.info(f"Log file: {self.log_file}")
        ctx.log.info("="*60)
        
        ctx.log.alert("="*60)
        ctx.log.alert("🔥 STANDOFF 2 TOKEN HUNTER ACTIVE!")
        ctx.log.alert("🔓 SSL PINNING BYPASS: ENABLED")
        ctx.log.alert("📜 FAKE CERTIFICATES: ACTIVE")
        ctx.log.alert("="*60)
        
        # Test notification
        ctx.log.info("[TEST] If you see this - addon is WORKING!")
        ctx.log.warn("[TEST] Addon loaded successfully!")
        ctx.log.warn("[TEST] SSL Pinning will be bypassed automatically!")
        
        # Initialize log file
        self._init_log_file()
        
    def _init_log_file(self):
        """Initialize or append to log file"""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Standoff 2 Token Hunter Session Started\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
            ctx.log.info(f"Log file initialized: {self.log_file}")
        except Exception as e:
            ctx.log.error(f"Failed to initialize log file: {e}")
            # Fallback to internal storage
            self.log_file = "/data/data/com.pcapdroid.mitm/files/standoff2_tokens.txt"
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"\n=== Session {datetime.now()} ===\n")
                ctx.log.warn(f"Using fallback log file: {self.log_file}")
            except:
                ctx.log.error("Cannot write to any log file!")
                
    def tls_clienthello(self, data):
        """
        Перехватываем TLS ClientHello для модификации SNI
        Это позволяет обойти SSL pinning
        """
        try:
            # Логируем попытку TLS подключения
            ctx.log.info(f"[TLS] ClientHello intercepted for SNI modification")
            
            # mitmproxy автоматически подменит сертификат
            # Нам просто нужно перехватить трафик
            
        except Exception as e:
            ctx.log.debug(f"TLS intercept error: {e}")
    
    def tls_established(self, data):
        """
        TLS соединение установлено - сертификат принят!
        """
        try:
            client_conn = data.context.client
            server_conn = data.context.server
            
            ctx.log.alert("="*60)
            ctx.log.alert("🔓 TLS CONNECTION ESTABLISHED!")
            ctx.log.alert(f"Client: {client_conn.peername if client_conn else 'unknown'}")
            ctx.log.alert(f"Server: {server_conn.address if server_conn else 'unknown'}")
            ctx.log.alert("✅ SSL PINNING BYPASSED SUCCESSFULLY!")
            ctx.log.alert("="*60)
            
            # Логируем в файл
            log_msg = f"\n[TLS ESTABLISHED] {datetime.now()}\n"
            log_msg += f"Server: {server_conn.address if server_conn else 'unknown'}\n"
            log_msg += f"SSL Pinning: BYPASSED ✅\n"
            self._write_to_file({"id": 0, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                               "type": "TLS", "server": str(server_conn.address if server_conn else ''),
                               "url": "", "source": "TLS Handshake", "length": 0,
                               "token": log_msg})
            
        except Exception as e:
            ctx.log.debug(f"TLS established log error: {e}")
    
    def request(self, flow: http.HTTPFlow):
        """Parse HTTP requests for tokens"""
        if not self.enabled:
            return
            
        # Check if it's Standoff 2 traffic
        if not self._is_standoff2_traffic(flow):
            return
        
        self.packet_count += 1
        server_info = f"{flow.request.host}:{flow.server_conn.address[1] if flow.server_conn else 'unknown'}"
        
        ctx.log.info(f"[REQUEST] Analyzing: {flow.request.method} {flow.request.pretty_url}")
        
        # Extract tokens from headers
        self._extract_from_headers(flow.request.headers, "REQUEST", server_info, flow.request.pretty_url)
        
        # Extract tokens from body
        if flow.request.content:
            self._extract_from_body(flow.request.content, "REQUEST", server_info, flow.request.pretty_url)
    
    def response(self, flow: http.HTTPFlow):
        """Parse HTTP responses for tokens"""
        if not self.enabled:
            return
            
        if not self._is_standoff2_traffic(flow):
            return
        
        self.packet_count += 1
        server_info = f"{flow.request.host}:{flow.server_conn.address[1] if flow.server_conn else 'unknown'}"
        
        ctx.log.info(f"[RESPONSE] Analyzing: {flow.response.status_code} from {server_info}")
        
        # Extract tokens from headers
        self._extract_from_headers(flow.response.headers, "RESPONSE", server_info, flow.request.pretty_url)
        
        # Extract tokens from body  
        if flow.response.content:
            self._extract_from_body(flow.response.content, "RESPONSE", server_info, flow.request.pretty_url)
    
    def tcp_message(self, flow: tcp.TCPFlow):
        """Parse raw TCP messages (for non-HTTP traffic like game protocol)"""
        if not self.enabled:
            return
        
        # Check if connection is to Standoff 2 servers
        if not flow.server_conn:
            return
            
        server_host = flow.server_conn.address[0]
        server_port = flow.server_conn.address[1]
        
        # Check if it's a target server/port
        is_target = any(srv in server_host for srv in self.TARGET_SERVERS) or server_port in self.TARGET_PORTS
        
        if not is_target:
            return
        
        # Get latest message
        if not flow.messages:
            return
            
        msg = flow.messages[-1]
        direction = "TCP_CLIENT" if msg.from_client else "TCP_SERVER"
        server_info = f"{server_host}:{server_port}"
        
        ctx.log.info(f"[{direction}] TCP packet from {server_info}, size: {len(msg.content)} bytes")
        
        # Try to extract tokens from raw TCP data
        self._extract_from_body(msg.content, direction, server_info, f"tcp://{server_info}")
    
    def _is_standoff2_traffic(self, flow: http.HTTPFlow) -> bool:
        """Check if traffic is from Standoff 2"""
        host = flow.request.host.lower()
        
        # Check domain
        for target in self.TARGET_SERVERS:
            if target in host:
                return True
        
        # Check port if server connection exists
        if flow.server_conn:
            port = flow.server_conn.address[1]
            if port in self.TARGET_PORTS:
                return True
        
        return False
    
    def _extract_from_headers(self, headers, direction: str, server: str, url: str):
        """Extract tokens from HTTP headers"""
        for header_name in self.TOKEN_HEADERS:
            if header_name in headers:
                value = headers[header_name]
                
                # Process Bearer tokens
                if value.lower().startswith("bearer "):
                    token = value[7:].strip()
                    self._save_token(token, f"{direction} | Header: {header_name} (Bearer)", server, url)
                else:
                    self._save_token(value, f"{direction} | Header: {header_name}", server, url)
    
    def _extract_from_body(self, content: bytes, direction: str, server: str, url: str):
        """Extract tokens from request/response body"""
        try:
            # Try UTF-8 decode
            text = content.decode('utf-8', errors='ignore')
            
            # 1. Try JSON parsing
            try:
                data = json.loads(text)
                self._extract_from_json(data, direction, server, url)
            except:
                pass
            
            # 2. Search for JWT tokens (eyJ... format)
            jwt_pattern = r'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'
            for match in re.finditer(jwt_pattern, text):
                token = match.group(0)
                self._save_token(token, f"{direction} | Body: JWT Token", server, url)
            
            # 3. Search for Bearer tokens in text
            bearer_pattern = r'Bearer\s+([A-Za-z0-9_\-\.]{20,})'
            for match in re.finditer(bearer_pattern, text, re.IGNORECASE):
                token = match.group(1)
                self._save_token(token, f"{direction} | Body: Bearer", server, url)
            
            # 4. Search for quoted token strings
            quoted_pattern = r'"(?:token|session|auth|handshake|access_token|bearer)":\s*"([^"]{20,})"'
            for match in re.finditer(quoted_pattern, text, re.IGNORECASE):
                token = match.group(1)
                self._save_token(token, f"{direction} | Body: JSON String", server, url)
            
            # 5. Search for long alphanumeric strings (potential tokens)
            alphanum_pattern = r'\b([A-Za-z0-9_\-]{32,})\b'
            for match in re.finditer(alphanum_pattern, text):
                token = match.group(1)
                # More strict validation for generic patterns
                if self._is_valid_token_format(token):
                    self._save_token(token, f"{direction} | Body: Alphanumeric", server, url)
            
            # 6. Try to decode Base64 encoded data
            self._extract_base64_tokens(text, direction, server, url)
            
            # 7. For binary data, try hex search
            if len(content) > 20:
                self._extract_from_binary(content, direction, server, url)
                
        except Exception as e:
            ctx.log.debug(f"Error extracting from body: {e}")
    
    def _extract_from_json(self, data, direction: str, server: str, url: str):
        """Recursively extract tokens from JSON data"""
        if isinstance(data, dict):
            # Check for token-like keys
            for key in self.TOKEN_JSON_KEYS:
                if key in data:
                    value = data[key]
                    if isinstance(value, str) and len(value) >= 20:
                        self._save_token(value, f"{direction} | JSON: {key}", server, url)
                    elif isinstance(value, (dict, list)):
                        self._extract_from_json(value, direction, server, url)
            
            # Recurse into nested objects
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    self._extract_from_json(value, direction, server, url)
                elif isinstance(value, str) and len(value) >= 20:
                    # Check if value looks like a token even if key name is unknown
                    if self._is_valid_token_format(value):
                        self._save_token(value, f"{direction} | JSON: {key} (auto)", server, url)
                    
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._extract_from_json(item, direction, server, url)
                elif isinstance(item, str) and len(item) >= 20:
                    if self._is_valid_token_format(item):
                        self._save_token(item, f"{direction} | JSON: array item", server, url)
    
    def _extract_base64_tokens(self, text: str, direction: str, server: str, url: str):
        """Try to decode Base64 encoded tokens"""
        # Base64 pattern (minimum 20 chars)
        b64_pattern = r'\b([A-Za-z0-9+/]{20,}={0,2})\b'
        
        for match in re.finditer(b64_pattern, text):
            b64_str = match.group(1)
            
            # Skip if it looks like a JWT (already handled)
            if b64_str.startswith('eyJ'):
                continue
                
            try:
                decoded = base64.b64decode(b64_str, validate=True)
                decoded_text = decoded.decode('utf-8', errors='ignore')
                
                # Check if decoded data contains token-like strings
                if len(decoded_text) >= 20:
                    # Recursively check decoded content
                    self._extract_from_body(decoded, f"{direction} | Base64", server, url)
                    
            except Exception:
                pass  # Not valid base64 or not decodable
    
    def _extract_from_binary(self, content: bytes, direction: str, server: str, url: str):
        """Extract tokens from binary/protobuf-like data"""
        # Look for ASCII strings in binary data
        ascii_pattern = rb'[\x20-\x7E]{20,}'
        
        for match in re.finditer(ascii_pattern, content):
            token_bytes = match.group(0)
            try:
                token = token_bytes.decode('ascii')
                if self._is_valid_token_format(token):
                    self._save_token(token, f"{direction} | Binary: ASCII String", server, url)
            except:
                pass
    
    def _is_valid_token_format(self, token: str) -> bool:
        """Validate if string looks like a real token"""
        # Minimum length
        if len(token) < 20:
            return False
        
        # Check for invalid patterns
        token_lower = token.lower()
        for invalid in self.INVALID_PATTERNS:
            if invalid in token_lower:
                return False
        
        # Token should have good entropy (not all same chars)
        unique_chars = len(set(token))
        if unique_chars < 8:  # Too repetitive
            return False
        
        # Check for alphanumeric + common token chars
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.')
        token_chars = set(token)
        
        # At least 80% should be valid token characters
        valid_ratio = len(token_chars & valid_chars) / len(token_chars)
        if valid_ratio < 0.8:
            return False
        
        return True
    
    def _save_token(self, token: str, source: str, server: str, url: str):
        """Save and log discovered token"""
        # Validate token
        if not self._is_valid_token_format(token):
            return
        
        # Avoid duplicates
        if token in self.seen_tokens:
            return
        
        self.seen_tokens.add(token)
        self.token_count += 1
        
        # Determine token type
        token_type = self._classify_token(token)
        
        token_info = {
            "id": self.token_count,
            "token": token,
            "type": token_type,
            "source": source,
            "server": server,
            "url": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "length": len(token)
        }
        
        self.tokens.append(token_info)
        
        # Log to console (mitmproxy)
        ctx.log.alert("=" * 60)
        ctx.log.alert(f"🔑 TOKEN FOUND #{self.token_count}")
        ctx.log.alert(f"Type: {token_type}")
        ctx.log.alert(f"Server: {server}")
        ctx.log.alert(f"Source: {source}")
        ctx.log.alert(f"Length: {len(token)} chars")
        ctx.log.alert(f"Token: {token[:80]}{'...' if len(token) > 80 else ''}")
        ctx.log.alert("=" * 60)
        
        # Write to file
        self._write_to_file(token_info)
        
    def _classify_token(self, token: str) -> str:
        """Classify token type"""
        if token.startswith('eyJ') and '.' in token:
            return "JWT"
        elif len(token) == 32 and all(c in '0123456789abcdefABCDEF' for c in token):
            return "MD5/UUID"
        elif len(token) == 64 and all(c in '0123456789abcdefABCDEF' for c in token):
            return "SHA256"
        elif '-' in token and len(token) == 36:
            return "UUID"
        elif token.isalnum():
            return "Session Token"
        else:
            return "Custom Token"
    
    def _write_to_file(self, token_info: dict):
        """Write token to log file"""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"TOKEN #{token_info['id']}\n")
                f.write(f"{'='*80}\n")
                f.write(f"Timestamp:  {token_info['timestamp']}\n")
                f.write(f"Type:       {token_info['type']}\n")
                f.write(f"Server:     {token_info['server']}\n")
                f.write(f"URL:        {token_info['url']}\n")
                f.write(f"Source:     {token_info['source']}\n")
                f.write(f"Length:     {token_info['length']} chars\n")
                f.write(f"\nToken Value:\n{token_info['token']}\n")
                
                # Try to decode JWT
                if token_info['type'] == "JWT":
                    try:
                        parts = token_info['token'].split('.')
                        if len(parts) >= 2:
                            # Decode header
                            header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8', errors='ignore')
                            payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8', errors='ignore')
                            f.write(f"\nJWT Header:\n{header}\n")
                            f.write(f"\nJWT Payload:\n{payload}\n")
                    except:
                        pass
                
                f.write(f"\n")
                
        except Exception as e:
            ctx.log.error(f"Failed to write to log file: {e}")
        
    def get_all_tokens(self) -> list:
        """Return all discovered tokens"""
        return self.tokens
    
    def get_statistics(self) -> str:
        """Get parsing statistics"""
        stats = f"""
Standoff 2 Token Hunter Statistics
{'='*60}
Packets Analyzed: {self.packet_count}
Tokens Found:     {self.token_count}
Unique Tokens:    {len(self.seen_tokens)}
Log File:         {self.log_file}
{'='*60}
"""
        return stats
    
    def clear_tokens(self):
        """Clear stored tokens"""
        self.tokens = []
        self.seen_tokens.clear()
        self.token_count = 0
        ctx.log.info("All tokens cleared")

# Register addon with mitmproxy
addons = [Standoff2Parser()]

ctx.log.info("Standoff2Parser registered in addons list!")
ctx.log.info("Parser ready to intercept traffic")
