#!/usr/bin/env python3
"""
Standoff 2 UDP/TCP Token Hunter - Full Traffic Parser
Intercepts UDP game protocol (port 50000) and HTTP/TCP traffic
NO SSL MITM - passes TLS through to fix internet
"""

import re
import json
import base64
import struct
from mitmproxy import http, tcp, ctx
from datetime import datetime
from typing import Set, Dict

# Output file
OUTPUT_FILE = "/data/data/com.pcapdroid.mitm/files/standoff2_tokens.txt"

class Standoff2Parser:
    """Full traffic parser - UDP game protocol + TCP/HTTP"""
    
    # Target servers
    TARGET_SERVERS = [
        "server.boltgaming.io",
        "boltgaming.io",
        "bolt-proxy-msk.boltgaming.io",
        "metrics.ms.boltgaming.io",
        "api.standoff2.com",
        "game.axlebolt.com"
    ]
    
    # Target ports
    TARGET_PORTS = [50000, 2223, 9111, 443, 80]
    
    # Game server IPs (UDP:50000)
    GAME_SERVER_IPS = [
        "94.131.93.175", "95.41.17.21", "3.126.177.210",
        "78.14.156.6", "15.161.124.154", "111.88.130.254",
        "80.251.159.25", "54.221.250.68", "15.229.88.215",
        "51.21.83.33", "157.22.133.223", "54.248.33.112",
        "178.178.66.190", "63.184.38.3",
        "169.40.38.128", "64.137.111.128", "35.157.171.55",
        "3.76.91.243", "35.157.34.248", "18.197.197.4"
    ]
    
    def __init__(self):
        self.tokens: list = []
        self.seen_tokens: Set[str] = set()
        self.log_file: str = OUTPUT_FILE
        self.packet_count: int = 0
        self.udp_packet_count: int = 0
        self.token_count: int = 0
        self.udp_flows: Dict[str, dict] = {}
        
    def load(self, loader):
        """Initialize addon"""
        ctx.log.alert("="*70)
        ctx.log.alert("🎮 STANDOFF 2 FULL TRAFFIC HUNTER")
        ctx.log.alert("📡 UDP Parser: ENABLED (port 50000)")
        ctx.log.alert("🌐 HTTP Parser: ENABLED")
        ctx.log.alert("🚫 TLS MITM: DISABLED (passthrough for internet)")
        ctx.log.alert("="*70)
        self._init_log_file()
        
    def _init_log_file(self):
        """Initialize log file"""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Standoff 2 Full Traffic Hunter - {datetime.now()}\n")
                f.write("Mode: UDP + HTTP Parser, NO TLS MITM\n")
                f.write("=" * 80 + "\n\n")
            ctx.log.info(f"✅ Log file ready: {self.log_file}")
        except Exception as e:
            ctx.log.error(f"❌ Log file error: {e}")
    
    def request(self, flow: http.HTTPFlow):
        """Parse HTTP requests"""
        if not self._is_standoff2_traffic(flow):
            return
        
        self.packet_count += 1
        server_info = f"{flow.request.host}:{flow.server_conn.address[1] if flow.server_conn else '?'}"
        
        ctx.log.info(f"📤 HTTP REQ: {flow.request.method} {flow.request.pretty_url}")
        
        # Extract from headers
        for header_name, value in flow.request.headers.items():
            if any(keyword in header_name.lower() for keyword in ["token", "auth", "session", "key", "bearer"]):
                self._save_token(value, f"HTTP Request Header: {header_name}", server_info, flow.request.pretty_url)
        
        # Extract from body
        if flow.request.content:
            self._extract_from_body(flow.request.content, "HTTP Request Body", server_info, flow.request.pretty_url)
    
    def response(self, flow: http.HTTPFlow):
        """Parse HTTP responses"""
        if not self._is_standoff2_traffic(flow):
            return
        
        self.packet_count += 1
        server_info = f"{flow.request.host}:{flow.server_conn.address[1] if flow.server_conn else '?'}"
        
        ctx.log.info(f"📥 HTTP RESP: {flow.response.status_code} from {server_info}")
        
        # Extract from headers
        for header_name, value in flow.response.headers.items():
            if any(keyword in header_name.lower() for keyword in ["token", "auth", "session", "key", "set-cookie"]):
                self._save_token(value, f"HTTP Response Header: {header_name}", server_info, flow.request.pretty_url)
        
        # Extract from body
        if flow.response.content:
            self._extract_from_body(flow.response.content, "HTTP Response Body", server_info, flow.request.pretty_url)
    
    def tcp_message(self, flow: tcp.TCPFlow):
        """Parse TCP messages - including UDP-over-TCP and raw TCP"""
        if not flow.server_conn:
            return
        
        server_host = flow.server_conn.address[0]
        server_port = flow.server_conn.address[1]
        
        # Check if it's game traffic
        is_game_server = (
            any(ip in server_host for ip in self.GAME_SERVER_IPS) or
            server_port in self.TARGET_PORTS or
            any(srv in server_host for srv in self.TARGET_SERVERS)
        )
        
        if not is_game_server:
            return
        
        if not flow.messages:
            return
        
        msg = flow.messages[-1]
        direction = "CLIENT→SERVER" if msg.from_client else "SERVER→CLIENT"
        server_info = f"{server_host}:{server_port}"
        
        # Special handling for UDP port 50000
        if server_port == 50000:
            self.udp_packet_count += 1
            ctx.log.warn(f"🎯 UDP GAME PACKET: {direction} {server_info} ({len(msg.content)} bytes)")
            self._parse_udp_game_protocol(msg.content, direction, server_info)
        else:
            ctx.log.info(f"📡 TCP: {direction} {server_info} ({len(msg.content)} bytes)")
            self._extract_from_body(msg.content, f"TCP {direction}", server_info, f"tcp://{server_info}")
    
    def _parse_udp_game_protocol(self, data: bytes, direction: str, server: str):
        """Parse Standoff 2 UDP game protocol"""
        if len(data) < 8:
            return
        
        try:
            # Log raw hex dump
            hex_dump = data[:256].hex()
            ctx.log.warn(f"UDP HEX: {hex_dump[:128]}...")
            
            # Try to find text patterns (handshake tokens are often text)
            text_matches = re.findall(rb'[\x20-\x7E]{8,}', data)
            for match in text_matches:
                try:
                    token = match.decode('ascii')
                    if len(token) >= 20:
                        ctx.log.alert(f"🔑 UDP TOKEN FOUND: {token[:100]}")
                        self._save_token(token, f"UDP Game Protocol {direction}", server, f"udp://{server}")
                except:
                    pass
            
            # Try JSON parsing
            try:
                text = data.decode('utf-8', errors='ignore')
                if '{' in text:
                    json_match = re.search(r'\{[^}]+\}', text)
                    if json_match:
                        json_data = json.loads(json_match.group(0))
                        ctx.log.alert(f"📦 UDP JSON: {json_data}")
                        self._extract_from_json(json_data, f"UDP JSON {direction}", server, f"udp://{server}")
            except:
                pass
            
            # Try binary protocol parsing
            if len(data) >= 16:
                # Common packet header: magic, type, length, payload
                magic = struct.unpack('>I', data[0:4])[0]
                packet_type = data[4] if len(data) > 4 else 0
                
                ctx.log.info(f"UDP Packet: magic=0x{magic:08x}, type={packet_type}, len={len(data)}")
                
                # Look for handshake patterns
                if b'handshake' in data.lower() or b'token' in data.lower():
                    ctx.log.alert("🔐 HANDSHAKE DETECTED in UDP packet!")
                    self._extract_from_body(data, f"UDP Handshake {direction}", server, f"udp://{server}")
            
            # Save full packet for analysis
            self._write_udp_packet(data, direction, server)
            
        except Exception as e:
            ctx.log.error(f"UDP parse error: {e}")
    
    def _write_udp_packet(self, data: bytes, direction: str, server: str):
        """Write UDP packet to file for offline analysis"""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"\n--- UDP PACKET #{self.udp_packet_count} ---\n")
                f.write(f"Direction: {direction}\n")
                f.write(f"Server: {server}\n")
                f.write(f"Size: {len(data)} bytes\n")
                f.write(f"Hex: {data[:512].hex()}\n")
                f.write(f"ASCII: {data[:512].decode('ascii', errors='ignore')}\n")
                f.write("\n")
        except:
            pass
    
    def _is_standoff2_traffic(self, flow: http.HTTPFlow) -> bool:
        """Check if HTTP traffic is from Standoff 2"""
        host = flow.request.host.lower()
        
        for target in self.TARGET_SERVERS:
            if target in host:
                return True
        
        if flow.server_conn:
            port = flow.server_conn.address[1]
            if port in self.TARGET_PORTS:
                return True
        
        return False
    
    def _extract_from_body(self, content: bytes, source: str, server: str, url: str):
        """Extract tokens from body content"""
        try:
            text = content.decode('utf-8', errors='ignore')
            
            # JSON parsing
            try:
                data = json.loads(text)
                self._extract_from_json(data, source, server, url)
            except:
                pass
            
            # JWT tokens
            jwt_pattern = r'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'
            for match in re.finditer(jwt_pattern, text):
                token = match.group(0)
                self._save_token(token, f"{source} - JWT", server, url)
            
            # Long alphanumeric tokens
            token_pattern = r'\b([A-Za-z0-9_\-]{32,128})\b'
            for match in re.finditer(token_pattern, text):
                token = match.group(1)
                if self._is_valid_token(token):
                    self._save_token(token, f"{source} - Alphanumeric", server, url)
            
            # Handshake-specific patterns
            handshake_pattern = r'(?:handshake|session|token|auth)["\s:=]+([A-Za-z0-9_\-\.]{20,})'
            for match in re.finditer(handshake_pattern, text, re.IGNORECASE):
                token = match.group(1)
                self._save_token(token, f"{source} - Handshake Pattern", server, url)
            
        except Exception as e:
            ctx.log.debug(f"Body extract error: {e}")
    
    def _extract_from_json(self, data, source: str, server: str, url: str):
        """Extract tokens from JSON"""
        if isinstance(data, dict):
            for key, value in data.items():
                if any(k in key.lower() for k in ["token", "auth", "session", "handshake", "key", "secret"]):
                    if isinstance(value, str) and len(value) >= 20:
                        self._save_token(value, f"{source} - JSON:{key}", server, url)
                elif isinstance(value, (dict, list)):
                    self._extract_from_json(value, source, server, url)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._extract_from_json(item, source, server, url)
    
    def _is_valid_token(self, token: str) -> bool:
        """Check if string looks like a token"""
        if len(token) < 20:
            return False
        
        # Skip common false positives
        invalid = [".dll", ".exe", ".png", ".jpg", "http://", "https://", "android", "google"]
        if any(inv in token.lower() for inv in invalid):
            return False
        
        # Check entropy
        unique_chars = len(set(token))
        if unique_chars < 8:
            return False
        
        return True
    
    def _save_token(self, token: str, source: str, server: str, url: str):
        """Save discovered token"""
        if not self._is_valid_token(token):
            return
        
        if token in self.seen_tokens:
            return
        
        self.seen_tokens.add(token)
        self.token_count += 1
        
        token_info = {
            "id": self.token_count,
            "token": token,
            "source": source,
            "server": server,
            "url": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "length": len(token)
        }
        
        self.tokens.append(token_info)
        
        ctx.log.alert("=" * 70)
        ctx.log.alert(f"🔑 TOKEN #{self.token_count} FOUND!")
        ctx.log.alert(f"Server: {server}")
        ctx.log.alert(f"Source: {source}")
        ctx.log.alert(f"Token: {token[:150]}")
        ctx.log.alert("=" * 70)
        
        self._write_token(token_info)
    
    def _write_token(self, token_info: dict):
        """Write token to file"""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"TOKEN #{token_info['id']}\n")
                f.write(f"{'='*80}\n")
                f.write(f"Timestamp:  {token_info['timestamp']}\n")
                f.write(f"Server:     {token_info['server']}\n")
                f.write(f"URL:        {token_info['url']}\n")
                f.write(f"Source:     {token_info['source']}\n")
                f.write(f"Length:     {token_info['length']} chars\n")
                f.write(f"\nToken:\n{token_info['token']}\n\n")
        except Exception as e:
            ctx.log.error(f"Write error: {e}")

# Register addon
addons = [Standoff2Parser()]
