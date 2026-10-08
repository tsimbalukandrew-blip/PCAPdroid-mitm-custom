#!/usr/bin/env python3
"""
Standoff 2 Traffic Interceptor для PCAPdroid MITM
Перехватывает ВСЕ данные к server.boltgaming.io и сохраняет в файл
"""

from mitmproxy import http, ctx
import base64
import time

class Standoff2Interceptor:
    """Перехватывает весь трафик Standoff 2"""
    
    def __init__(self):
        self.target_hosts = [
            "server.boltgaming.io",
            "boltgaming.io",
            "prd-matchmaking.boltgaming.io",
            "geoip-yc.boltgaming.io"
        ]
        self.output_file = "/sdcard/standoff2_traffic.txt"
        self.packet_count = 0
        
    def load(self, loader):
        """Загрузка аддона"""
        ctx.log.alert("="*60)
        ctx.log.alert("🔥 STANDOFF 2 INTERCEPTOR ACTIVE!")
        ctx.log.alert(f"Targets: {', '.join(self.target_hosts)}")
        ctx.log.alert(f"Output: {self.output_file}")
        ctx.log.alert("="*60)
        
        # Создаём файл
        try:
            with open(self.output_file, "w") as f:
                f.write("=== STANDOFF 2 TRAFFIC LOG ===\n")
                f.write(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        except Exception as e:
            ctx.log.error(f"Failed to create log file: {e}")
    
    def request(self, flow: http.HTTPFlow):
        """Перехват REQUEST"""
        
        # Проверяем хост
        if not any(host in flow.request.pretty_host for host in self.target_hosts):
            return
        
        self.packet_count += 1
        
        try:
            # Логируем
            ctx.log.alert(f"\n🔵 REQUEST #{self.packet_count}")
            ctx.log.alert(f"URL: {flow.request.pretty_url}")
            ctx.log.alert(f"Method: {flow.request.method}")
            ctx.log.alert(f"Content-Length: {len(flow.request.content)} bytes")
            
            # Сохраняем в файл
            with open(self.output_file, "a") as f:
                f.write("="*70 + "\n")
                f.write(f"REQUEST #{self.packet_count}\n")
                f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"URL: {flow.request.pretty_url}\n")
                f.write(f"Method: {flow.request.method}\n")
                f.write(f"Headers:\n")
                for k, v in flow.request.headers.items():
                    f.write(f"  {k}: {v}\n")
                
                # Тело запроса
                if flow.request.content:
                    f.write(f"\nBody ({len(flow.request.content)} bytes):\n")
                    
                    # Сохраняем как Base64 (может быть бинарные данные)
                    b64_content = base64.b64encode(flow.request.content).decode()
                    f.write(f"Base64: {b64_content}\n")
                    
                    # Пытаемся декодировать как текст
                    try:
                        text = flow.request.content.decode('utf-8', errors='ignore')
                        if text.isprintable() or any(word in text.lower() for word in ['handshake', 'token', 'auth', 'session']):
                            f.write(f"Text: {text}\n")
                            
                            # Если нашли ключевые слова - АЛЕРТ!
                            if any(word in text.lower() for word in ['handshake', 'token', 'auth']):
                                ctx.log.alert("🎉 FOUND KEYWORD IN REQUEST!")
                                f.write(">>> POTENTIAL HANDSHAKE/TOKEN! <<<\n")
                    except:
                        pass
                
                f.write("\n")
        except Exception as e:
            ctx.log.error(f"Error in request: {e}")
    
    def response(self, flow: http.HTTPFlow):
        """Перехват RESPONSE"""
        
        # Проверяем хост
        if not any(host in flow.request.pretty_host for host in self.target_hosts):
            return
        
        try:
            # Логируем
            ctx.log.alert(f"\n🟢 RESPONSE to #{self.packet_count}")
            ctx.log.alert(f"Status: {flow.response.status_code}")
            ctx.log.alert(f"Content-Length: {len(flow.response.content)} bytes")
            
            # Сохраняем в файл
            with open(self.output_file, "a") as f:
                f.write(f"RESPONSE to #{self.packet_count}\n")
                f.write(f"Status: {flow.response.status_code}\n")
                f.write(f"Headers:\n")
                for k, v in flow.response.headers.items():
                    f.write(f"  {k}: {v}\n")
                
                # Тело ответа
                if flow.response.content:
                    f.write(f"\nBody ({len(flow.response.content)} bytes):\n")
                    
                    # Base64
                    b64_content = base64.b64encode(flow.response.content).decode()
                    f.write(f"Base64: {b64_content}\n")
                    
                    # Текст
                    try:
                        text = flow.response.content.decode('utf-8', errors='ignore')
                        if text.isprintable() or any(word in text.lower() for word in ['handshake', 'token', 'auth', 'session']):
                            f.write(f"Text: {text}\n")
                            
                            if any(word in text.lower() for word in ['handshake', 'token', 'auth']):
                                ctx.log.alert("🎉 FOUND KEYWORD IN RESPONSE!")
                                f.write(">>> POTENTIAL HANDSHAKE/TOKEN! <<<\n")
                    except:
                        pass
                
                f.write("\n" + "="*70 + "\n\n")
        except Exception as e:
            ctx.log.error(f"Error in response: {e}")

# Регистрируем аддон
addons = [Standoff2Interceptor()]
