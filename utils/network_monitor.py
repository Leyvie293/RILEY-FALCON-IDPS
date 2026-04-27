# utils/network_monitor.py
"""
Network-Based Intrusion Detection System (NIDS)
Monitors and analyzes network traffic in real-time on Windows
"""

from scapy.all import *
from scapy.arch.windows import get_windows_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import time
from datetime import datetime, timedelta
import sys
import os
import psutil
import platform
import subprocess
import re
import socket
from collections import deque

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import NetworkTraffic, Alert, db

# Import broadcast function (will be set by routes)
broadcast_new_alert = None

def set_broadcast_function(func):
    """Set the broadcast function for real-time alerts"""
    global broadcast_new_alert
    broadcast_new_alert = func


class NetworkMonitor:
    def __init__(self, ai_engine=None, alert_manager=None):
        self.ai_engine = ai_engine
        self.alert_manager = alert_manager
        self.is_monitoring = False
        self.capture_thread = None
        self.packet_count = 0
        self.suspicious_packets = 0
        self.captured_packets = deque(maxlen=5000)  # Keep last 5000 packets
        self.packet_history = deque(maxlen=60)  # For chart data (60 seconds)
        self.current_interface = None
        self.current_ip = None
        self.wifi_ssid = None
        self.app_context = None  # For Flask application context
        self.stats = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0,
            'bytes': 0,
            'start_time': None,
            'packets_per_second': deque(maxlen=60)
        }
        self.os_type = platform.system()
        self.db_save_counter = 0
        self.db_save_batch_size = 5  # Save every 5 packets for real-time DB updates
        
        # Verify Npcap is installed
        self._check_npcap_installation()
        
        # Get current network info
        self._update_network_info()
        
        print(f"💻 Running on: {self.os_type}")
        print("📡 Initializing Network Monitor for Windows...")
        
        # Suspicious patterns for detection
        self.suspicious_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
            135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 2049: 'NFS', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM',
            6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch'
        }
    
    def set_app_context(self, app):
        """Set Flask app context for database operations in background threads"""
        self.app_context = app
        print("✅ Flask app context set for network monitor")
    
    def _update_network_info(self):
        """Update current network connection information"""
        try:
            # Get hostname
            hostname = platform.node()
            
            # Try to get active interface and IP using multiple methods
            interface_found = False
            
            # Method 1: Try netsh command
            try:
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, shell=True)
                if "There is no wireless interface" not in result.stdout:
                    for line in result.stdout.split('\n'):
                        if 'SSID' in line and ':' in line:
                            self.wifi_ssid = line.split(':')[1].strip()
                            print(f"📶 Connected to WiFi: {self.wifi_ssid}")
                        if 'Name' in line and ':' in line:
                            interface_name = line.split(':')[1].strip()
                            if interface_name and 'Wi-Fi' in line:
                                self.current_interface = interface_name
                                interface_found = True
            except:
                pass
            
            # Method 2: Get IP from socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.current_ip = s.getsockname()[0]
                s.close()
                print(f"🌐 Current IP: {self.current_ip}")
            except:
                pass
            
            # Method 3: Get interface from Scapy if not found
            if not interface_found:
                try:
                    from scapy.arch.windows import get_windows_if_list
                    interfaces = get_windows_if_list()
                    for iface in interfaces:
                        if iface.get('name') and iface.get('ips'):
                            ips = iface.get('ips', [])
                            for ip in ips:
                                if ip and not ip.startswith('127.') and not ip.startswith('fe80:'):
                                    if '.' in ip:  # IPv4
                                        self.current_ip = ip
                                        self.current_interface = iface['name']
                                        interface_found = True
                                        print(f"🌐 Found interface: {self.current_interface} with IP: {self.current_ip}")
                                        break
                            if interface_found:
                                break
                except:
                    pass
            
            # Default fallback
            if not self.current_interface:
                self.current_interface = 'Wi-Fi'
                print(f"🔌 Using default interface: {self.current_interface}")
            
            print(f"🔌 Current Interface: {self.current_interface or 'Unknown'}")
            
        except Exception as e:
            print(f"⚠️ Error updating network info: {e}")
            self.current_interface = 'Wi-Fi'  # Default fallback
    
    def _check_npcap_installation(self):
        """Verify Npcap is installed for packet capture"""
        try:
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\WOW6432Node\Npcap")
                version = winreg.QueryValueEx(key, "Version")[0]
                print(f"✅ Npcap detected: Version {version}")
                return True
            except:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Npcap")
                version = winreg.QueryValueEx(key, "Version")[0]
                print(f"✅ Npcap detected: Version {version}")
                return True
        except:
            print("⚠️ Npcap not found. Please install Npcap for packet capture.")
            print("   Download from: https://npcap.com")
            return False
    
    def get_active_interface(self):
        """Get the currently active network interface"""
        try:
            # First try the known working interface from your test
            known_working = ['Wi-Fi', 'WiFi', 'WLAN', 'Ethernet']
            for iface_name in known_working:
                try:
                    test_socket = conf.L2listen(iface=iface_name)
                    test_socket.close()
                    print(f"✅ Using working interface: {iface_name}")
                    self.current_interface = iface_name
                    return iface_name
                except:
                    continue
            
            # Then try netsh command
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, shell=True)
            
            if "There is no wireless interface" not in result.stdout:
                for line in result.stdout.split('\n'):
                    if 'Name' in line and ':' in line:
                        interface_name = line.split(':')[1].strip()
                        if interface_name:
                            self.current_interface = interface_name
                            self.wifi_ssid = None
                            for l in result.stdout.split('\n'):
                                if 'SSID' in l and ':' in l:
                                    self.wifi_ssid = l.split(':')[1].strip()
                            print(f"✅ Found interface from netsh: {interface_name}")
                            return interface_name
            
            # Last resort - get from interface list
            interfaces = get_windows_if_list()
            for iface in interfaces:
                if iface.get('name') and iface.get('ips'):
                    # Look for interface with 192.168.x.x IP (local network)
                    ips = iface.get('ips', [])
                    for ip in ips:
                        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                            self.current_interface = iface['name']
                            self.current_ip = ip
                            print(f"✅ Found active interface from IP: {iface['name']} ({ip})")
                            return iface['name']
            
            return 'Wi-Fi'  # Default fallback
            
        except Exception as e:
            print(f"❌ Error getting active interface: {e}")
            return 'Wi-Fi'  # Default fallback
    
    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        try:
            active_interface = self.get_active_interface()
            windows_ifaces = get_windows_if_list()
            
            print("\n" + "="*60)
            print("📡 AVAILABLE NETWORK INTERFACES")
            print("="*60)
            
            if self.wifi_ssid:
                print(f"\n📶 CURRENTLY CONNECTED TO: {self.wifi_ssid}")
            
            for i, iface in enumerate(windows_ifaces):
                if iface['name'] and iface['ips']:
                    if 'Virtual' not in iface['description'] and 'Loopback' not in iface['description']:
                        is_active = (iface['name'] == active_interface)
                        status = "✅ ACTIVE" if is_active else "○ AVAILABLE"
                        
                        interfaces.append({
                            'name': iface['name'],
                            'description': iface['description'],
                            'ips': iface['ips'],
                            'is_active': is_active,
                            'ssid': self.wifi_ssid if is_active and self.wifi_ssid else None
                        })
                        
                        print(f"\n{i+1}. {iface['description']}")
                        print(f"   Name: {iface['name']}")
                        print(f"   IPs: {', '.join(iface['ips'])}")
                        print(f"   Status: {status}")
                        if is_active and self.wifi_ssid:
                            print(f"   Connected to: {self.wifi_ssid}")
            
        except Exception as e:
            print(f"❌ Error getting interfaces: {e}")
            
        return interfaces
    
    def get_wifi_status(self):
        """Get detailed WiFi connection status"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True, shell=True)
            
            status = {
                'connected': False,
                'ssid': None,
                'signal': None,
                'interface': None,
                'ip': self.current_ip
            }
            
            if "There is no wireless interface" not in result.stdout:
                for line in result.stdout.split('\n'):
                    if 'SSID' in line and ':' in line:
                        status['ssid'] = line.split(':')[1].strip()
                        status['connected'] = True
                    if 'Signal' in line and ':' in line:
                        status['signal'] = line.split(':')[1].strip()
                    if 'Name' in line and ':' in line:
                        status['interface'] = line.split(':')[1].strip()
            
            # Update wifi_ssid if connected
            if status['connected']:
                self.wifi_ssid = status['ssid']
            
            return status
        except:
            return {'connected': False, 'ssid': None, 'signal': None, 'interface': None, 'ip': self.current_ip}
    
    def start_monitoring(self, interface=None):
        """Start network monitoring"""
        if self.is_monitoring:
            print("⚠️ Monitoring already running")
            return True
        
        # If no interface specified, auto-detect
        if not interface:
            interface = self.get_active_interface()
            print(f"🔍 Auto-detected interface: {interface}")
        
        print(f"\n" + "="*60)
        print(f"🎯 STARTING REAL NETWORK CAPTURE")
        print("="*60)
        print(f"Interface: {interface}")
        
        wifi_status = self.get_wifi_status()
        if wifi_status['connected']:
            print(f"WiFi Network: {wifi_status['ssid']}")
            print(f"Signal: {wifi_status['signal']}")
        
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*60)
        
        self.get_available_interfaces()
        
        # Verify interface works
        try:
            test_socket = conf.L2listen(iface=interface)
            test_socket.close()
        except Exception as e:
            print(f"\n❌ ERROR: Cannot open interface '{interface}': {e}")
            print("\nAvailable interfaces:")
            for iface in get_windows_if_list():
                if iface['name']:
                    print(f"  - {iface['name']}: {iface['description']}")
            print("\nPlease select a valid interface from the list above.")
            return False
        
        self.current_interface = interface
        self.is_monitoring = True
        self.stats['start_time'] = datetime.utcnow()
        self.capture_thread = threading.Thread(target=self._capture_packets, args=(interface,))
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        print(f"\n✅ REAL-TIME network monitoring started on {interface}")
        if wifi_status['connected']:
            print(f"📶 Monitoring WiFi: {wifi_status['ssid']}")
        print("📊 Capturing and analyzing live network traffic...")
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        duration = 0
        if self.stats['start_time']:
            duration = (datetime.utcnow() - self.stats['start_time']).total_seconds()
        
        print(f"\n" + "="*60)
        print("🛑 NETWORK CAPTURE STOPPED")
        print("="*60)
        print(f"Duration: {duration:.1f} seconds")
        print(f"Real packets captured: {self.packet_count}")
        print(f"Suspicious packets detected: {self.suspicious_packets}")
        print(f"Packets saved to database: {self.db_save_counter}")
        print("="*60)
        return True
    
    def _capture_packets(self, interface):
        """Capture and analyze REAL network packets"""
        try:
            print(f"\n📡 Capturing REAL packets on {interface}...")
            print("Press Stop button to end capture")
            print("-"*60)
            
            sniff(
                iface=interface,
                prn=self._analyze_packet,
                store=False,
                stop_filter=lambda x: not self.is_monitoring
            )
        except Exception as e:
            print(f"\n❌ REAL packet capture error: {e}")
            self.is_monitoring = False
    
    def _analyze_packet(self, packet):
        """Analyze individual real packet"""
        try:
            if IP in packet:
                self.packet_count += 1
                self.stats['bytes'] += len(packet)
                
                if TCP in packet:
                    proto_name = 'TCP'
                    self.stats['tcp'] += 1
                    flags = str(packet[TCP].flags)
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                elif UDP in packet:
                    proto_name = 'UDP'
                    self.stats['udp'] += 1
                    flags = '-'
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                elif ICMP in packet:
                    proto_name = 'ICMP'
                    self.stats['icmp'] += 1
                    flags = '-'
                    sport = 0
                    dport = 0
                else:
                    proto_name = 'OTHER'
                    self.stats['other'] += 1
                    flags = '-'
                    sport = 0
                    dport = 0
                
                score = 0.0
                is_suspicious = False
                attack = ''
                
                # AI-based detection if available
                if self.ai_engine:
                    try:
                        features = self.ai_engine.extract_features_from_packet(packet)
                        score, anomaly_score, signature_score = self.ai_engine.hybrid_detection(features)
                        is_suspicious = score > 0.7
                        if is_suspicious:
                            attack = self.ai_engine.get_threat_level(score)
                    except Exception as e:
                        print(f"AI detection error: {e}")
                
                # Signature-based detection
                if not is_suspicious:
                    if dport in self.suspicious_ports:
                        service = self.suspicious_ports[dport]
                        is_suspicious = True
                        score = 0.8
                        attack = f"Suspicious Port: {service}"
                    
                    if len(packet) > 1400 and proto_name == 'UDP':
                        is_suspicious = True
                        score = 0.75
                        attack = "Large UDP packet"
                
                # Get source and destination IPs
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                packet_info = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': proto_name,
                    'src_port': sport,
                    'dst_port': dport,
                    'size': len(packet),
                    'flags': flags,
                    'suspicious': is_suspicious,
                    'score': score,
                    'attack': attack,
                    'service': self.suspicious_ports.get(dport, '')
                }
                
                self.captured_packets.append(packet_info)
                
                self.packet_history.append({
                    'timestamp': time.time(),
                    'count': 1
                })
                
                # Save to database with app context
                self._save_packet_to_db(packet, proto_name, sport, dport, flags, is_suspicious, score)
                
                if is_suspicious:
                    self.suspicious_packets += 1
                    self._create_alert(packet, proto_name, sport, dport, flags, score, attack)
                
                if self.packet_count % 100 == 0:
                    pps = len([p for p in self.packet_history if time.time() - p['timestamp'] < 5]) / 5
                    wifi_info = f" | WiFi: {self.wifi_ssid}" if self.wifi_ssid else ""
                    print(f"📊 Real packets: {self.packet_count} | Suspicious: {self.suspicious_packets} | Rate: {pps:.1f} pps | DB: {self.db_save_counter}{wifi_info}", end='\r')
                    
        except Exception as e:
            print(f"Error analyzing packet: {e}")
    
    def _save_packet_to_db(self, packet, protocol, sport, dport, flags, is_suspicious, score):
        """Save packet to database with proper app context"""
        try:
            def save_impl():
                # Handle different packet types
                if hasattr(packet, 'src'):  # Scapy packet
                    src_ip = packet.src
                    dst_ip = packet.dst
                    size = len(packet)
                    timestamp = datetime.utcnow()
                elif isinstance(packet, dict):  # Dictionary packet
                    src_ip = packet.get('src_ip', '0.0.0.0')
                    dst_ip = packet.get('dst_ip', '0.0.0.0')
                    size = packet.get('size', 0)
                    timestamp = datetime.fromisoformat(packet['timestamp']) if 'timestamp' in packet else datetime.utcnow()
                else:  # Unknown type
                    src_ip = '0.0.0.0'
                    dst_ip = '0.0.0.0'
                    size = 0
                    timestamp = datetime.utcnow()
                
                traffic = NetworkTraffic(
                    timestamp=timestamp,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=protocol,
                    source_port=sport if sport else 0,
                    destination_port=dport if dport else 0,
                    packet_size=size,
                    flags=str(flags) if flags else '',
                    is_suspicious=is_suspicious,
                    anomaly_score=score
                )
                db.session.add(traffic)
                db.session.commit()
                self.db_save_counter += 1
                return True
            
            # Use app context if available
            if self.app_context:
                with self.app_context.app_context():
                    return save_impl()
            else:
                return save_impl()
                
        except Exception as e:
            print(f"Error saving packet to DB: {e}")
            db.session.rollback()
            return False
    
    def save_all_packets_to_db(self):
        """Save all captured packets from memory to database"""
        saved_count = 0
        failed_count = 0
        
        print(f"💾 Saving {len(self.captured_packets)} packets to database...")
        
        def save_impl():
            nonlocal saved_count, failed_count
            for packet in list(self.captured_packets):
                try:
                    timestamp = packet.get('timestamp', datetime.utcnow().isoformat())
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp)
                    
                    traffic = NetworkTraffic(
                        timestamp=timestamp,
                        source_ip=packet.get('src_ip', '0.0.0.0'),
                        destination_ip=packet.get('dst_ip', '0.0.0.0'),
                        protocol=packet.get('protocol', 'TCP'),
                        source_port=packet.get('src_port', 0),
                        destination_port=packet.get('dst_port', 0),
                        packet_size=packet.get('size', 0),
                        flags=packet.get('flags', ''),
                        is_suspicious=packet.get('suspicious', False),
                        anomaly_score=packet.get('score', 0)
                    )
                    db.session.add(traffic)
                    saved_count += 1
                    
                    if saved_count % 100 == 0:
                        db.session.commit()
                        print(f"   Saved {saved_count} packets...")
                        
                except Exception as e:
                    failed_count += 1
                    print(f"Error saving packet: {e}")
            
            db.session.commit()
        
        # Use app context if available
        if self.app_context:
            with self.app_context.app_context():
                save_impl()
        else:
            save_impl()
        
        print(f"✅ Saved {saved_count} packets to database ({failed_count} failed)")
        return saved_count
    
    def _create_alert(self, packet, protocol, sport, dport, flags, score, attack):
        """Create alert for suspicious packet with app context"""
        try:
            def alert_impl():
                if hasattr(packet, 'src'):
                    src_ip = packet.src
                    dst_ip = packet.dst
                    size = len(packet)
                else:
                    src_ip = packet.get('src_ip', 'Unknown')
                    dst_ip = packet.get('dst_ip', 'Unknown')
                    size = packet.get('size', 0)
                
                alert = Alert(
                    alert_type='signature' if 'port' in str(attack).lower() else 'anomaly',
                    severity='high' if score > 0.8 else 'medium',
                    source='network',
                    description=f"Suspicious network activity: {attack or 'Anomaly detected'}",
                    details=f"""
Source: {src_ip}:{sport}
Destination: {dst_ip}:{dport}
Protocol: {protocol}
Size: {size} bytes
Flags: {flags}
Score: {score:.3f}
Attack: {attack}
WiFi Network: {self.wifi_ssid or 'Unknown'}
Interface: {self.current_interface}
Timestamp: {datetime.utcnow().isoformat()}
                    """
                )
                db.session.add(alert)
                db.session.commit()
                
                if broadcast_new_alert:
                    broadcast_new_alert(alert)
                
                if self.alert_manager:
                    self.alert_manager.send_alert(alert)
            
            # Use app context if available
            if self.app_context:
                with self.app_context.app_context():
                    alert_impl()
            else:
                alert_impl()
                
        except Exception as e:
            print(f"Error creating alert: {e}")
            db.session.rollback()
    
    def get_statistics(self):
        """Get network monitoring statistics"""
        duration = 0
        if self.stats['start_time']:
            duration = (datetime.utcnow() - self.stats['start_time']).total_seconds()
        
        current_time = time.time()
        recent_packets = [p for p in self.packet_history if current_time - p['timestamp'] < 5]
        packets_per_second = len(recent_packets) / 5 if recent_packets else 0
        
        bytes_per_second = (self.stats['bytes'] / max(duration, 1)) if duration > 0 else 0
        
        wifi_status = self.get_wifi_status()
        
        return {
            'total_packets': self.packet_count,
            'suspicious_packets': self.suspicious_packets,
            'suspicious_percentage': (self.suspicious_packets / max(self.packet_count, 1)) * 100,
            'tcp_packets': self.stats['tcp'],
            'udp_packets': self.stats['udp'],
            'icmp_packets': self.stats['icmp'],
            'other_packets': self.stats['other'],
            'total_bytes': self.stats['bytes'],
            'packets_per_second': round(packets_per_second, 2),
            'bytes_per_second': round(bytes_per_second, 2),
            'is_monitoring': self.is_monitoring,
            'duration': round(duration, 1),
            'timestamp': datetime.utcnow().isoformat(),
            'db_saved_count': self.db_save_counter,
            'wifi': {
                'connected': wifi_status['connected'],
                'ssid': wifi_status['ssid'],
                'signal': wifi_status['signal'],
                'interface': self.current_interface,
                'ip': self.current_ip
            }
        }
    
    def get_recent_packets(self, limit=50):
        """Get recent packets for display"""
        return list(reversed(list(self.captured_packets)[-limit:]))
    
    def get_chart_data(self):
        """Get data for live chart (last 60 seconds)"""
        current_time = time.time()
        chart_data = []
        
        for i in range(20):
            time_window = current_time - (19 - i) * 3
            count = len([p for p in self.packet_history 
                        if time_window - 3 < p['timestamp'] <= time_window])
            chart_data.append(count)
        
        return chart_data
    
    def get_protocol_details(self):
        """Get detailed protocol counts including port-based services"""
        try:
            from datetime import datetime, timedelta
            from sqlalchemy import func
            
            result = {
                'tcp': 0,
                'udp': 0,
                'icmp': 0,
                'http': 0,
                'https': 0,
                'dns': 0,
                'other': 0
            }
            
            # First try from live captured packets
            if len(self.captured_packets) > 0:
                for packet in self.captured_packets:
                    protocol = packet.get('protocol', '').upper()
                    dst_port = packet.get('dst_port', 0)
                    
                    if protocol == 'TCP':
                        result['tcp'] += 1
                        if dst_port in [80, 8080]:
                            result['http'] += 1
                        elif dst_port in [443, 8443]:
                            result['https'] += 1
                    elif protocol == 'UDP':
                        result['udp'] += 1
                        if dst_port == 53:
                            result['dns'] += 1
                    elif protocol == 'ICMP':
                        result['icmp'] += 1
                    else:
                        result['other'] += 1
                
                return result
            
            # Fallback to database with app context
            def db_query():
                last_hour = datetime.utcnow() - timedelta(hours=1)
                
                protocols = db.session.query(
                    NetworkTraffic.protocol,
                    func.count(NetworkTraffic.id).label('count')
                ).filter(
                    NetworkTraffic.timestamp > last_hour
                ).group_by(
                    NetworkTraffic.protocol
                ).all()
                
                if protocols:
                    for protocol, count in protocols:
                        protocol_upper = protocol.upper() if protocol else 'OTHER'
                        if protocol_upper == 'TCP':
                            result['tcp'] = count
                        elif protocol_upper == 'UDP':
                            result['udp'] = count
                        elif protocol_upper == 'ICMP':
                            result['icmp'] = count
                        else:
                            result['other'] += count
                    
                    result['http'] = NetworkTraffic.query.filter(
                        NetworkTraffic.timestamp > last_hour,
                        NetworkTraffic.protocol == 'TCP',
                        NetworkTraffic.destination_port.in_([80, 8080])
                    ).count()
                    
                    result['https'] = NetworkTraffic.query.filter(
                        NetworkTraffic.timestamp > last_hour,
                        NetworkTraffic.protocol == 'TCP',
                        NetworkTraffic.destination_port.in_([443, 8443])
                    ).count()
                    
                    result['dns'] = NetworkTraffic.query.filter(
                        NetworkTraffic.timestamp > last_hour,
                        NetworkTraffic.protocol == 'UDP',
                        NetworkTraffic.destination_port == 53
                    ).count()
                    
                    return result
                
                return None
            
            if self.app_context:
                with self.app_context.app_context():
                    db_result = db_query()
                    if db_result:
                        return db_result
            else:
                db_result = db_query()
                if db_result:
                    return db_result
            
            # Use current session stats
            if self.packet_count > 0:
                result['tcp'] = self.stats['tcp']
                result['udp'] = self.stats['udp']
                result['icmp'] = self.stats['icmp']
                result['other'] = self.stats['other']
                return result
            
            return result
            
        except Exception as e:
            print(f"Error getting protocol details: {e}")
            return {
                'tcp': 0,
                'udp': 0,
                'icmp': 0,
                'http': 0,
                'https': 0,
                'dns': 0,
                'other': 0
            }
    
    def get_database_packets(self, start_date=None, end_date=None, limit=1000):
        """Get packets from database for reporting"""
        try:
            def query_impl():
                query = NetworkTraffic.query
                
                if start_date:
                    query = query.filter(NetworkTraffic.timestamp >= start_date)
                if end_date:
                    query = query.filter(NetworkTraffic.timestamp <= end_date)
                
                return query.order_by(NetworkTraffic.timestamp.desc()).limit(limit).all()
            
            if self.app_context:
                with self.app_context.app_context():
                    return query_impl()
            else:
                return query_impl()
        except Exception as e:
            print(f"Error getting database packets: {e}")
            return []
    
    def get_database_stats(self, start_date=None, end_date=None):
        """Get statistics from database for reporting"""
        try:
            def query_impl():
                query = NetworkTraffic.query
                
                if start_date:
                    query = query.filter(NetworkTraffic.timestamp >= start_date)
                if end_date:
                    query = query.filter(NetworkTraffic.timestamp <= end_date)
                
                total = query.count()
                suspicious = query.filter_by(is_suspicious=True).count()
                tcp = query.filter_by(protocol='TCP').count()
                udp = query.filter_by(protocol='UDP').count()
                icmp = query.filter_by(protocol='ICMP').count()
                
                return {
                    'total_packets': total,
                    'suspicious_packets': suspicious,
                    'tcp_packets': tcp,
                    'udp_packets': udp,
                    'icmp_packets': icmp,
                    'other_packets': total - (tcp + udp + icmp)
                }
            
            if self.app_context:
                with self.app_context.app_context():
                    return query_impl()
            else:
                return query_impl()
        except Exception as e:
            print(f"Error getting database stats: {e}")
            return {
                'total_packets': 0,
                'suspicious_packets': 0,
                'tcp_packets': 0,
                'udp_packets': 0,
                'icmp_packets': 0,
                'other_packets': 0
            }


# Create global instance
network_monitor = None