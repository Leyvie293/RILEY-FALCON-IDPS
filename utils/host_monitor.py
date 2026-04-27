# utils/host_monitor.py - FIXED VERSION (No alert_triggered field)

"""
Host-Based Intrusion Detection System (HIDS)
Monitors system processes, CPU, memory, disk, and network connections
"""

import psutil
import threading
import time
from datetime import datetime, timedelta
import platform
import subprocess
import re
from collections import deque
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models import HostActivity, Alert, db

# Import broadcast function (will be set by routes)
broadcast_new_alert = None

def set_broadcast_function(func):
    """Set the broadcast function for real-time alerts"""
    global broadcast_new_alert
    broadcast_new_alert = func


class HostMonitor:
    def __init__(self, alert_manager=None):
        self.alert_manager = alert_manager
        self.is_monitoring = False
        self.monitor_thread = None
        self.process_history = deque(maxlen=5000)  # Store process data for reports
        self.system_stats_history = deque(maxlen=1000)
        self.cpu_history = deque(maxlen=60)
        self.memory_history = deque(maxlen=60)
        self.disk_history = deque(maxlen=60)
        self.app_context = None
        self.os_type = platform.system()
        self.hostname = platform.node()
        self.monitoring_interval = 3
        self.last_scan_time = None
        self.total_processes_scanned = 0
        
        # Suspicious process patterns
        self.suspicious_processes = {
            'miner': ['minerd', 'cgminer', 'sgminer', 'bfgminer', 'xmrig', 'claymore', 'ethminer', 
                      'miner', 'mining', 'crypto', 'nicehash'],
            'malware': ['virus', 'trojan', 'ransomware', 'backdoor', 'rootkit', 'malware', 'worm',
                       'mimikatz', 'cobaltstrike'],
            'hacking': ['nmap', 'wireshark', 'tcpdump', 'hydra', 'john', 'aircrack', 'metasploit',
                       'sqlmap', 'nikto'],
            'suspicious': ['powershell -enc', 'cmd /c', 'rundll32', 'regsvr32', 'wscript', 'cscript',
                          'mshta', 'certutil', 'bitsadmin']
        }
        
        # Known safe system processes
        self.safe_processes = [
            'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'spoolsv.exe', 'taskhostw.exe', 'dwm.exe',
            'conhost.exe', 'sihost.exe', 'fontdrvhost.exe', 'runtimebroker.exe',
            'SearchIndexer.exe', 'SecurityHealthService.exe', 'MsMpEng.exe',
            'chrome.exe', 'firefox.exe', 'edge.exe', 'python.exe', 'code.exe',
            'System', 'System Idle Process', 'Registry', 'Memory Compression'
        ]
        
        print(f"🖥️ Host Monitor initialized for {self.hostname} ({self.os_type})")
    
    def set_app_context(self, app):
        """Set Flask app context for database operations in background threads"""
        self.app_context = app
        print("✅ Flask app context set for host monitor")
    
    def start_monitoring(self, interval=3):
        """Start host monitoring in background thread"""
        if self.is_monitoring:
            print("⚠️ Host monitoring already running")
            return True
        
        self.monitoring_interval = interval
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        print(f"✅ Host monitoring started (interval: {interval}s)")
        return True
    
    def stop_monitoring(self):
        """Stop host monitoring"""
        self.is_monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        print("🛑 Host monitoring stopped")
        return True
    
    def _monitor_loop(self):
        """Main monitoring loop running in background thread"""
        scan_count = 0
        while self.is_monitoring:
            try:
                scan_count += 1
                self.last_scan_time = datetime.utcnow()
                
                self._collect_system_stats()
                self._monitor_processes()
                
                self.total_processes_scanned += 1
                
                if scan_count % 10 == 0:
                    print(f"🖥️ Host monitor active: {len(self.process_history)} records in history")
                
                time.sleep(self.monitoring_interval)
            except Exception as e:
                print(f"❌ Error in host monitoring loop: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(5)
    
    def _collect_system_stats(self):
        """Collect system statistics (CPU, Memory, Disk)"""
        try:
            current_time = datetime.utcnow()
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_history.append(cpu_percent)
            
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.memory_history.append(memory_percent)
            
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            self.disk_history.append(disk_percent)
            
            self.system_stats_history.append({
                'timestamp': current_time,
                'type': 'system_stats',
                'cpu': cpu_percent,
                'memory': memory_percent,
                'disk': disk_percent
            })
        except Exception as e:
            print(f"Error collecting system stats: {e}")
    
    def _monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        try:
            suspicious_count = 0
            current_time = datetime.utcnow()
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 
                                             'exe', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    pid = pinfo['pid']
                    name = pinfo['name'] or 'Unknown'
                    cpu = pinfo['cpu_percent'] or 0
                    memory = pinfo['memory_percent'] or 0
                    username = pinfo['username'] or 'Unknown'
                    
                    # Skip system idle process
                    if name == 'System Idle Process' or pid == 0:
                        continue
                    
                    # Check if suspicious
                    is_suspicious = self._is_suspicious_process(name, pinfo.get('cmdline', []))
                    
                    if is_suspicious:
                        suspicious_count += 1
                    
                    # Store in memory history for reports
                    process_record = {
                        'timestamp': current_time,
                        'type': 'process',
                        'process_name': name,
                        'process_id': pid,
                        'user': username,
                        'cpu_usage': round(cpu, 2),
                        'memory_usage': round(memory, 2),
                        'is_suspicious': is_suspicious,
                        'command_line': ' '.join(pinfo.get('cmdline', []))[:200] if pinfo.get('cmdline') else '',
                        'process_path': pinfo.get('exe', '')
                    }
                    
                    self.process_history.append(process_record)
                    
                    # Save to database (only if we have app context)
                    if self.app_context:
                        self._save_activity(pid, name, cpu, memory, username, is_suspicious, 
                                           pinfo.get('cmdline', []), pinfo.get('exe', ''))
                    
                    # Create alert for suspicious processes
                    if is_suspicious and self.app_context:
                        self._create_alert(pid, name, cpu, memory, username, pinfo.get('cmdline', []))
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            if suspicious_count > 0:
                print(f"⚠️ Found {suspicious_count} suspicious processes")
                
        except Exception as e:
            print(f"Error monitoring processes: {e}")
    
    def _is_suspicious_process(self, process_name, cmdline):
        """Check if a process is suspicious"""
        process_lower = process_name.lower()
        
        # Skip safe processes
        if process_name in self.safe_processes:
            return False
        
        # Check against suspicious patterns
        for category, patterns in self.suspicious_processes.items():
            for pattern in patterns:
                if pattern.lower() in process_lower:
                    return True
                
                # Check command line if available
                if cmdline:
                    cmdline_str = ' '.join(cmdline).lower()
                    if pattern.lower() in cmdline_str:
                        return True
        
        return False
    
    def _save_activity(self, pid, process_name, cpu_usage, memory_usage, user, is_suspicious, cmdline, process_path):
        """Save host activity to database with app context"""
        try:
            def save_impl():
                # Get network connections count for this process
                network_connections = 0
                try:
                    proc = psutil.Process(pid)
                    network_connections = len(proc.connections())
                except:
                    pass
                
                # Get parent process info
                parent_pid = 0
                parent_name = ''
                try:
                    proc = psutil.Process(pid)
                    parent = proc.parent()
                    if parent:
                        parent_pid = parent.pid
                        parent_name = parent.name() or ''
                except:
                    pass
                
                # Create activity record - matching your model fields exactly
                activity = HostActivity(
                    timestamp=datetime.utcnow(),
                    hostname=self.hostname,
                    process_name=process_name[:200],
                    process_id=pid,
                    user=user[:50] if user else None,
                    cpu_usage=round(cpu_usage, 2),
                    memory_usage=round(memory_usage, 2),
                    network_connections=network_connections,
                    open_files=0,  # Can be updated if needed
                    is_suspicious=is_suspicious,
                    process_path=process_path[:500] if process_path else None,
                    command_line=cmdline[:500] if cmdline else None,
                    parent_process_id=parent_pid if parent_pid else None,
                    parent_process_name=parent_name[:200] if parent_name else None
                )
                db.session.add(activity)
                db.session.commit()
            
            # Use app context
            with self.app_context.app_context():
                save_impl()
                
        except Exception as e:
            print(f"Error saving host activity: {e}")
            try:
                db.session.rollback()
            except:
                pass
    
    def _create_alert(self, pid, process_name, cpu_usage, memory_usage, user, cmdline):
        """Create alert for suspicious process"""
        try:
            def alert_impl():
                # Determine severity based on resource usage
                if cpu_usage > 90 or memory_usage > 50:
                    severity = 'critical'
                elif cpu_usage > 70 or memory_usage > 30:
                    severity = 'high'
                else:
                    severity = 'medium'
                
                cmdline_str = ' '.join(cmdline) if cmdline else 'N/A'
                
                alert = Alert(
                    alert_type='anomaly',
                    severity=severity,
                    source='host',
                    description=f"Suspicious process detected: {process_name} (PID: {pid})",
                    details=f"""
Process Name: {process_name}
Process ID: {pid}
User: {user}
CPU Usage: {cpu_usage}%
Memory Usage: {memory_usage}%
Command Line: {cmdline_str[:200]}
Host: {self.hostname}
Timestamp: {datetime.utcnow().isoformat()}
                    """
                )
                db.session.add(alert)
                db.session.commit()
                
                # Broadcast alert if function is set
                if broadcast_new_alert:
                    broadcast_new_alert(alert)
                
                # Send to alert manager if available
                if self.alert_manager:
                    self.alert_manager.send_alert(alert)
                
                print(f"🚨 ALERT: Suspicious process {process_name} (PID: {pid}) - CPU: {cpu_usage}% - {severity.upper()}")
            
            with self.app_context.app_context():
                alert_impl()
                
        except Exception as e:
            print(f"Error creating host alert: {e}")
            try:
                db.session.rollback()
            except:
                pass
    
    def get_statistics(self):
        """Get current system statistics"""
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            uptime_days = uptime_seconds // 86400
            uptime_hours = (uptime_seconds % 86400) // 3600
            uptime_minutes = (uptime_seconds % 3600) // 60
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            total_processes = len(list(psutil.process_iter()))
            suspicious_processes = self.get_suspicious_count()
            active_users = len(psutil.users())
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used': memory.used,
                'memory_total': memory.total,
                'disk_percent': disk.percent,
                'disk_used': disk.used,
                'disk_total': disk.total,
                'uptime': f"{int(uptime_days)}d {int(uptime_hours)}h {int(uptime_minutes)}m",
                'total_processes': total_processes,
                'suspicious_processes': suspicious_processes,
                'active_users': active_users,
                'is_monitoring': self.is_monitoring,
                'hostname': self.hostname,
                'os_type': self.os_type,
                'timestamp': datetime.utcnow().isoformat(),
                'cpu_history': list(self.cpu_history)[-20:],
                'memory_history': list(self.memory_history)[-20:],
                'disk_history': list(self.disk_history)[-20:],
                'history_size': len(self.process_history),
                'last_scan': self.last_scan_time.isoformat() if self.last_scan_time else None
            }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_percent': 0,
                'uptime': '0d 0h 0m',
                'total_processes': 0,
                'suspicious_processes': 0,
                'active_users': 0,
                'is_monitoring': self.is_monitoring,
                'hostname': self.hostname,
                'os_type': self.os_type,
                'timestamp': datetime.utcnow().isoformat(),
                'cpu_history': [0] * 20,
                'memory_history': [0] * 20,
                'disk_history': [0] * 20,
                'history_size': 0,
                'last_scan': None
            }
    
    def get_top_processes(self, limit=10, by='cpu'):
        """Get top processes by CPU or memory usage"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
                try:
                    pinfo = proc.info
                    if pinfo['cpu_percent'] > 0 or pinfo['memory_percent'] > 0:
                        processes.append({
                            'process_name': pinfo['name'] or 'Unknown',
                            'process_id': pinfo['pid'],
                            'user': pinfo['username'] or 'Unknown',
                            'cpu_usage': round(pinfo['cpu_percent'] or 0, 2),
                            'memory_usage': round(pinfo['memory_percent'] or 0, 2),
                            'is_suspicious': self._is_suspicious_process(pinfo['name'] or '', [])
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if by == 'cpu':
                processes.sort(key=lambda x: x['cpu_usage'], reverse=True)
            else:
                processes.sort(key=lambda x: x['memory_usage'], reverse=True)
            
            return processes[:limit]
        except Exception as e:
            print(f"Error getting top processes: {e}")
            return []
    
    def get_suspicious_count(self):
        """Get count of currently running suspicious processes"""
        count = 0
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pinfo = proc.info
                    if pinfo['name'] and self._is_suspicious_process(pinfo['name'], pinfo.get('cmdline', [])):
                        count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error counting suspicious processes: {e}")
        return count
    
    def get_process_details(self, pid):
        """Get detailed information about a specific process"""
        try:
            proc = psutil.Process(pid)
            return {
                'pid': pid,
                'name': proc.name() if proc.name() else 'Unknown',
                'user': proc.username() if proc.username() else 'Unknown',
                'cpu_usage': round(proc.cpu_percent(interval=0.1), 2),
                'memory_usage': round(proc.memory_percent(), 2),
                'memory_rss': proc.memory_info().rss if proc.memory_info() else 0,
                'status': proc.status(),
                'threads': proc.num_threads(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat() if proc.create_time() else None,
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'connections': len(proc.connections()),
                'open_files': len(proc.open_files()),
                'is_suspicious': self._is_suspicious_process(proc.name(), proc.cmdline())
            }
        except psutil.NoSuchProcess:
            return {'error': f'Process {pid} not found'}
        except psutil.AccessDenied:
            return {'error': f'Access denied to process {pid}'}
        except Exception as e:
            return {'error': str(e)}
    
    def kill_process(self, pid):
        """Terminate a process (requires admin rights)"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            time.sleep(2)
            if proc.is_running():
                proc.kill()
            
            print(f"✅ Process {proc_name} (PID: {pid}) terminated")
            return True, f"Process {proc_name} (PID: {pid}) terminated successfully"
        except psutil.NoSuchProcess:
            return False, f"Process {pid} not found"
        except psutil.AccessDenied:
            return False, f"Access denied to terminate process {pid}. Run as Administrator."
        except Exception as e:
            return False, f"Error terminating process: {str(e)}"
    
    def kill_suspicious_processes(self):
        """Kill all suspicious processes (requires admin rights)"""
        killed = []
        failed = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pinfo = proc.info
                    if pinfo['name'] and self._is_suspicious_process(pinfo['name'], pinfo.get('cmdline', [])):
                        pid = pinfo['pid']
                        name = pinfo['name']
                        
                        try:
                            proc.terminate()
                            time.sleep(1)
                            if proc.is_running():
                                proc.kill()
                            killed.append({'pid': pid, 'name': name})
                            print(f"✅ Killed suspicious process: {name} (PID: {pid})")
                        except Exception as e:
                            failed.append({'pid': pid, 'name': name, 'error': str(e)})
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'success': True,
                'count': len(killed),
                'killed': killed,
                'failed': failed,
                'message': f"Killed {len(killed)} suspicious processes"
            }
        except Exception as e:
            return {
                'success': False,
                'count': 0,
                'error': str(e)
            }
    
    def get_chart_data(self):
        """Get chart data for real-time updates"""
        return {
            'cpu': list(self.cpu_history)[-20:],
            'memory': list(self.memory_history)[-20:],
            'disk': list(self.disk_history)[-20:]
        }
    
    def get_history_for_reporting(self, start_date, end_date):
        """Get historical process data for reporting"""
        filtered = []
        
        if start_date and hasattr(start_date, 'tzinfo') and start_date.tzinfo:
            start_naive = start_date.replace(tzinfo=None)
        else:
            start_naive = start_date
            
        if end_date and hasattr(end_date, 'tzinfo') and end_date.tzinfo:
            end_naive = end_date.replace(tzinfo=None)
        else:
            end_naive = end_date
        
        for item in self.process_history:
            if isinstance(item, dict) and item.get('type') == 'process':
                timestamp = item.get('timestamp')
                if timestamp:
                    if hasattr(timestamp, 'tzinfo') and timestamp.tzinfo:
                        timestamp = timestamp.replace(tzinfo=None)
                    
                    if start_naive <= timestamp <= end_naive:
                        filtered.append(item)
        
        return filtered


# Create global instance
host_monitor = None