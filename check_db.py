from models import NetworkTraffic, Alert, HostActivity
from __init__ import db, app
from datetime import datetime, timedelta

with app.app_context():
    print("=" * 60)
    print("DATABASE STATUS REPORT")
    print("=" * 60)
    
    network_count = NetworkTraffic.query.count()
    alert_count = Alert.query.count()
    host_count = HostActivity.query.count()
    
    print(f"\n📊 Network Traffic Records: {network_count}")
    print(f"⚠️ Alert Records: {alert_count}")
    print(f"🖥️ Host Activity Records: {host_count}")
    
    # Check recent records (last 24 hours)
    last_24h = datetime.utcnow() - timedelta(hours=24)
    recent_network = NetworkTraffic.query.filter(NetworkTraffic.timestamp > last_24h).count()
    recent_alerts = Alert.query.filter(Alert.timestamp > last_24h).count()
    recent_host = HostActivity.query.filter(HostActivity.timestamp > last_24h).count()
    
    print(f"\n📈 Last 24 Hours:")
    print(f"   Network Traffic: {recent_network}")
    print(f"   Alerts: {recent_alerts}")
    print(f"   Host Activity: {recent_host}")
    
    # Show sample data if available
    if network_count > 0:
        sample = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).first()
        print(f"\n📦 Sample Network Packet:")
        print(f"   Timestamp: {sample.timestamp}")
        print(f"   Source: {sample.source_ip}:{sample.source_port}")
        print(f"   Destination: {sample.destination_ip}:{sample.destination_port}")
        print(f"   Protocol: {sample.protocol}")
        print(f"   Suspicious: {sample.is_suspicious}")
    
    if alert_count > 0:
        sample = Alert.query.order_by(Alert.timestamp.desc()).first()
        print(f"\n🚨 Sample Alert:")
        print(f"   Timestamp: {sample.timestamp}")
        print(f"   Severity: {sample.severity}")
        print(f"   Description: {sample.description[:100]}")
    
    print("\n" + "=" * 60)
