import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from run.py
from run import app
from models import NetworkTraffic, Alert, HostActivity, User

with app.app_context():
    print("=" * 60)
    print("DATABASE STATUS REPORT")
    print("=" * 60)
    
    network_count = NetworkTraffic.query.count()
    alert_count = Alert.query.count()
    host_count = HostActivity.query.count()
    user_count = User.query.count()
    
    print(f"\n📊 Network Traffic Records: {network_count}")
    print(f"⚠️ Alert Records: {alert_count}")
    print(f"🖥️ Host Activity Records: {host_count}")
    print(f"👤 User Records: {user_count}")
    
    if network_count > 0:
        recent = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).limit(5).all()
        print(f"\n📦 Recent Network Packets (last 5):")
        for pkt in recent:
            print(f"   {pkt.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {pkt.source_ip}:{pkt.source_port} -> {pkt.destination_ip}:{pkt.destination_port}")
    
    if alert_count > 0:
        recent = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
        print(f"\n🚨 Recent Alerts (last 5):")
        for alert in recent:
            print(f"   {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - [{alert.severity}] {alert.description[:60]}")
    
    if network_count == 0 and alert_count == 0 and host_count == 0:
        print("\n⚠️ No data found in database!")
        print("\nTo generate test data, run:")
        print("   python generate_test_data_fixed.py")
    
    print("\n" + "=" * 60)
