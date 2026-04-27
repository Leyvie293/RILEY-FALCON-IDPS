# run.py
from __init__ import create_app, socketio

app = create_app()

if __name__ == '__main__':
    print("=" * 50)
    print("Riley Falcon Security Services - IDPS")
    print("Intrusion Detection and Prevention System")
    print("=" * 50)
    print("Starting server...")
    print("Access the application at: http://localhost:5000")
    print("Press CTRL+C to stop")
    print("=" * 50)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)