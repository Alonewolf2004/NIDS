import sys
sys.stdout.reconfigure(encoding='utf-8')
import os
import signal
import threading
import time
from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3 # <-- ADDED THIS LINE

# Import your NIDS classes
from aintegrated import EnhancedAIIDS, ThreatDatabase, FlowTracker, AIModelManager

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Global instance of the NIDS
nids_instance = None

@app.route('/api/start', methods=['POST'])
def start_nids():
    global nids_instance
    if nids_instance and nids_instance.running:
        return jsonify({'message': 'NIDS is already running'}), 400
    
    config_data = request.json
    
    # Create a NIDSConfig object
    nids_config = NIDSConfig(config_data)
    
    # Start the NIDS initialization in a separate thread
    # This thread will instantiate EnhancedAIIDS and call its start method
    def initialize_and_start_nids():
        global nids_instance
        try:
            app.logger.info("NIDS initialization thread started.")
            # Instantiate EnhancedAIIDS inside the thread
            nids_instance = EnhancedAIIDS(nids_config)
            app.logger.info("EnhancedAIIDS instance created. Starting NIDS...")
            nids_instance.start()
            app.logger.info("NIDS started successfully in background thread.")
        except Exception as e:
            app.logger.error(f"Error starting NIDS in background thread: {e}")
            nids_instance = None # Clear instance on failure

    thread = threading.Thread(target=initialize_and_start_nids, daemon=True)
    thread.start()
    
    # Immediately return a success message to the frontend
    return jsonify({'message': 'NIDS initialization started in background. Check status for readiness.'}), 202 # 202 Accepted

class NIDSConfig:
    """Configuration class for the NIDS instance, populated from API requests."""
    def __init__(self, data):
        self.interface = data.get('interface')
        self.enable_blocking = data.get('enableBlocking', False)
        self.allow_local_blocking = data.get('allowLocalBlocking', False) # New setting for demo
        self.block_duration = data.get('blockDuration', 300)
        self.ai_confidence = data.get('aiConfidence', 0.7) # Expected to be between 0 and 1
        self.db_file = 'ids_database.db' # Consider making this configurable via env var
        self.models_path = 'models/'
        self.signature_file = 'signature.json'

@app.route('/api/stop', methods=['POST'])
def stop_nids():
    global nids_instance
    if nids_instance and nids_instance.running:
        nids_instance.stop()
        nids_instance = None
        return jsonify({'message': 'NIDS stopped successfully'}), 200
    return jsonify({'message': 'NIDS is not running'}), 400

@app.route('/api/restart', methods=['POST'])
def restart_nids_logs():
    """
    Clears all threat logs from the database and resets the statistics
    of the currently running NIDS instance.
    """
    db_file = 'ids_database.db' # Assuming this is the standard DB file
    try:
        # Clear the database table
        conn = sqlite3.connect(db_file, check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM threat_events;')
        # Optional: Reset the autoincrement counter
        cursor.execute('DELETE FROM sqlite_sequence WHERE name="threat_events";')
        conn.commit()
        conn.close()
        app.logger.info("Threat logs have been cleared from the database.")

        # If NIDS is running, reset its internal counters
        if nids_instance and nids_instance.running:
            nids_instance.reset_stats()
            app.logger.info("Live NIDS statistics have been reset.")
        return jsonify({'message': 'NIDS logs and stats cleared successfully'}), 200
    except Exception as e:
        app.logger.error(f"Failed to restart NIDS logs: {e}")
        return jsonify({'message': f'An error occurred: {e}'}), 500

@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    global nids_instance
    if not nids_instance or not nids_instance.running or not nids_instance.network_blocker:
        return jsonify({'message': 'NIDS is not running or blocking is not enabled'}), 400

    data = request.json
    ip_to_unblock = data.get('ip')
    if not ip_to_unblock:
        return jsonify({'message': 'IP address not provided'}), 400

    if nids_instance.network_blocker.unblock_ip(ip_to_unblock):
        return jsonify({'message': f'Successfully unblocked {ip_to_unblock}'}), 200
    return jsonify({'message': f'Failed to unblock {ip_to_unblock}. It might not be blocked or an error occurred.'}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    global nids_instance
    if nids_instance and nids_instance.running:
        stats = {
            'running': True,
            'packet_count': nids_instance.packet_count,
            'flow_count': nids_instance.flow_count,
            'threat_count': nids_instance.threat_count,
            'blocked_ips': list(nids_instance.network_blocker.blocked_ips) if nids_instance.network_blocker else []
        }
        return jsonify(stats), 200
    return jsonify({'running': False}), 200

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    try:
        from scapy.all import get_working_ifaces
        interfaces = [iface.name for iface in get_working_ifaces()]
        return jsonify({'interfaces': interfaces}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# NEW ENDPOINT: Fetch Threat Log data from the database
@app.route('/api/threats', methods=['GET'])
def get_threats():
    threats_list = []
    try:
        # Connect to the SQLite database
        conn = sqlite3.connect(nids_instance.config.db_file if nids_instance else 'ids_database.db', check_same_thread=False)
        cursor = conn.cursor()
        
        # Retrieve all threat events, ordered by timestamp
        cursor.execute('''
            SELECT id, timestamp, source_ip, dest_ip, threat_type, details, blocked, confidence 
            FROM threat_events ORDER BY timestamp DESC
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        
        # Format rows into a list of dictionaries
        for row in rows:
            threats_list.append({
                'id': row[0],
                'timestamp': row[1],
                'source_ip': row[2],
                'dest_ip': row[3],
                'threat_type': row[4],
                'details': row[5],
                'blocked': bool(row[6]),
                'confidence': row[7]
            })
            
    except Exception as e:
        # Log the error but return an empty list to avoid breaking the frontend
        app.logger.error(f"Failed to retrieve threat data: {e}")
        return jsonify({'error': 'Failed to retrieve threat data'}), 500
        
    return jsonify({'threats': threats_list}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5000)