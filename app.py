import sys
sys.stdout.reconfigure(encoding='utf-8')
import os
import signal
import threading
import time
from flask import Flask, jsonify, request
from flask_cors import CORS

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
    
    config = request.json
    
    # Instantiate and start the NIDS in a separate thread
    class Config:
        def __init__(self, data):
            self.interface = data.get('interface')
            self.enable_blocking = data.get('enableBlocking', False)
            self.block_duration = data.get('blockDuration', 300)
            self.ai_confidence = data.get('aiConfidence', 0.7)
            self.db_file = 'ids_database.db'
            self.models_path = 'models/'
            self.signature_file = 'signature.json'

    nids_config = Config(config)
    nids_instance = EnhancedAIIDS(nids_config)
    
    thread = threading.Thread(target=nids_instance.start, daemon=True)
    thread.start()
    
    return jsonify({'message': 'NIDS started successfully'}), 200

@app.route('/api/stop', methods=['POST'])
def stop_nids():
    global nids_instance
    if nids_instance and nids_instance.running:
        nids_instance.stop()
        nids_instance = None
        return jsonify({'message': 'NIDS stopped successfully'}), 200
    return jsonify({'message': 'NIDS is not running'}), 400

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

if __name__ == '__main__':
    app.run(debug=True, port=5000)