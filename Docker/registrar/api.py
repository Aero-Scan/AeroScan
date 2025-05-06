from flask import Flask, request, jsonify
import time
import threading
# Add any other necessary imports

# ---> Create the Flask app instance HERE <---
app = Flask(__name__)

# --- Your Global Variables (if any) ---
registered_pis = {}
LOCK = threading.Lock()
TIMEOUT_SECONDS = 600

# --- Define your API routes HERE ---
@app.route('/register', methods=['POST'])
def register_pi():
    data = request.get_json()
    identifier = data.get('identifier')
    ip = data.get('ip')
    port = data.get('port', 8000) # Default exporter port

    if not identifier or not ip:
        return jsonify({"status": "error", "message": "Missing identifier or ip"}), 400

    with LOCK:
        registered_pis[identifier] = {
            "ip": ip,
            "port": port,
            "timestamp": time.time()
        }
    print(f"Registered/Updated Pi: {identifier} at {ip}:{port}")
    return jsonify({"status": "success"}), 200

@app.route('/targets')
def get_targets():
    targets_list = []
    current_time = time.time()

    with LOCK:
        # Filter out stale entries
        active_pis = {
            id: info for id, info in registered_pis.items()
            if current_time - info['timestamp'] < TIMEOUT_SECONDS
        }
        # Update the main dictionary (optional, could just use active_pis)
        # registered_pis.clear()
        # registered_pis.update(active_pis)

        # Format for Prometheus HTTP SD
        for identifier, info in active_pis.items():
            targets_list.append({
                "targets": [f"{info['ip']}:{info['port']}"],
                "labels": {
                    "pi_identifier": identifier,
                    "job": "pi_network_monitor_http_sd" # Label indicating the source
                }
            })
    # print(f"Returning targets: {targets_list}") # Debugging
    return jsonify(targets_list)

# ---> Run the app at the VERY END <---
if __name__ == '__main__':
    # Ensure it binds to 0.0.0.0 to be accessible within the Docker network
    # and potentially from outside if the port is exposed.
    # The internal port is 5000.
    app.run(host='0.0.0.0', port=5000)
