from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Mock database for devices with sayan9168's encryption key status
connected_devices = {
    "Target_Device_001": {
        "status": "Online", 
        "os": "Android 14", 
        "auth_id": "sayan9168",
        "lock_state": "Active"
    }
}

@app.route('/')
def index():
    return """
    <html>
    <head>
        <title>Sayan's Kernel-X Control Center</title>
        <style>
            body { font-family: sans-serif; text-align: center; background-color: #1a1a1a; color: white; }
            .btn { padding: 15px 25px; font-size: 18px; margin: 10px; cursor: pointer; border-radius: 8px; border: none; }
            .unlock { background-color: #4CAF50; color: white; }
            .shutdown { background-color: #ff0000; color: white; font-weight: bold; width: 80%; height: 60px; }
            .status-box { border: 1px solid #444; padding: 20px; width: 300px; margin: 0 auto; background: #222; }
        </style>
    </head>
    <body>
        <h1>Kernel-X Management Console</h1>
        <div class="status-box">
            <h3>Device: Target_Device_001</h3>
            <p>OS: Android 14 (SDK 34)</p>
            <p>Auth Owner: <b>sayan9168</b></p>
        </div>
        <br>
        <button class="btn unlock" onclick="send_command('unlock')">Bypass Screen Lock</button>
        <br><br>
        <hr style="border: 0.5px solid #444; width: 80%;">
        <br>
        <button class="btn shutdown" onclick="emergency_shutdown()">🚨 EMERGENCY SHUTDOWN (KILL SWITCH)</button>
        
        <script>
        function send_command(cmd) {
            fetch('/execute', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({command: cmd})
            }).then(res => res.json()).then(data => alert(data.status));
        }

        function emergency_shutdown() {
            if(confirm("CRITICAL: This will permanently disable the service on target device. Proceed?")) {
                send_command('kill_switch');
            }
        }
        </script>
    </body>
    </html>
    """

@app.route('/execute', methods=['POST'])
def execute():
    data = request.json
    command = data.get('command')
    
    if command == "unlock":
        return jsonify({"status": "SUCCESS: Kernel Payload sent for Android 12+ Bypass!"})
    
    elif command == "kill_switch":
        # logic to revoke sayan9168's API access and lock the kernel module
        return jsonify({
            "status": "CRITICAL: Kill-Switch Activated! Device services terminated. Contract Revoked."
        })
    
    return jsonify({"status": "Unknown Command"})

if __name__ == '__main__':
    # Running on local server (Access via your phone's browser)
    app.run(host='0.0.0.0', port=5000)
  
