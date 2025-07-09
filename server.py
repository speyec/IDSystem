from flask import Flask, request
import base64
import json

app = Flask(__name__)

@app.route('/api/<data>', methods=['GET'])
def receive_data(data):
    try:
        decoded = base64.b64decode(data).decode('utf-8')
        parsed = json.loads(decoded)
        print("[RECEIVED DATA]")
        print(json.dumps(parsed, indent=2))
        return "Received", 200
    except Exception as e:
        print(f"Error decoding payload: {e}")
        return "Error", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)  # You must run as root or use port >= 1024
