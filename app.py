from flask import Flask, jsonify, render_template
from detector import get_alerts
import threading
from packet_sniffer import start_sniffing

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/alerts")
def alerts():
    return jsonify(get_alerts())

if __name__ == "__main__":
    t = threading.Thread(target=start_sniffing)
    t.daemon = True
    t.start()
    app.run(debug=True)
