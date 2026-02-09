from flask import Flask, render_template, request, Response
from webapp.engine import run_full_scan_stream
    

import json

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/scan")
def scan():
    url = request.args.get("url")
    jwt = request.args.get("jwt")

    def event_stream():
        for msg in run_full_scan_stream(url, jwt):
            yield f"data: {msg}\n\n"

    return Response(event_stream(), mimetype="text/event-stream")

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
