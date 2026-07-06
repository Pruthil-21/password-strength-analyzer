from flask import Flask, render_template, request, jsonify, send_file

from config import Config
from analyzer.strength import analyze_password
from analyzer.generator import generate_password
from analyzer.breach import check_password_breach
from analyzer.report import generate_report
from analyzer.database import (
    initialize_database,
    save_password,
    password_exists,
    get_history
)

app = Flask(__name__)
app.config.from_object(Config)

# Create database on startup
initialize_database()

# Stores last analysis for PDF export
last_result = None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    global last_result

    data = request.get_json()

    password = data.get("password", "").strip()

    if not password:
        return jsonify({
            "error": "Password is required."
        }), 400

    # Password analysis
    result = analyze_password(password)

    # Check if password was previously used
    result["reuse"] = password_exists(password)

    # Save password hash to database
    save_password(
        password=password,
        strength=result["strength"],
        entropy=result["entropy"]
    )

    # Check Have I Been Pwned
    breach = check_password_breach(password)

    if breach.get("error"):

        result["breach"] = "Unavailable"

    elif breach["breached"]:

        result["breach"] = f"Found ({breach['count']:,} times)"

    else:

        result["breach"] = "Not Found"

    # Save latest analysis for PDF export
    last_result = result

    return jsonify(result)


@app.route("/generate")
def generate():

    password = generate_password()

    return jsonify({
        "password": password
    })


@app.route("/history")
def history():

    history = get_history()

    response = []

    for item in history:

        response.append({
            "strength": item[0],
            "entropy": item[1],
            "date": item[2]
        })

    return jsonify(response)


@app.route("/export")
def export():

    global last_result

    if last_result is None:

        return jsonify({
            "error": "Analyze a password first."
        }), 400

    pdf_path = generate_report(last_result)

    return send_file(
        pdf_path,
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)