from flask import Flask, render_template, request, jsonify, send_file, session

from config import Config
from analyzer.strength import analyze_password
from analyzer.generator import generate_password
from analyzer.breach import check_password_breach
from analyzer.report import generate_report
from analyzer.database import (
    initialize_database,
    save_password,
    password_exists,
    get_history,
    delete_entry,
    clear_history
)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]

# Create database on startup
initialize_database()


# ==========================================================
# SECURITY HEADERS
# ==========================================================

@app.after_request
def set_secure_headers(response):
    """Attach a small set of defensive headers to every response."""

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/history-page")
def history_page():
    return render_template("history.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True) or {}

    password = data.get("password", "").strip()

    if not password:
        return jsonify({
            "error": "Password is required."
        }), 400

    if len(password) > 256:
        return jsonify({
            "error": "Password exceeds the maximum supported length (256)."
        }), 400

    # Password analysis
    result = analyze_password(password)

    # Check if password was previously used
    result["reuse"] = password_exists(password)

    # Check Have I Been Pwned
    breach = check_password_breach(password)

    if breach.get("error"):

        result["breach"] = "Unavailable"
        is_breached = False

    elif breach["breached"]:

        result["breach"] = f"Found ({breach['count']:,} times)"
        is_breached = True

    else:

        result["breach"] = "Not Found"
        is_breached = False

    # Save scan to history (score and breach status included)
    save_password(
        password=password,
        strength=result["strength"],
        entropy=result["entropy"],
        score=result["score"],
        is_breached=is_breached
    )

    # Save the latest analysis to this user's session (not a shared
    # global) so PDF export pulls back the right result for the right
    # browser session, even with multiple people using the app at once.
    session["last_result"] = result
    session["last_breach"] = breach

    return jsonify(result)


@app.route("/generate", methods=["GET", "POST"])
def generate():

    options = request.get_json(silent=True) or {}

    # Support both GET (defaults, for a simple refresh) and POST (custom
    # options from the generator controls in the UI).
    length = int(options.get("length", app.config.get("DEFAULT_PASSWORD_LENGTH", 16)))
    uppercase = bool(options.get("uppercase", True))
    lowercase = bool(options.get("lowercase", True))
    numbers = bool(options.get("numbers", True))
    symbols = bool(options.get("symbols", True))

    try:

        password = generate_password(
            length=length,
            uppercase=uppercase,
            lowercase=lowercase,
            numbers=numbers,
            symbols=symbols,
        )

    except ValueError as error:

        return jsonify({"error": str(error)}), 400

    return jsonify({
        "password": password
    })


@app.route("/history", methods=["GET"])
def history():

    search = request.args.get("search", "").strip()
    limit = min(int(request.args.get("limit", 100)), 500)

    entries = get_history(limit=limit, search=search or None)

    return jsonify(entries)


@app.route("/history/<int:entry_id>", methods=["DELETE"])
def history_delete(entry_id):

    deleted = delete_entry(entry_id)

    if not deleted:
        return jsonify({"error": "Entry not found."}), 404

    return jsonify({"deleted": True, "id": entry_id})


@app.route("/history", methods=["DELETE"])
def history_clear():

    count = clear_history()

    return jsonify({"cleared": count})


@app.route("/export")
def export():

    result = session.get("last_result")
    breach = session.get("last_breach")

    if result is None:

        return jsonify({
            "error": "Analyze a password first."
        }), 400

    pdf_path = generate_report(result, breach)

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name="password-strength-report.pdf"
    )


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(500)
def server_error(_error):
    return jsonify({"error": "Internal server error."}), 500


if __name__ == "__main__":
    app.run(debug=app.config.get("DEBUG", True))