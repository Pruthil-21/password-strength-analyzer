"""
report.py

Generate PDF reports for password analysis.
"""

from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from config import Config


# Rating -> color, used for the score row in the summary table.
RATING_COLORS = {
    "Very Weak": colors.HexColor("#dc2626"),
    "Weak": colors.HexColor("#ea580c"),
    "Fair": colors.HexColor("#ca8a04"),
    "Strong": colors.HexColor("#16a34a"),
    "Very Strong": colors.HexColor("#059669"),
}


def generate_report(result: dict, breach: dict = None) -> str:
    """
    Generate a PDF report from an analyze_password() result.

    `result` is expected to be the dict returned by
    analyzer.strength.analyze_password(). `breach` is the dict returned
    by analyzer.breach.check_password_breach() — passed in as its own
    structured argument rather than pre-flattened into a string, so this
    function isn't relying on an untyped, implicit contract with the
    route that calls it.

    Returns:
        Path to the generated PDF, as a string.
    """

    reports_dir = Path(Config.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)

    filename = f"password_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    filepath = reports_dir / filename

    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=LETTER,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#6b7280"),
        spaceAfter=16,
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=13,
        spaceBefore=16,
        spaceAfter=8,
    ))

    story = []

    story.append(Paragraph("Password Strength Analysis Report", styles["Title"]))

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %b %Y %H:%M:%S')}",
            styles["ReportSubtitle"],
        )
    )

    rating = result["strength"]
    rating_color = RATING_COLORS.get(rating, colors.black)

    summary_data = [
        ["Score", f"{result.get('score', 0)} / 100"],
        ["Rating", rating],
        ["Entropy", f"{result['entropy']} bits"],
        ["Crack Time (offline)", result["crack_time"]],
    ]

    summary_table = Table(summary_data, colWidths=[2.2 * inch, 3.8 * inch])

    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (1, 1), (1, 1), rating_color),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#e5e7eb")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f9fafb")),
    ]))

    story.append(summary_table)

    # ------------------------------------------------------------------
    # Breach status
    # ------------------------------------------------------------------

    story.append(Paragraph("Breach Check", styles["SectionHeading"]))

    if breach is None or breach.get("error"):
        breach_text = "Could not be verified against the breach database."

    elif breach.get("breached"):
        breach_text = (
            f"This password has appeared in known data breaches "
            f"approximately {breach['count']:,} time(s). It should be changed immediately."
        )

    else:
        breach_text = "This password was not found in any known data breach corpus."

    story.append(Paragraph(breach_text, styles["Normal"]))

    # ------------------------------------------------------------------
    # Weaknesses
    # ------------------------------------------------------------------

    weaknesses = result.get("weaknesses", [])

    if weaknesses:

        story.append(Paragraph("Weaknesses Identified", styles["SectionHeading"]))

        for item in weaknesses:

            story.append(Paragraph(f"&bull; {item}", styles["Normal"]))
            story.append(Spacer(1, 3))

    # ------------------------------------------------------------------
    # Suggestions
    # ------------------------------------------------------------------

    suggestions = result.get("suggestions", [])

    story.append(Paragraph("Suggestions", styles["SectionHeading"]))

    if suggestions:

        for suggestion in suggestions:

            story.append(Paragraph(f"&bull; {suggestion}", styles["Normal"]))
            story.append(Spacer(1, 3))

    else:

        story.append(Paragraph("No suggestions. Password is strong.", styles["Normal"]))

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "This report does not contain the analyzed password in any form. "
            "Only a SHA-256 hash of it is retained in local scan history.",
            styles["ReportSubtitle"],
        )
    )

    doc.build(story)

    return str(filepath)


if __name__ == "__main__":

    sample_result = {

        "strength": "Strong",

        "score": 82,

        "entropy": 81.45,

        "crack_time": "centuries",

        "weaknesses": [],

        "suggestions": [
            "Avoid using the same password across websites."
        ]

    }

    sample_breach = {

        "breached": False,

        "count": 0

    }

    print(generate_report(sample_result, sample_breach))