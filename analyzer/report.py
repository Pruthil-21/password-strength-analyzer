"""
report.py

Generate PDF reports for password analysis.
"""

from pathlib import Path
from datetime import datetime

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph

from config import Config


def generate_report(result: dict) -> str:
    """
    Generate a PDF report.

    Returns:
        Path to generated PDF.
    """

    reports_dir = Path(Config.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)

    filename = f"password_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    filepath = reports_dir / filename

    doc = SimpleDocTemplate(str(filepath))

    styles = getSampleStyleSheet()

    story = []

    story.append(Paragraph("<b>Password Strength Analysis Report</b>", styles["Title"]))

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %b %Y %H:%M:%S')}",
            styles["Normal"],
        )
    )

    story.append(Paragraph("<br/>", styles["Normal"]))

    story.append(
        Paragraph(f"<b>Strength:</b> {result['strength']}", styles["Normal"])
    )

    story.append(
        Paragraph(f"<b>Entropy:</b> {result['entropy']} bits", styles["Normal"])
    )

    story.append(
        Paragraph(f"<b>Crack Time:</b> {result['crack_time']}", styles["Normal"])
    )

    story.append(
        Paragraph(
            f"<b>Breach Status:</b> {result['breach']}",
            styles["Normal"],
        )
    )

    story.append(Paragraph("<br/>", styles["Normal"]))

    story.append(Paragraph("<b>Suggestions</b>", styles["Heading2"]))

    if result["suggestions"]:
        for suggestion in result["suggestions"]:
            story.append(
                Paragraph(f"• {suggestion}", styles["Normal"])
            )
    else:
        story.append(
            Paragraph("No suggestions. Password is strong.", styles["Normal"])
        )

    doc.build(story)

    return str(filepath)


if __name__ == "__main__":

    sample = {

        "strength": "Strong",

        "entropy": 81.45,

        "crack_time": "centuries",

        "breach": "Not Found",

        "suggestions": [
            "Avoid using the same password across websites."
        ]

    }

    print(generate_report(sample))