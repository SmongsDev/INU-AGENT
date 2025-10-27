import json
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.lib.units import cm
import boto3
import os

# ------------------------
# Cover Page
# ------------------------
def draw_sdg_cover(canvas, doc, event_id="E000", attack_name="UnknownAttack"):
    width, height = A4
    color_blocks = [
        colors.HexColor("#7BC96F"),
        colors.HexColor("#E07BAF"),
        colors.HexColor("#F6C344"),
        colors.HexColor("#24B2D3"),
    ]
    accent_text = colors.HexColor("#24B2D3")
    text_black = colors.HexColor("#000000")

    canvas.setFillColor(colors.white)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)

    block_x = 2.8 * cm
    block_y = height - 6 * cm
    block_width = 0.6 * cm
    block_height = 1.2 * cm
    gap = 0.1 * cm
    for color in color_blocks:
        canvas.setFillColor(color)
        canvas.rect(block_x, block_y, block_width, block_height, fill=1, stroke=0)
        block_y -= (block_height + gap)

    text_start_x = block_x + block_width + 1.4 * cm
    top_y = height - 5.6 * cm

    canvas.setFont("Helvetica-Bold", 22)
    canvas.setFillColor(accent_text)
    canvas.drawString(text_start_x, top_y, f"{event_id}  {attack_name}")

    canvas.setFillColor(text_black)
    canvas.setFont("Helvetica-Bold", 48)
    title_y = height / 2 + 7.1 * cm
    canvas.drawString(text_start_x, title_y, "Security")
    canvas.drawString(text_start_x, title_y - 2 * cm, "Event Report")

    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(colors.HexColor("#E07BAF"))
    canvas.circle(width - 5 * cm, 3 * cm, 0.4 * cm, fill=1, stroke=0)
    canvas.setFillColor(text_black)
    canvas.setFont("Helvetica", 10)
    canvas.drawString(width - 4.3 * cm, 2.9 * cm, "INU Security")


# ------------------------
# Table of Contents
# ------------------------
def draw_table_of_contents(canvas, doc):
    width, height = A4
    canvas.setFillColor(colors.white)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)

    black = colors.HexColor("#000000")
    gray = colors.HexColor("#666666")

    canvas.setFont("Helvetica-Bold", 28)
    canvas.setFillColor(black)
    canvas.drawString(6.8 * cm, height - 7 * cm, "Table of Contents")

    sections = [
        "Basic Information",
        "False Positive Info",
        "Behavior Analysis",
        "Timeline",
        "Mitre Mapping",
        "Recommendations",
    ]

    y_start = height - 10 * cm
    for i, section in enumerate(sections, start=1):
        canvas.setFont("Helvetica-Bold", 18)
        canvas.drawString(6.8 * cm, y_start, str(i))
        canvas.setFont("Helvetica", 14)
        canvas.drawString(8.2 * cm, y_start, section)
        y_start -= 1.3 * cm

    canvas.setFont("Helvetica", 10)
    canvas.setFillColor(gray)
    canvas.drawString(6.8 * cm, 3 * cm, "INU Security | Automated Security Event Report")


# ------------------------
# Confidential Header & Footer
# ------------------------
def draw_confidential(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(40, A4[1] - 30, "CONFIDENTIAL - INTERNAL USE ONLY")
    canvas.restoreState()


def draw_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#777777"))
    y = 25
    canvas.drawRightString(A4[0] - 40, y + 10, "CONFIDENTIAL - INTERNAL USE ONLY")
    canvas.drawRightString(A4[0] - 40, y - 3, "© 2025 INU Security")
    canvas.restoreState()


# ------------------------
# Main Content
# ------------------------
def build_security_report_elements(event_data: dict):
    pdfmetrics.registerFont(UnicodeCIDFont("HYSMyeongJo-Medium"))
    gray_box = colors.HexColor("#F5F5F5")

    styles = getSampleStyleSheet()
    wrap_style = ParagraphStyle(
        "WrapText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=14
    )

    # 기본 정보
    event_id = event_data.get("event_id", "N/A")
    timestamp = event_data.get("timestamp", "N/A")
    source = event_data.get("source", "N/A")
    event_name = event_data.get("event_name", "N/A")
    user_id = event_data.get("user_id", "N/A")
    user_arn = event_data.get("user_arn", "N/A")
    source_ip = event_data.get("source_ip", "N/A")
    user_agent = event_data.get("user_agent", "N/A")
    session_id = event_data.get("session_id", "N/A")
    region = event_data.get("Region", "N/A")
    geolocation = event_data.get("geolocation", "N/A")

    false_positive = event_data.get("false_positive_info", {})
    behavior = event_data.get("behavior", {})
    timeline = event_data.get("Timeline", "N/A")
    mitre_mapping = event_data.get("Mitre Mapping", "N/A")

    # Severity & Accuracy Section
    severity = event_data.get("severity", "N/A").capitalize()
    accuracy = event_data.get("accuracy", "N/A")

    severity_colors = {
        "High": "#FF4D4F",
        "Medium": "#FFD700",
        "Low": "#52C41A"
    }
    severity_color = severity_colors.get(severity, "#000000")

    summary_text = (
        f"This report has a <font color='{severity_color}'><b>{severity}</b></font> severity. "
        f"(<b>{accuracy}</b> accuracy)"
    )

    summary_style = ParagraphStyle(
        "SummaryTitle",
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        alignment=1,
        textColor=colors.black
    )

    elements = [PageBreak(), Paragraph(summary_text, summary_style), Spacer(1, 35)]

    # 표 섹션
    title_style = ParagraphStyle("Title", fontName="Helvetica-Bold", fontSize=15, leading=18)
    sections = [
        ("Basic Information", [
            ["Event ID", event_id],
            ["Timestamp", timestamp],
            ["Source", source],
            ["Event Name", event_name],
            ["User ID", user_id],
            ["User ARN", user_arn],
            ["Source IP", source_ip],
            ["User Agent", user_agent],
            ["Session ID", session_id],
            ["Region", region],
            ["Geolocation", geolocation]
        ]),
        ("False Positive Info", [
            ["FP ID", false_positive.get("fp_id", "N/A")],
            ["Result", false_positive.get("result", "N/A")],
            ["Confidence", false_positive.get("confidence", "N/A")],
            ["Reason", Paragraph(false_positive.get("reason", "N/A"), wrap_style)]
        ]),
        ("Behavior Analysis", [
            ["Unusual Time", "Yes" if behavior.get("unusual_time") else "No"],
            ["New Location", "Yes" if behavior.get("new_location") else "No"]
        ])
    ]

    for title_text, data in sections:
        elements.append(Paragraph(title_text, title_style))
        elements.append(Spacer(1, 18))
        table = Table(data, colWidths=[4 * cm, 10 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#36454F")),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("BOX", (0, 0), (-1, -1), 0.3, colors.gray),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.gray),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        elements.append(table)
        elements.append(Spacer(1, 35))

    # Timeline
    desc_style = ParagraphStyle("DescStyle", fontName="HYSMyeongJo-Medium", fontSize=11.5, leading=15)
    elements.append(Paragraph("Timeline", title_style))
    elements.append(Spacer(1, 18))
    timeline_box = Table([[Paragraph(timeline, desc_style)]], colWidths=[16.2 * cm])
    timeline_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), gray_box),
        ("BOX", (0, 0), (-1, -1), 0.3, colors.gray),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12)
    ]))
    elements.append(timeline_box)
    elements.append(Spacer(1, 35))

    # Mitre Mapping
    elements.append(Paragraph("Mitre Mapping", title_style))
    elements.append(Spacer(1, 18))
    mitre_box = Table([[Paragraph(mitre_mapping, desc_style)]], colWidths=[16.2 * cm])
    mitre_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), gray_box),
        ("BOX", (0, 0), (-1, -1), 0.3, colors.gray),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12)
    ]))
    elements.append(mitre_box)
    elements.append(Spacer(1, 35))

    # Recommendations
    rec_style = ParagraphStyle("RecStyle", fontName="HYSMyeongJo-Medium", fontSize=10.5, leading=14)
    rec_text = (
        f"This event (<b>{event_name}</b>) was detected in <b>{region}</b>. "
        f"Recommended actions:<br/><br/>"
        f"1. Review access logs for <b>{user_id}</b>.<br/>"
        f"2. Validate <b>{source_ip}</b> source legitimacy.<br/>"
        f"3. If false positive: verify FP ID <b>{false_positive.get('fp_id', 'N/A')}</b> result status."
    )

    elements.append(Paragraph("Recommended Actions", title_style))
    elements.append(Spacer(1, 18))
    rec_box = Table([[Paragraph(rec_text, rec_style)]], colWidths=[16.2 * cm])
    rec_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), gray_box),
        ("BOX", (0, 0), (-1, -1), 0.3, colors.gray),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10)
    ]))
    elements.append(rec_box)
    return elements


# ------------------------
# Generate PDF + Upload S3
# ------------------------
def generate_full_pdf(company_name: str, event_data: dict):
    event_id = event_data.get("event_id", "E000")
    attack_name = event_data.get("event_name", "UnknownEvent")

    output_file = f"{event_id}_Security Event Report.pdf"
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    elements = build_security_report_elements(event_data)

    def first_page(canvas, doc):
        draw_sdg_cover(canvas, doc, event_id, attack_name)
        canvas.showPage()
        draw_table_of_contents(canvas, doc)

    doc.build(
        elements,
        onFirstPage=first_page,
        onLaterPages=lambda c, d: (draw_confidential(c, d), draw_footer(c, d))
    )

    print(f"✅ PDF successfully generated: {output_file}")

    # ✅ S3 Upload Section
        # ✅ S3 Upload Section
    try:
        s3 = boto3.client("s3")
        bucket_name = "inu-security-reports-2025"
        date_prefix = datetime.now().strftime("%Y-%m") 
        folder_path = f"{company_name}/{date_prefix}/"  
        s3_key = folder_path + os.path.basename(output_file)

        s3.upload_file(output_file, bucket_name, s3_key)
        print(f"✅ Uploaded to S3: s3://{bucket_name}/{s3_key}")
    except Exception as e:
        print(f"❌ S3 upload failed: {e}")
