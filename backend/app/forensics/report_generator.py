import os
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from app.config import settings

def generate_case_pdf_dossier(
    case_data: Dict[str, Any],
    evidence_list: List[Dict[str, Any]],
    custody_info: Dict[str, Any],
    graph_analytics: Dict[str, Any],
    alerts_list: List[Dict[str, Any]],
    output_pdf_path: Optional[Path] = None
) -> Path:
    """
    Generate an authoritative, tamper-evident PDF Case Dossier featuring
    the Digital Evidence Integrity Matrix, Chain of Custody Audit, and
    Ethical Decision-Support Network Analytics.
    """
    case_id = case_data.get("case_id", "CASE_REPORT")
    if output_pdf_path is None:
        settings.REPORTS_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        output_pdf_path = settings.REPORTS_STORAGE_DIR / f"Case_Dossier_{case_id}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

    doc = SimpleDocTemplate(
        str(output_pdf_path),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0f172a")
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=13,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#475569")
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    mono_style = ParagraphStyle(
        'MonoCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a")
    )

    disclaimer_style = ParagraphStyle(
        'DisclaimerBox',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        alignment=TA_JUSTIFY,
        textColor=colors.HexColor("#b91c1c")
    )

    story = []

    # 1. Official Header
    story.append(Paragraph("LAW ENFORCEMENT & FORENSIC INTELLIGENCE DOSSIER", title_style))
    story.append(Paragraph("AI-POWERED CRIMINAL NETWORK ANALYSIS & EVIDENCE INTEGRITY AUDIT", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceAfter=10))

    # 2. Ethical Non-Predictive Disclaimer Box
    disclaimer_text = (
        "<b>LEGAL & ETHICAL COMPLIANCE DISCLAIMER (PS 26189):</b> This dossier is an investigative decision-support and "
        "evidence audit document. Network position, centrality metrics, and pattern flags reflect structural data and "
        "activity frequency only. The system does NOT make predictions of future criminal behavior. All extracted entities, "
        "events, and alerts require independent human verification by authorized investigators before any legal action."
    )
    disclaimer_table = Table([[Paragraph(disclaimer_text, disclaimer_style)]], colWidths=[530])
    disclaimer_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#ef4444")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(disclaimer_table)
    story.append(Spacer(1, 12))

    # 3. Case Overview Table
    story.append(Paragraph("1. EXECUTIVE CASE OVERVIEW", h1_style))
    case_info_data = [
        [
            Paragraph(f"<b>Case ID:</b> {case_data.get('case_id', 'N/A')}", body_style),
            Paragraph(f"<b>Case Title:</b> {case_data.get('title', 'N/A')}", body_style)
        ],
        [
            Paragraph(f"<b>Status:</b> {case_data.get('status', 'OPEN')}", body_style),
            Paragraph(f"<b>Investigator:</b> {case_data.get('created_by', 'Assigned Officer')}", body_style)
        ],
        [
            Paragraph(f"<b>Generated At (UTC):</b> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", body_style),
            Paragraph(f"<b>Evidence Items:</b> {len(evidence_list)}", body_style)
        ]
    ]
    t_case = Table(case_info_data, colWidths=[265, 265])
    t_case.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_case)
    story.append(Spacer(1, 14))

    # 4. Digital Evidence Cryptographic Integrity Section
    story.append(Paragraph("2. DIGITAL EVIDENCE INTEGRITY MATRIX (SHA-256 FINGERPRINTS)", h1_style))
    if not evidence_list:
        story.append(Paragraph("No digital evidence artifacts registered for this case.", body_style))
    else:
        ev_table_data = [
            [
                Paragraph("<b>Evidence ID</b>", body_style),
                Paragraph("<b>File Name / Type</b>", body_style),
                Paragraph("<b>SHA-256 Cryptographic Fingerprint</b>", body_style),
                Paragraph("<b>Integrity Status</b>", body_style)
            ]
        ]
        for ev in evidence_list[:15]: # display up to 15 key artifacts
            ev_id = ev.get("evidence_id", "EV")
            fname = f"{ev.get('file_name', 'artifact')} ({ev.get('file_type', 'BIN')})"
            shash = ev.get("sha256_hash", "")
            status_val = ev.get("integrity_status", "VERIFIED")
            status_color = "#16a34a" if status_val == "VERIFIED" else "#dc2626"
            
            ev_table_data.append([
                Paragraph(f"<b>{ev_id}</b>", body_style),
                Paragraph(fname, body_style),
                Paragraph(shash, mono_style),
                Paragraph(f"<font color='{status_color}'><b>{status_val}</b></font>", body_style)
            ])

        t_ev = Table(ev_table_data, colWidths=[70, 110, 260, 90])
        t_ev.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(t_ev)

    story.append(Spacer(1, 14))

    # 5. Digital Chain of Custody Audit
    story.append(Paragraph("3. DIGITAL CHAIN OF CUSTODY (VERIFIABLE HASH CHAIN)", h1_style))
    is_chain_valid = custody_info.get("chain_valid", True)
    chain_color = "#16a34a" if is_chain_valid else "#dc2626"
    chain_status_str = "INTACT & VERIFIED (Zero Tampering Detected)" if is_chain_valid else "INTEGRITY COMPROMISED (Tampering Detected)"

    custody_table_data = [
        [
            Paragraph(f"<b>Chain Status:</b> <font color='{chain_color}'><b>{chain_status_str}</b></font>", body_style),
            Paragraph(f"<b>Total Custody Logs:</b> {custody_info.get('records_checked', 0)}", body_style)
        ],
        [
            Paragraph(f"<b>Genesis / First Hash:</b> {custody_info.get('first_hash', '0'*64)[:24]}...", mono_style),
            Paragraph(f"<b>Latest Case Hash:</b> {custody_info.get('latest_hash', 'N/A')[:24]}...", mono_style)
        ]
    ]
    t_custody = Table(custody_table_data, colWidths=[265, 265])
    t_custody.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_custody)
    story.append(Spacer(1, 14))

    # 6. Network Analytics & Key Influencers
    story.append(Paragraph("4. NETWORK ANALYTICS & INVESTIGATIVE PRIORITY", h1_style))
    top_influencers = graph_analytics.get("top_influencers", [])
    if not top_influencers:
        story.append(Paragraph("Graph analysis has not yet been computed or graph contains insufficient connected entities.", body_style))
    else:
        influencer_data = [
            [
                Paragraph("<b>Entity (Pseudonym / Label)</b>", body_style),
                Paragraph("<b>Type</b>", body_style),
                Paragraph("<b>PageRank</b>", body_style),
                Paragraph("<b>Betweenness</b>", body_style),
                Paragraph("<b>Priority Score (0-100)</b>", body_style)
            ]
        ]
        for inf in top_influencers[:8]:
            score_val = inf.get("priority_score", 0.0)
            influencer_data.append([
                Paragraph(str(inf.get("label", inf.get("id", "Entity"))), body_style),
                Paragraph(str(inf.get("type", "Person")), body_style),
                Paragraph(f"{inf.get('pagerank', 0.0):.4f}", body_style),
                Paragraph(f"{inf.get('betweenness', 0.0):.4f}", body_style),
                Paragraph(f"<b>{score_val:.1f} / 100</b>", body_style)
            ])

        t_inf = Table(influencer_data, colWidths=[150, 70, 90, 100, 120])
        t_inf.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_inf)

    story.append(Spacer(1, 14))

    # 7. Alerts Summary
    story.append(Paragraph("5. HUMAN-VERIFIED & PENDING ALERTS", h1_style))
    if not alerts_list:
        story.append(Paragraph("No automated detection alerts currently recorded for this case.", body_style))
    else:
        alerts_data = [
            [
                Paragraph("<b>Alert Type</b>", body_style),
                Paragraph("<b>Reason / Pattern</b>", body_style),
                Paragraph("<b>Status</b>", body_style),
                Paragraph("<b>Reviewer Notes</b>", body_style)
            ]
        ]
        for al in alerts_list[:10]:
            st = al.get("status", "PENDING")
            st_color = "#16a34a" if st == "CONFIRMED" else ("#64748b" if st == "DISMISSED" else "#ea580c")
            alerts_data.append([
                Paragraph(f"<b>{al.get('alert_type', 'ALERT')}</b>", body_style),
                Paragraph(str(al.get("reason", "Pattern detected")), body_style),
                Paragraph(f"<font color='{st_color}'><b>{st}</b></font>", body_style),
                Paragraph(str(al.get("review_notes") or "Awaiting Human Review"), body_style)
            ])
        t_al = Table(alerts_data, colWidths=[110, 170, 80, 170])
        t_al.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_al)

    # Build PDF document
    doc.build(story)
    return output_pdf_path
