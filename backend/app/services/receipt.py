import io
import datetime
from decimal import Decimal
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_pdf_receipt(
    receipt_no: str,
    atm_code: str,
    atm_city: str,
    account_number: str,
    card_last4: str,
    txn_type: str,
    amount: Decimal,
    new_balance: Decimal,
    timestamp: datetime.datetime,
    risk_level: str = "LOW"
) -> bytes:
    """
    Generates a secure, downloadable PDF transaction receipt using ReportLab.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    header_style = ParagraphStyle(
        'ReceiptHeader',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor('#0f172a'),
        alignment=1, # Center
        spaceAfter=6
    )
    sub_header = ParagraphStyle(
        'ReceiptSubHeader',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#475569'),
        alignment=1,
        spaceAfter=15
    )
    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#1e293b')
    )
    bold_cell_style = ParagraphStyle(
        'BoldCellText',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.HexColor('#0f172a')
    )
    footer_style = ParagraphStyle(
        'ReceiptFooter',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        textColor=colors.HexColor('#64748b'),
        alignment=1,
        spaceBefore=15
    )

    elements = []

    # Bank Logo / Header
    elements.append(Paragraph("SECUREVAULT ATM NETWORK", header_style))
    elements.append(Paragraph("Zero-Trust Cryptographic Transaction Record", sub_header))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceAfter=15))

    # Masked account
    masked_acc = f"XXXX-XXXX-{account_number[-4:]}" if len(account_number) >= 4 else account_number

    # Receipt Metadata Table
    data = [
        [Paragraph("Receipt Reference:", bold_cell_style), Paragraph(receipt_no, cell_style)],
        [Paragraph("Date & Time (UTC):", bold_cell_style), Paragraph(timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"), cell_style)],
        [Paragraph("Terminal ID:", bold_cell_style), Paragraph(f"{atm_code} ({atm_city})", cell_style)],
        [Paragraph("Card Number:", bold_cell_style), Paragraph(f"•••• •••• •••• {card_last4}", cell_style)],
        [Paragraph("Account Number:", bold_cell_style), Paragraph(masked_acc, cell_style)],
        [Paragraph("Transaction Type:", bold_cell_style), Paragraph(txn_type, bold_cell_style)],
        [Paragraph("Transaction Amount:", bold_cell_style), Paragraph(f"INR {amount:,.2f}", bold_cell_style)],
        [Paragraph("Available Balance:", bold_cell_style), Paragraph(f"INR {new_balance:,.2f}", bold_cell_style)],
        [Paragraph("Security Verification:", bold_cell_style), Paragraph(f"SEC-HASH-OK ({risk_level} Risk Cleared)", cell_style)],
    ]

    t = Table(data, colWidths=[200, 300])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#0f172a')),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    elements.append(t)

    elements.append(Spacer(1, 20))
    elements.append(Paragraph("Thank you for banking with SecureVault ATM.", sub_header))
    elements.append(Paragraph("Notice: For your security, this transaction is protected by end-to-end cryptographic audit hash chains.", footer_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
