import os
from datetime import datetime
from fpdf import FPDF
from utils.logger import setup_logger

logger = setup_logger()

class PenTestReport(FPDF):
    """Custom PDF class for penetration testing reports."""
    
    def header(self):
        """Add report header."""
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'WiFi Penetration Test Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        """Add report footer."""
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_report(data, output_path):
    """
    Generate a penetration testing report.
    
    Args:
        data (dict): Report data including scan results and attack outcomes
        output_path (str): Path to save the report
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Determine report format based on file extension
        _, ext = os.path.splitext(output_path)
        
        if ext.lower() == '.pdf':
            return _generate_pdf_report(data, output_path)
        else:  # Default to text report
            return _generate_text_report(data, output_path)

    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise

def _generate_pdf_report(data, output_path):
    """Generate a PDF format report."""
    try:
        pdf = PenTestReport()
        
        # Add title page
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'WiFi Penetration Test Report', 0, 1, 'C')
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        pdf.ln(20)

        # Executive Summary
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Executive Summary', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 10, _generate_executive_summary(data))
        pdf.ln(10)

        # Scan Results
        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Network Scan Results', 0, 1, 'L')
        _add_scan_results(pdf, data.get('scan_results', []))

        # Attack Results
        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Attack Results', 0, 1, 'L')
        _add_attack_results(pdf, data.get('attack_results', []))

        # Recommendations
        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Recommendations', 0, 1, 'L')
        pdf.set_font('Arial', '', 12)
        _add_recommendations(pdf, data)

        # Save the PDF
        pdf.output(output_path)
        logger.info(f"PDF report generated: {output_path}")
        return True

    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        raise

def _generate_text_report(data, output_path):
    """Generate a text format report."""
    try:
        with open(output_path, 'w') as f:
            # Title
            f.write("WiFi Penetration Test Report\n")
            f.write("=" * 30 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Executive Summary
            f.write("Executive Summary\n")
            f.write("-" * 20 + "\n")
            f.write(_generate_executive_summary(data) + "\n\n")

            # Scan Results
            f.write("Network Scan Results\n")
            f.write("-" * 20 + "\n")
            _write_scan_results(f, data.get('scan_results', []))
            f.write("\n")

            # Attack Results
            f.write("Attack Results\n")
            f.write("-" * 20 + "\n")
            _write_attack_results(f, data.get('attack_results', []))
            f.write("\n")

            # Recommendations
            f.write("Recommendations\n")
            f.write("-" * 20 + "\n")
            _write_recommendations(f, data)

        logger.info(f"Text report generated: {output_path}")
        return True

    except Exception as e:
        logger.error(f"Error generating text report: {str(e)}")
        raise

def _generate_executive_summary(data):
    """Generate executive summary text."""
    networks_found = len(data.get('scan_results', []))
    vulnerable_networks = sum(1 for n in data.get('scan_results', [])
                            if n.get('vulnerabilities'))
    
    summary = (
        f"This report summarizes the results of a WiFi network security assessment. "
        f"During the assessment, {networks_found} networks were discovered, "
        f"of which {vulnerable_networks} showed potential vulnerabilities. "
        "The assessment included network discovery, encryption analysis, "
        "and targeted security testing."
    )
    return summary

def _add_scan_results(pdf, results):
    """Add scan results to PDF report."""
    try:
        # Table header
        pdf.set_font('Arial', 'B', 12)
        col_widths = [60, 50, 30, 50]
        pdf.cell(col_widths[0], 10, 'SSID', 1)
        pdf.cell(col_widths[1], 10, 'BSSID', 1)
        pdf.cell(col_widths[2], 10, 'Channel', 1)
        pdf.cell(col_widths[3], 10, 'Security', 1)
        pdf.ln()

        # Table content
        pdf.set_font('Arial', '', 12)
        for network in results:
            pdf.cell(col_widths[0], 10, network.get('ssid', ''), 1)
            pdf.cell(col_widths[1], 10, network.get('bssid', ''), 1)
            pdf.cell(col_widths[2], 10, str(network.get('channel', '')), 1)
            pdf.cell(col_widths[3], 10, network.get('encryption_type', ''), 1)
            pdf.ln()

    except Exception as e:
        logger.error(f"Error adding scan results to PDF: {str(e)}")
        raise

def _write_scan_results(file, results):
    """Write scan results to text report."""
    try:
        file.write("\nDiscovered Networks:\n")
        for network in results:
            file.write(f"\nSSID: {network.get('ssid', '')}\n")
            file.write(f"BSSID: {network.get('bssid', '')}\n")
            file.write(f"Channel: {network.get('channel', '')}\n")
            file.write(f"Security: {network.get('encryption_type', '')}\n")
            file.write("-" * 30 + "\n")

    except Exception as e:
        logger.error(f"Error writing scan results: {str(e)}")
        raise

def _add_attack_results(pdf, results):
    """Add attack results to PDF report."""
    try:
        pdf.set_font('Arial', '', 12)
        for result in results:
            pdf.cell(0, 10, f"Target: {result.get('target', '')}", 0, 1)
            pdf.cell(0, 10, f"Attack Type: {result.get('type', '')}", 0, 1)
            pdf.cell(0, 10, f"Outcome: {result.get('outcome', '')}", 0, 1)
            pdf.ln(5)

    except Exception as e:
        logger.error(f"Error adding attack results to PDF: {str(e)}")
        raise

def _write_attack_results(file, results):
    """Write attack results to text report."""
    try:
        for result in results:
            file.write(f"\nTarget: {result.get('target', '')}\n")
            file.write(f"Attack Type: {result.get('type', '')}\n")
            file.write(f"Outcome: {result.get('outcome', '')}\n")
            file.write("-" * 30 + "\n")

    except Exception as e:
        logger.error(f"Error writing attack results: {str(e)}")
        raise

def _add_recommendations(pdf, data):
    """Add recommendations to PDF report."""
    try:
        recommendations = _generate_recommendations(data)
        for rec in recommendations:
            pdf.cell(0, 10, rec, 0, 1)
            pdf.ln(5)

    except Exception as e:
        logger.error(f"Error adding recommendations to PDF: {str(e)}")
        raise

def _write_recommendations(file, data):
    """Write recommendations to text report."""
    try:
        recommendations = _generate_recommendations(data)
        for rec in recommendations:
            file.write(f"- {rec}\n")

    except Exception as e:
        logger.error(f"Error writing recommendations: {str(e)}")
        raise

def _generate_recommendations(data):
    """Generate security recommendations based on findings."""
    recommendations = [
        "Ensure all networks use WPA2 or WPA3 encryption",
        "Implement strong, unique passwords for all networks",
        "Regularly update firmware on all access points",
        "Monitor for unauthorized access points",
        "Implement network segmentation where possible"
    ]
    
    # Add specific recommendations based on findings
    scan_results = data.get('scan_results', [])
    for network in scan_results:
        if network.get('encryption_type') in ['WEP', 'None']:
            recommendations.append(
                f"Upgrade encryption for network '{network.get('ssid')}' "
                "to WPA2/WPA3"
            )
    
    return recommendations
