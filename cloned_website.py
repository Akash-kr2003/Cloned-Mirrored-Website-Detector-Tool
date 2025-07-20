import sys
import os
import ssl
import socket
import difflib
import requests
import whois
import dns.resolver
import time
from datetime import datetime
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QMessageBox, QProgressBar
)
from fpdf import FPDF

GOOGLE_API_KEY = "AIzaSyDIdMdFjMVLBTgx1z3c0XtLhDg5tNJH1Ok"

class ClonedWebsiteDetector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cloned Website Detector")
        self.setGeometry(100, 100, 700, 600)

        self.layout = QVBoxLayout()

        self.url_label1 = QLabel("Enter Original Website URL:")
        self.url_input1 = QLineEdit()

        self.url_label2 = QLabel("Enter Suspected Website URL:")
        self.url_input2 = QLineEdit()

        self.check_btn = QPushButton("Check Website")
        self.check_btn.clicked.connect(self.check_website)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)

        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)

        self.export_btn = QPushButton("Export Report as PDF")
        self.export_btn.clicked.connect(self.export_pdf)

        self.layout.addWidget(self.url_label1)
        self.layout.addWidget(self.url_input1)
        self.layout.addWidget(self.url_label2)
        self.layout.addWidget(self.url_input2)
        self.layout.addWidget(self.check_btn)
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(self.result_area)
        self.layout.addWidget(self.export_btn)

        self.setLayout(self.layout)

    def get_domain_info(self, url):
        try:
            domain = url.replace("https://", "").replace("http://", "").split("/")[0]
            info = whois.whois(domain)
            return info
        except Exception:
            return None

    def get_ssl_info(self, url):
        try:
            hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return None

    def get_dns_info(self, url):
        try:
            domain = url.replace("https://", "").replace("http://", "").split("/")[0]
            return dns.resolver.resolve(domain, 'A')
        except Exception:
            return "Could not fetch DNS records"

    def get_page_content(self, url):
        try:
            start = time.time()
            response = requests.get(url, timeout=10)
            load_time = time.time() - start
            return BeautifulSoup(response.text, "html.parser"), load_time
        except Exception:
            return None, None

    def extract_resources(self, soup):
        js_files = [script['src'] for script in soup.find_all('script', src=True)]
        external = [link['href'] for link in soup.find_all('link', href=True)]
        return js_files, external

    def check_blacklist(self, url):
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
            payload = {
                "client": {
                    "clientId": "cloned-site-detector",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [
                        {"url": url}
                    ]
                }
            }
            response = requests.post(api_url, json=payload)
            result = response.json()
            if result.get("matches"):
                return "This website is BLACKLISTED."
            else:
                return "This website is not blacklisted."
        except Exception:
            return "Blacklist check failed."

    def compare_html(self, html1, html2):
        return difflib.SequenceMatcher(None, html1.prettify(), html2.prettify()).ratio() * 100

    def check_website(self):
        url1 = self.url_input1.text().strip()
        url2 = self.url_input2.text().strip()

        if not url1 or not url2:
            QMessageBox.warning(self, "Input Error", "Please enter both URLs.")
            return

        self.progress_bar.setValue(10)

        domain_info1 = self.get_domain_info(url1)
        domain_info2 = self.get_domain_info(url2)
        self.progress_bar.setValue(25)

        ssl_info1 = self.get_ssl_info(url1)
        ssl_info2 = self.get_ssl_info(url2)
        self.progress_bar.setValue(35)

        dns_info1 = self.get_dns_info(url1)
        dns_info2 = self.get_dns_info(url2)
        self.progress_bar.setValue(45)

        soup1, load_time1 = self.get_page_content(url1)
        soup2, load_time2 = self.get_page_content(url2)
        self.progress_bar.setValue(60)

        js1, ext1 = self.extract_resources(soup1)
        js2, ext2 = self.extract_resources(soup2)
        self.progress_bar.setValue(75)

        similarity = self.compare_html(soup1, soup2) if soup1 and soup2 else 0

        blacklist_status1 = self.check_blacklist(url1)
        blacklist_status2 = self.check_blacklist(url2)
        self.progress_bar.setValue(90)

        result = f"Original URL: {url1}\nSuspected URL: {url2}\n\n"
        result += f"Original Domain Info:\n{domain_info1}\n\n"
        result += f"Suspected Domain Info:\n{domain_info2}\n\n"

        result += f"Original SSL: {'VALID' if ssl_info1 else 'INVALID'}\n"
        result += f"Suspected SSL: {'VALID' if ssl_info2 else 'INVALID'}\n\n"

        result += f"Original DNS Records: {dns_info1}\n"
        result += f"Suspected DNS Records: {dns_info2}\n\n"

        result += f"Original JS Files: {js1}\nExternal Resources: {ext1}\n"
        result += f"Suspected JS Files: {js2}\nExternal Resources: {ext2}\n\n"

        result += f"Original Load Time: {load_time1:.2f} seconds\n"
        result += f"Suspected Load Time: {load_time2:.2f} seconds\n\n"

        result += f"HTML Similarity: {similarity:.2f}%\n\n"
        result += f"Original Blacklist Status: {blacklist_status1}\n"
        result += f"Suspected Blacklist Status: {blacklist_status2}\n"

        result += "\n✅ Likely NOT a cloned site." if similarity < 70 else "\n⚠️ WARNING: This might be a CLONED site!"

        self.result_area.setText(result)
        self.last_result = result

        self.progress_bar.setValue(100)

    def export_pdf(self):
        if not hasattr(self, 'last_result'):
            QMessageBox.warning(self, "Export Error", "Run a check before exporting the report.")
            return

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        for line in self.last_result.splitlines():
            pdf.cell(200, 10, txt=line, ln=True)

        if not os.path.exists("reports"):
            os.mkdir("reports")

        report_path = os.path.join("reports", f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        pdf.output(report_path)
        QMessageBox.information(self, "Exported", f"Report saved to {report_path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ClonedWebsiteDetector()
    window.show()
    sys.exit(app.exec_())
