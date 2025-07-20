
# 🕵️‍♂️ Cloned Website Detector

This is a **Python-based GUI tool** designed to detect and compare potentially cloned or phishing websites by analyzing domain info, SSL certificates, DNS records, content similarity, and external resources.

## 🧰 Features

- Compare two website URLs to determine cloning/similarity
- WHOIS domain info retrieval
- SSL certificate validation
- DNS record resolution
- HTML content similarity analysis
- External JS and resource extraction
- Google Safe Browsing blacklist check
- GUI interface with progress tracking
- PDF report generation

## 🖥️ Technologies Used

- **Python**
- **PyQt5** – for building the GUI
- **BeautifulSoup** – for HTML parsing
- **requests** – for web requests
- **whois** – to fetch domain registration details
- **dns.resolver** – to query DNS records
- **ssl/socket** – to check SSL certificates
- **difflib** – for HTML similarity analysis
- **FPDF** – for PDF export

## 🚀 How to Run

1. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

2. Run the application:
    ```bash
    python cloned_website.py
    ```

## 📤 Exporting Reports

- After a website check, click **"Export Report as PDF"** to save a detailed comparison report.

## 📌 Notes

- Requires an internet connection for DNS, SSL, and blacklist lookups.
- Integrates with the Google Safe Browsing API (you may need your own API key).

## 🛡️ Disclaimer

This tool is intended for **educational and ethical use only**. Do not use it to target or probe websites without permission.

---

Created by [Akash Kumar]
