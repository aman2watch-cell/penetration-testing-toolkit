# 🔍 Web Vulnerability Scanner (Python)

A simple **Python-based web crawler and vulnerability scanner** that detects potential **SQL Injection** and **Cross-Site Scripting (XSS)** vulnerabilities by crawling a target website and testing HTML forms.

---

## ⚠️ Legal Disclaimer
This tool is for **educational and authorized penetration testing only**.  
**Do NOT** use it on websites you do not own or have explicit permission to test.  
Unauthorized scanning is **illegal** and punishable by law.

---

## 📌 Features
- 🔗 Crawls target websites recursively
- 🕵️ Extracts **all internal links**
- 📝 Detects **HTML forms**
- 💉 Tests forms for:
  - **SQL Injection** (`' OR '1'='1` payload)
  - **XSS** (`<script>alert('XSS')</script>` payload)
- 🛠 Lightweight — only requires `requests` & `BeautifulSoup`

---

## 🛠 Requirements
Install dependencies:
```bash
pip install requests beautifulsoup4

