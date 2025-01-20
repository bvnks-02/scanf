import requests
import re

def scan_url(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)
        page_content = response.text

        # List to store detected vulnerabilities
        vulnerabilities = []

        # Check for common XSS vulnerabilities in the page content
        xss_pattern = r"<script[^>]*>alert\('xss'\)</script>"
        xss_matches = re.finditer(xss_pattern, page_content, re.IGNORECASE)
        for match in xss_matches:
            vulnerabilities.append({
                "type": "Cross-Site Scripting (XSS)",
                "description": "Potential XSS vulnerability found in page HTML.",
                "location": f"Line {page_content.count('\n', 0, match.start()) + 1}, Position {match.start()}"
            })

        # Check for HTML injection in the page content
        html_injection_pattern = r"<[A-z\/]+((\s[^>]*)?>|.)+>"
        html_matches = re.finditer(html_injection_pattern, page_content, re.IGNORECASE)
        for match in html_matches:
            vulnerabilities.append({
                "type": "HTML Injection",
                "description": "Potential HTML injection vulnerability found in page content.",
                "location": f"Line {page_content.count('\n', 0, match.start()) + 1}, Position {match.start()}"
            })

        # Check for reflected XSS in the URL
        if "javascript:" in url.lower() or "data:text/html" in url.lower():
            vulnerabilities.append({
                "type": "Reflected Cross-Site Scripting (XSS)",
                "description": "Potential Reflected XSS vulnerability found in URL.",
                "location": "URL Parameter"
            })

        # Check for SQL injection patterns in the URL
        sql_injection_pattern = r"('|\"|--|;|/\*|\*/|@@|@|char|union|select|insert|update|delete|drop|exec)"
        sql_matches = re.finditer(sql_injection_pattern, url, re.IGNORECASE)
        for match in sql_matches:
            vulnerabilities.append({
                "type": "SQL Injection",
                "description": "Potential SQL Injection vulnerability found in URL.",
                "location": f"URL Parameter at Position {match.start()}"
            })

        # Check for sensitive data exposure (e.g., passwords, API keys)
        sensitive_data_pattern = r"(password|api_key|secret)=[^&]+"
        sensitive_matches = re.finditer(sensitive_data_pattern, url, re.IGNORECASE)
        for match in sensitive_matches:
            vulnerabilities.append({
                "type": "Sensitive Data Exposure",
                "description": "Potential sensitive data exposure in URL.",
                "location": f"URL Parameter at Position {match.start()}"
            })

        # Output the results
        if vulnerabilities:
            print(f"\n\033[91mVulnerabilities found for {url}:\033[0m")  # Red color for vulnerabilities
            for vuln in vulnerabilities:
                print(f"\n\033[93mType: {vuln['type']}\033[0m")  # Yellow color for type
                print(f"Description: {vuln['description']}")
                print(f"Location: {vuln['location']}")
        else:
            print(f"\n\033[92mNo vulnerabilities detected for {url}.\033[0m")  # Green color for no vulnerabilities

    except requests.exceptions.RequestException as e:
        print(f"\n\033[91mError scanning {url}: {e}\033[0m")  # Red color for errors

def display_menu():
    print("\n\033[96m=== URL Vulnerability Scanner ===\033[0m")  # Cyan color for menu
    print("1. Scan a URL")
    print("2. Exit")

def main():
    while True:
        display_menu()
        choice = input("\nEnter your choice (1 or 2): ")

        if choice == "1":
            url_to_scan = input("\nEnter the URL to scan: ")
            if not url_to_scan.startswith(("http://", "https://")):
                print("\033[93mWarning: URL should start with 'http://' or 'https://'. Adding 'http://' by default.\033[0m")  # Yellow color for warning
                url_to_scan = "http://" + url_to_scan
            scan_url(url_to_scan)
        elif choice == "2":
            print("\n\033[96mThank you for using the URL Vulnerability Scanner. Goodbye!\033[0m")
            break
        else:
            print("\n\033[91mInvalid choice. Please enter 1 or 2.\033[0m")  # Red color for invalid choice

if __name__ == "__main__":
    main()