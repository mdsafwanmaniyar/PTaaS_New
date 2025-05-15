import os
import re
import subprocess
import urllib.parse
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import openai
from dotenv import load_dotenv
import json

# Load environment variables from .env file
load_dotenv()  # Load the API key from environment variables
openai.api_key = os.getenv("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")  # Ensure the key is loaded securely

app = Flask(__name__)

# Function to run the security scan using subprocess
def run_security_scan(url):
    decoded_url = urllib.parse.unquote(url)
    parsed_url = urlparse(decoded_url)
    if not parsed_url.scheme:
        decoded_url = 'https://' + decoded_url

    try:
        result = subprocess.run(
            ['python3', 'security_scanner.py', decoded_url, '--all'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except Exception as e:
        return str(e)

# Function to generate AI-powered explanation using OpenAI's API
def generate_ai_explanation(vulnerability_type, details):
    prompt = f"Explain the following vulnerability in detail:\n\n{vulnerability_type}:\n{details}\n\nProvide actionable recommendations to mitigate the issue."

    try:
        response = openai.Completion.create(
            engine="text-davinci-003",  # Use GPT-3.5 or later
            prompt=prompt,
            max_tokens=500,
            temperature=0.7
        )
        return response.choices[0].text.strip()
    except openai.error.AuthenticationError:
        return "Error: OpenAI API key is missing or invalid. Please provide a valid API key."
    except Exception as e:
        return f"Error generating explanation: {e}"

# Function to process scan results and add AI-generated explanations
def process_scan_results(scan_result):
    vulnerabilities = []

    # Check for open ports
    if "Open Ports" in scan_result:
        ports_section = re.search(r"Open Ports: (\[.*\])", scan_result)
        if ports_section:
            open_ports = ports_section.group(1)
            ai_explanation = generate_ai_explanation("Open Ports", f"Open ports found: {open_ports}")
            vulnerabilities.append({
                "type": "Open Ports",
                "details": f"Open ports: {open_ports}",
                "explanation": "Open ports can expose your application to various threats, including unauthorized access. Ports 80 and 443 are typically used for HTTP and HTTPS traffic. While these ports are essential for web communication, they may be vulnerable to attacks such as DoS (Denial of Service), brute force, or exploitation of unpatched vulnerabilities in services running on these ports. Ensuring that these ports are properly secured and monitored is crucial for maintaining the integrity of your system.",
                "fix": "Review open ports and close unnecessary ones. Ensure firewalls are correctly configured to restrict access to only trusted IP addresses. If these ports are in use, ensure that the software running on them is up to date and secure.",
                "likelihood": "Medium. Open ports are a known attack vector, but their actual exploitability depends on the services running behind them and the applied security measures.",
            })

    # Check for SQL Injection
    if "SQL Injection Vulnerable" in scan_result:
        sql_injection_section = re.search(r"SQL Injection Vulnerable: (\w+)", scan_result)
        if sql_injection_section and sql_injection_section.group(1) == "Yes":
            ai_explanation = generate_ai_explanation("SQL Injection", "SQL Injection vulnerability detected. This vulnerability allows attackers to manipulate SQL queries and access sensitive database information.")
            vulnerabilities.append({
                "type": "SQL Injection",
                "details": "SQL Injection vulnerability detected.",
                "explanation": ai_explanation,
                "fix": "Use parameterized queries or prepared statements to safely handle user input. Ensure that input is properly sanitized before being passed into SQL queries."
            })
        else:
            vulnerabilities.append({
                "type": "SQL Injection",
                "details": "No SQL Injection vulnerability detected.",
                "explanation": "No issues found regarding SQL Injection. The application is likely using parameterized queries and proper input validation, which prevent malicious SQL commands from being injected into the database. This is a good sign that your application is properly sanitizing user inputs.",
                "fix": "Continue ensuring that all input handling is secure. Regularly audit database queries and ensure that parameterized queries are being used across all inputs.",
                "likelihood": "None detected. This vulnerability is not present in the current scan.",
            })

    # Check for XSS vulnerability
    if "XSS Vulnerable" in scan_result:
        xss_section = re.search(r"XSS Vulnerable: (\w+)", scan_result)
        if xss_section and xss_section.group(1) == "Yes":
            ai_explanation = generate_ai_explanation("Cross-Site Scripting (XSS)", "XSS vulnerability detected. This vulnerability allows attackers to inject malicious scripts into web pages.")
            vulnerabilities.append({
                "type": "Cross-Site Scripting (XSS)",
                "details": "XSS vulnerability detected.",
                "explanation": ai_explanation,
                "fix": "Maintain strong input sanitization practices. Review your application's client-side code to ensure that user-generated content is properly escaped before being displayed."
            })
        else:
            vulnerabilities.append({
                "type": "Cross-Site Scripting (XSS)",
                "details": "No XSS vulnerability detected.",
                "explanation": "No issues found regarding XSS. The application likely uses proper input sanitization, encoding, and escaping techniques, preventing malicious scripts from being injected into web pages. This is important to protect users from attacks where malicious scripts are executed in their browsers.",
                "fix": "Maintain strong input sanitization practices. Review your application's client-side code to ensure that user-generated content is properly escaped before being displayed.",
                "likelihood": "None detected. This vulnerability is not present in the current scan.",
            })

    # Check for SSL/TLS configuration issues
   # Check for SSL/TLS configuration issues
    if "SSL/TLS Config" in scan_result:  # Check if SSL/TLS section exists
        ssl_section = re.search(r"SSL/TLS Config: (.*)", scan_result)  # Capture everything after "SSL/TLS Config:"
        
        if ssl_section:
            ssl_status = ssl_section.group(1).strip()  # Get the status (e.g., Potential Issues, Secure)
            
            if ssl_status == "Potential Issues":
                ai_explanation = generate_ai_explanation("SSL/TLS Configuration", "Potential issues found in SSL/TLS configuration. This could lead to compromised communication.")
                vulnerabilities.append({
                    "type": "SSL/TLS Configuration",
                    "details": "Potential issues in SSL/TLS configuration.",
                    "explanation": ai_explanation,
                    "fix": "Ensure that SSL/TLS uses strong cipher suites and modern protocols. Regularly update certificates and verify the security of your configurations using tools like SSL Labs.",
                    "likelihood": "Medium. SSL/TLS vulnerabilities can lead to eavesdropping and man-in-the-middle attacks if not properly configured.",
                })
            else:
                vulnerabilities.append({
                    "type": "SSL/TLS Configuration",
                    "details": "SSL/TLS configuration is secure.",
                    "explanation": "The SSL/TLS configuration appears to be secure, meaning that communications between clients and your server are encrypted. Using SSL/TLS with strong cipher suites ensures that data transmitted between the user and your server is protected from eavesdropping and man-in-the-middle attacks. This is essential for securing sensitive data such as login credentials and financial information.",
                    "fix": "Ensure that SSL/TLS is configured to use the latest and most secure protocols (such as TLS 1.2 or 1.3) and disable outdated protocols (e.g., SSL 3.0, TLS 1.0, or TLS 1.1). Regularly audit your SSL/TLS certificates to ensure they are valid and up-to-date.",
                    "likelihood": "Low. SSL/TLS configuration issues are not detected in this case, but periodic reviews are recommended to stay secure against new threats.",
                })
        else:
            print("No SSL/TLS Config information found in scan result.")
        
        return vulnerabilities
    

    # Function to handle feedback
def save_feedback(feedback_data):
    # Read existing feedback data from file
    feedback_file = r'E:\Vulnarabilities\vulnerability_scanner_web\EVulnarabilitiesvulnerability_scanner_webLearningfeedback.json'
    if os.path.exists(feedback_file):
        with open(feedback_file, 'r') as file:
            feedbacks = json.load(file)
    else:
        feedbacks = []

    # Add new feedback
    feedbacks.append(feedback_data)

    # Save the updated feedback data to file
    with open(feedback_file, 'w') as file:
        json.dump(feedbacks, file, indent=4)

    

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    if url:
        raw_scan_result = run_security_scan(url)
        vulnerabilities = process_scan_results(raw_scan_result)
        return render_template('result.html', raw_scan_result=raw_scan_result, vulnerabilities=vulnerabilities)
    else:
        return "Error: No URL provided", 400
    
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    rating = request.form['rating']
    accuracy = request.form['accuracy']
    comments = request.form['comments']

    # Prepare the feedback data
    feedback_data = {
        "rating": rating,
        "accuracy": accuracy,
        "comments": comments
    }

    # Save the feedback to the file
    save_feedback(feedback_data)

    # Render the thank you message in place of the form
    return render_template('thank_you.html', feedback_submitted=True)

if __name__ == '__main__':
    app.run(debug=True)
