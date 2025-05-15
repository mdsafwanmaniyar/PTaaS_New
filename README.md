# Vulnerability Scanner Web

## Overview
This project is a web-based vulnerability scanner that allows users to scan URLs for potential security vulnerabilities. It uses Flask as the web framework and integrates OpenAI's API for generating detailed explanations and recommendations for detected vulnerabilities.

## Features
- Scan URLs for vulnerabilities such as open ports, SQL injection, XSS, and SSL/TLS configuration issues.
- Generate AI-powered explanations and actionable recommendations for detected vulnerabilities.
- Submit user feedback on the scan results.

## Project Structure
- `app.py`: The main Flask application file.
- `requirements.txt`: Lists the Python dependencies required for the project.
- `security_scanner.py`: Script to perform the security scan.
- `Learning/`: Contains additional scripts and feedback data.
- `templates/`: HTML templates for rendering the web pages.
- `flask_env/`: Virtual environment for the project.

## Setup Instructions

### Prerequisites
- Python 3.12 or later
- pip (Python package manager)

### Steps
1. Clone the repository:
   ```
   git clone <repository-url>
   cd vulnerability_scanner_web
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv flask_env
   flask_env\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   - Create a `.env` file in the root directory.
   - Add your OpenAI API key:
     ```
     OPENAI_API_KEY=your_openai_api_key
     ```

5. Run the application:
   ```
   python app.py
   ```

6. Access the application in your browser at `http://127.0.0.1:5000/`.

## Usage
- Enter a URL in the input field to scan for vulnerabilities.
- View the scan results and AI-generated explanations.
- Submit feedback on the scan results.

## Dependencies
- Flask
- OpenAI
- python-dotenv

## Contributing
Feel free to fork the repository and submit pull requests for new features or bug fixes.

## License
This project is licensed under the MIT License.