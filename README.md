# Security Toolkit

Security Toolkit is a powerful package that integrates multiple cybersecurity services, including Shodan, URLScan, and VirusTotal. It allows users to investigate URLs, IP addresses, and other digital assets using these services and provides formatted outputs for easy analysis.

## Installation

To install the Toolkit, you need to have Python 3.6 or higher. You can install the package via pip:

```
pip install security-toolkit
```

## Setup

### Environment Variables

Before using the Toolkit, you need to set up the API keys for Shodan, URLScan, and VirusTotal. You can do this by setting the following environment variables:

- `SHODAN_API_KEY`
- `URLSCAN_API_KEY`
- `VIRUSTOTAL_API_KEY`

You can set these variables in your terminal or include them in your `.env` file if you're using a tool like `python-dotenv`.

```
export SHODAN_API_KEY="your_shodan_api_key"
export URLSCAN_API_KEY="your_urlscan_api_key"
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

## Usage

### Investigate URL

The `investigate_url` function integrates the services of URLScan, Shodan, and VirusTotal to provide comprehensive information about a URL.

```
import toolkit

toolkit.investigate_url('http://www.example.com')
```

This function will:
1. Submit the URL to URLScan and fetch the report.
2. Extract the IP address from the URLScan report and fetch information about the IP address from Shodan.
3. Scan the URL with VirusTotal.
4. Print the formatted reports from URLScan, Shodan, and VirusTotal.

### URLScan Module

#### Submit URL Scan Request

```
from toolkit import urlscan

scan_uuid = urlscan.submit_scan_request('http://www.example.com', private=False)
print(scan_uuid)
```

#### Get Report Data

```
report_data = urlscan.get_report_data(scan_uuid)
urlscan.print_report(report_data)
```

### Shodan Module

#### Get IP Information

```
from toolkit import shodan

ip_info = shodan.get_ip_info('8.8.8.8')
shodan.print_info(ip_info)
```

### VirusTotal Module

#### Scan URL

```
from toolkit import virustotal

vt_result = virustotal.scan_url('http://www.example.com')
virustotal.print_object(vt_result)
```

## Contributing

Contributions are welcome. Here are some guidelines to help you get started:

### Setting Up Your Development Environment

1. **Fork the Repository**: Fork the repository on GitHub to your account.
2. **Clone the Repository**: Clone your fork to your local machine.
   ```
   git clone https://github.com/yourusername/toolkit.git
   cd toolkit
   ```
3. **Create a Virtual Environment**: Set up a virtual environment and activate it.
   ```
   python -m venv env
   source env/bin/activate
   ```
4. **Install Dependencies**: Install the necessary dependencies.
   ```
   pip install -r requirements.txt
   ```

### Making Changes

1. **Create a Branch**: Create a new branch for your feature or bug fix.
   ```
   git checkout -b feature/your-feature-name
   ```
2. **Make Your Changes**: Make your changes in the code.
3. **Write Tests**: Write tests for your new feature or bug fix.
4. **Run Tests**: Run tests to make sure everything is working.
   ```
   pytest
   ```

### Submitting Your Changes

1. **Commit Your Changes**: Commit your changes with a meaningful commit message.
   ```
   git add .
   git commit -m "Add your commit message here"
   ```
2. **Push Your Changes**: Push your changes to your fork.
   ```
   git push origin feature/your-feature-name
   ```
3. **Create a Pull Request**: Go to the original repository and create a pull request from your fork.

### Code Style

Please follow PEP 8 guidelines for Python code.

### Reporting Issues

If you encounter any issues or bugs, please report them on the GitHub issues page. Provide as much detail as possible to help us understand and fix the problem.

### Documentation

If you add a new feature, please update this documentation accordingly. Good documentation helps others understand how to use your feature.

## Examples

### Example: Investigating a URL

```
import toolkit

# Investigate a URL
toolkit.investigate_url('http://www.example.com')
```

### Example: Submitting a URL Scan Request and Fetching the Report

```
from toolkit import urlscan

# Submit URL scan request
scan_uuid = urlscan.submit_scan_request('http://www.example.com', private=True)

# Fetch the report data
report_data = urlscan.get_report_data(scan_uuid)
urlscan.print_report(report_data)
```

### Example: Getting Information About an IP Address

```
from toolkit import shodan

# Get information about an IP address
ip_info = shodan.get_ip_info('8.8.8.8')
shodan.print_info(ip_info)
```

### Example: Scanning a URL with VirusTotal

```
from toolkit import virustotal

# Scan a URL with VirusTotal
vt_result = virustotal.scan_url('http://www.example.com')
virustotal.print_object(vt_result)
```
