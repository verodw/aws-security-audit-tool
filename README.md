# 🛡️ AWS Security Compliance Auditor

An enterprise-grade **Cloud Security Posture Management (CSPM)** tool designed to audit AWS infrastructure against **CIS AWS Foundations Benchmark** controls. 

This application offers a dual-mode architecture: a **Live Mode** for auditing real AWS environments and a **Demo Mode** (powered by `moto`) for risk-free simulations and portfolio demonstration.

<img width="1470" height="799" alt="Screenshot 2025-12-18 at 16 59 08" src="https://github.com/user-attachments/assets/8b3122f2-b089-43f2-8072-3a1d74347753" />
<img width="1470" height="799" alt="Screenshot 2025-12-18 at 17 00 19" src="https://github.com/user-attachments/assets/12313e1d-7d44-45ea-9ac0-29eaefa3054d" />

## Key Features

* **Dual Audit Modes:**
    * **Demo Mode:** Uses `moto` library to mock AWS services (S3, EC2, IAM) for safe, cost-free testing.
    * **Live Mode:** Connects to real AWS accounts using Boto3 to perform actual security assessments.
* **CIS Benchmark Compliance:** Audits against specific controls including:
    * CIS 1.5 (Root MFA)
    * CIS 1.10 (IAM User MFA)
    * CIS 2.1.5 (S3 Public Access)
    * CIS 2.2.1 (EBS Encryption)
    * CIS 5.2 (Security Groups SSH)
* **Automated Reporting:** Exports detailed audit findings in **CSV**, **JSON**, and **Text** formats for compliance documentation.
* **Interactive Dashboard:** Built with **Streamlit** to visualize compliance scores, risk levels, and historical data.
* **Auto-Remediation Simulator:** Demonstrates automated fixing of security vulnerabilities (in Demo Mode).

## Tech Stack

* **Language:** Python 3.10+
* **Cloud SDK:** AWS SDK for Python (Boto3)
* **Interface:** Streamlit
* **Data Processing:** Pandas
* **Testing/Mocking:** Moto

## Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/verodw/aws-security-audit-tool.git](https://github.com/verodw/aws-security-audit-tool.git)
    cd aws-security-audit-tool
    ```

2.  **Create a Virtual Environment (Recommended)**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use: venv\Scripts\activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the application locally using Streamlit:

```bash
streamlit run auditor.py
```
