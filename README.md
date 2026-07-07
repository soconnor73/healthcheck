# CipherTrust Healthcheck Reporter

> Version 2.2.0

An automated diagnostics tool that logs into Thales CipherTrust Manager via `ksctl`, gathers configuration data, analyzes it, and generates a structured, interactive dashboard report.

## Requirements

To run this script, your environment must meet the following requirements:

- **Python 3.x**: The script uses only built-in Python modules (`json`, `subprocess`, `sys`, `datetime`, `os`, `re`, `getpass`), so no external packages are needed.
- **ksctl**: The CipherTrust Manager CLI utility (`ksctl`) must be installed and present in your system's `PATH`.
- **Target CipherTrust Manager Server**: You must have network access and valid credentials (with adequate read permissions) for the CipherTrust Manager instance you wish to check.

## Installation

1. **Clone or download the project files** to your local machine:
   - Ensure `run_healthcheck.py` is in your workspace.
2. **Verify Python installation**:
   ```bash
   python --version
   ```
3. **Verify `ksctl` CLI availability**:
   Ensure `ksctl` is installed and runnable:
   ```bash
   ksctl version
   ```

## Usage

1. Open a terminal/command prompt in the directory containing the script.
2. Run the script:
   ```bash
   python run_healthcheck.py
   ```
3. You will be prompted to enter:
   - **CipherTrust Manager Server URL** (Default: `https://ciphertrust.thalescryptolabs.com`)
   - **Username** (Default: `readonly`)
   - **Password** (required, no default)
4. The script will perform the following actions:
   - Authenticate with the server using `ksctl login`.
   - Run diagnostic collection commands.
   - Save the filtered diagnostics raw data to `healthcheck_data.json`.
   - Generate an interactive dashboard report at `healthcheck_report.html`.

## Outputs

- **`healthcheck_data.json`**: Filtered diagnostics data of interest for compliance.
- **`healthcheck_report.html`**: The interactive web dashboard summarizing the findings.


