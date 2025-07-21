# Snyk and GitLab Security Dashboard Integration

This repository demonstrates how to integrate Snyk Open Source (SCA) and Snyk Code (SAST) security scan results into the GitLab Security Dashboard. This is achieved by converting Snyk's JSON and SARIF outputs into GitLab's native report formats.

## How It Works

The integration uses a GitLab CI/CD pipeline with two separate jobs to automate the process:

### Dependency Scanning (SCA)

1.  **Scan**: The `snyk-sca-scan` job runs `snyk test` to scan your project's dependencies for vulnerabilities, outputting the results to `snyk_data_file.json`.
2.  **Convert**: The `convert-snyk-to-gitlab.py` script processes the Snyk JSON output and converts it into the `gl-dependency-scanning-report.json` format.
3.  **Report**: The CI pipeline uploads the generated file as a `dependency_scanning` report artifact. GitLab ingests this report and displays the findings in the Security Dashboard.

### Static Application Security Testing (SAST)

1.  **Scan**: The `snyk-sast-scan` job runs `snyk code test` to scan your source code, outputting the results to `snyk.sarif`.
2.  **Convert**: The `convert-snyk-sast-to-gitlab.py` script processes the Snyk SARIF output and converts it into the `gl-sast-report.json` format.
3.  **Report**: The CI pipeline uploads the generated file as a `sast` report artifact, which GitLab also ingests into the Security Dashboard.

## Setup Instructions

To use this integration in your own GitLab project, follow these steps:

### 1. Add Files to Your Repository

Copy the following files from this repository into your own project's root directory:

*   `.gitlab-ci.yml`
*   `convert-snyk-to-gitlab.py` (for SCA)
*   `convert-snyk-sast-to-gitlab.py` (for SAST)
*   `.gitignore`

### 2. Get Your Snyk API Token

You need a Snyk API token to allow the CI pipeline to authenticate with Snyk.

1.  Log in to your Snyk account and go to your organization's settings.
2.  Navigate to **Settings > Service accounts**.
3.  Create a new service account with a descriptive name (e.g., `GitLab CI Integration`).
4.  Save the generated credentials.

### 3. Add the Snyk Token to GitLab CI/CD Variables

Store your Snyk token securely in your GitLab project's CI/CD variables.

1.  In your GitLab project, go to **Settings > CI/CD**.
2.  Expand the **Variables** section.
3.  Click **Add variable** and create a new variable:
    *   **Key**: `SNYK_TOKEN`
    *   **Value**: Paste your Snyk API token.
    *   **Protect variable**: Recommended.
    *   **Mask variable**: Recommended.

### 4. Run the Pipeline

Commit and push the new files to your repository. The `snyk-sca-scan` and `snyk-sast-scan` jobs in your pipeline will automatically run. Upon completion, the vulnerability findings from both scans will appear in your GitLab project's **Security & Compliance > Vulnerability Report**.

## Special Thanks

A special thanks to Afik Regev, Staff Solution Engineer at Snyk, for his significant contributions to the scripts in this project.
