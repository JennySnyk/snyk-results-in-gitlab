import json
import uuid
import datetime

def get_snyk_rule_details(rules, rule_id):
    """Finds a rule by its ID in the list of rules."""
    for rule in rules:
        if rule.get('id') == rule_id:
            return rule
    return {}

def convert_snyk_to_gitlab_sast(snyk_sarif_path, gitlab_sast_path):
    """Converts a Snyk SARIF file to a GitLab SAST report."""
    with open(snyk_sarif_path, 'r') as f:
        snyk_data = json.load(f)

    gitlab_vulns = []
    snyk_rules = snyk_data.get('runs', [{}])[0].get('tool', {}).get('driver', {}).get('rules', [])

    for result in snyk_data.get('runs', [{}])[0].get('results', []):
        rule_id = result.get('ruleId')
        rule_details = get_snyk_rule_details(snyk_rules, rule_id)
        location = result.get('locations', [{}])[0].get('physicalLocation', {})
        artifact_location = location.get('artifactLocation', {})
        region = location.get('region', {})

        # Map Snyk severity to GitLab severity
        snyk_level = result.get('level', 'warning')
        severity_mapping = {
            'error': 'High',
            'warning': 'Medium',
            'note': 'Low'
        }
        severity = severity_mapping.get(snyk_level, 'Unknown')

        cwe_identifiers = []
        for tag in rule_details.get('properties', {}).get('tags', []):
            if 'CWE' in tag:
                cwe_id = tag.split('-')[-1]
                cwe_identifiers.append({
                    "type": "cwe",
                    "name": tag,
                    "value": cwe_id,
                    "url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                })

        gitlab_vuln = {
            "id": str(uuid.uuid4()),
            "category": "sast",
            "name": rule_details.get('name', 'N/A'),
            "message": result.get('message', {}).get('text', 'N/A'),
            "description": rule_details.get('fullDescription', {}).get('text', 'No description available.'),
            "severity": severity,
            "solution": rule_details.get('help', {}).get('text', 'No solution available.'),
            "location": {
                "file": artifact_location.get('uri'),
                "start_line": region.get('startLine'),
                "end_line": region.get('endLine')
            },
            "identifiers": [{
                "type": "snyk",
                "name": f"Snyk-{rule_id}",
                "value": rule_id,
                "url": rule_details.get('helpUri', '')
            }] + cwe_identifiers
        }
        gitlab_vulns.append(gitlab_vuln)

    report = {
        "version": "15.0.6",
        "vulnerabilities": gitlab_vulns,
        "scan": {
            "analyzer": {"id": "snyk", "name": "Snyk", "vendor": {"name": "Snyk"}, "version": "1.0.0"},
            "scanner": {"id": "snyk-code", "name": "Snyk Code", "vendor": {"name": "Snyk"}, "version": "1.0.0"},
            "start_time": datetime.datetime.utcnow().isoformat(),
            "end_time": datetime.datetime.utcnow().isoformat(),
            "status": "success",
            "type": "sast"
        }
    }

    with open(gitlab_sast_path, 'w') as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    convert_snyk_to_gitlab_sast('snyk.sarif', 'gl-sast-report.json')
    print("Successfully converted snyk.sarif to gl-sast-report.json")
