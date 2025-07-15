import json
import datetime

with open("snyk_data_file.json") as f:
    snyk_data = json.load(f)

gitlab_vulns = []

for project in snyk_data.get("vulnerabilities", []):
    vuln_id = project.get("id", "SNYK-UNKNOWN")
    severity = project.get("severity", "medium").capitalize()
    description = project.get("title", "No description")
    identifiers = []

    for id_type, id_list in project.get("identifiers", {}).items():
        for id_value in id_list:
            identifiers.append({
                "type": id_type,
                "name": id_value,
                "value": id_value
            })

    gitlab_vulns.append({
        "id": vuln_id,
        "category": "dependency_scanning",
        "severity": severity,
        "description": description,
        "identifiers": identifiers,
        "location": {
            "file": project.get("from", ["unknown"])[0],
            "dependency": {
                "package": {
                    "name": project.get("packageName", "unknown")
                },
                "version": project.get("version", "unknown")
            }
        }
    })

report = {
    "version": "15.0.6",
    "scan": {
        "analyzer": {
            "id": "snyk",
            "name": "Snyk",
            "vendor": {"name": "Snyk"},
            "version": "1.0.0"
        },
        "scanner": {
            "id": "custom-snyk-scanner",
            "name": "Custom Snyk Scanner",
            "vendor": {"name": "Snyk"},
            "version": "1.0.0"
        },
        "start_time": datetime.datetime.utcnow().isoformat(),
        "end_time": datetime.datetime.utcnow().isoformat(),
        "status": "success",
        "type": "dependency_scanning"
    },
    "vulnerabilities": gitlab_vulns,
    "dependency_files": []
}

with open("gl-dependency-scanning-report.json", "w") as f:
    json.dump(report, f, indent=2)