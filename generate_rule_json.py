import json
import os
import sys
import requests

from sigma.collection import SigmaCollection
from mitreattack.stix20 import MitreAttackData


def get_mitre_attack_data(url, filename):
    """Downloads the MITRE ATT&CK data file if it doesn't exist."""
    if not os.path.exists(filename):
        print(f"Downloading {filename} from {url}...")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(filename, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print("Download complete.")
    else:
        print(f"{filename} already exists.")
    return filename

def process_sigma_rule(rule, mitre_attack_data):
    """
    Processes a single Sigma rule and returns a dictionary with the required information.
    """
    output_data = {
        'rule_name': rule.title,
        'rule_id': str(rule.id),
        'description': rule.description,
        'mitre_tactics': [],
        'mitre_techniques': [],
        'mitigations': []
    }

    mitigations_found = set()

    for tag in rule.tags:
        if tag.namespace == "attack":
            if tag.name.startswith("t"):
                original_technique_id = "T" + tag.name[1:]
                technique_obj = mitre_attack_data.get_object_by_attack_id(original_technique_id, 'attack-pattern')

                if technique_obj is None:
                    print(f"Warning: [Rule: {rule.title}] Invalid technique ID '{original_technique_id}' found. Skipping.", file=sys.stderr)
                    continue

                if getattr(technique_obj, "revoked", False) or technique_obj.get("x_mitre_deprecated", False):
                    revoking_obj = mitre_attack_data.get_revoking_object(technique_obj.id)
                    if revoking_obj:
                        technique_obj = revoking_obj
                        new_technique_id = mitre_attack_data.get_attack_id(technique_obj.id)
                        print(f"Notice: [Rule: {rule.title}] Deprecated technique ID '{original_technique_id}' was automatically updated to '{new_technique_id}'.")
                    else:
                        print(f"Warning: [Rule: {rule.title}] Deprecated technique ID '{original_technique_id}' found, but no replacement could be determined. Skipping.", file=sys.stderr)
                        continue

                technique_id = mitre_attack_data.get_attack_id(technique_obj.id)
                output_data['mitre_techniques'].append({
                    "id": technique_id,
                    "name": technique_obj.name
                })

                # Get mitigations for the technique
                mitigating_objects = mitre_attack_data.get_mitigations_mitigating_technique(technique_obj.id)
                for item in mitigating_objects:
                    mitigation = item["object"]
                    relationship = item["relationship"]
                    mitigation_id = ""
                    for ref in mitigation.external_references:
                        if ref.source_name == "mitre-attack" or ref.source_name == "mitre-course-of-action":
                            mitigation_id = ref.external_id
                            break

                    # Get the specific description from the relationship, fall back to general description
                    description = relationship.description if hasattr(relationship, "description") and relationship.description else mitigation.description

                    if mitigation_id and mitigation_id not in mitigations_found:
                        output_data['mitigations'].append({
                            "id": mitigation_id,
                            "name": mitigation.name,
                            "description": description,
                        })
                        mitigations_found.add(mitigation_id)
            else:
                output_data['mitre_tactics'].append(tag.name)

    return output_data

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Process Sigma rules and enrich them with MITRE ATT&CK data.")
    parser.add_argument("rules_path", help="Path to the directory containing Sigma rule files.")
    args = parser.parse_args()

    # URL for the Enterprise ATT&CK STIX data
    attack_data_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    attack_data_filename = "enterprise-attack.json"

    # Download the ATT&CK data
    get_mitre_attack_data(attack_data_url, attack_data_filename)

    # Initialize MitreAttackData
    mitre_attack_data = MitreAttackData(attack_data_filename)

    all_results = []

    # Recursively find and process all .yml/.yaml files
    for root, _, files in os.walk(args.rules_path):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        rule_yaml = f.read()
                    # SigmaCollection can contain multiple rule documents in one YAML file
                    rule_collection = SigmaCollection.from_yaml(rule_yaml)
                    for rule in rule_collection:
                        processed_rule = process_sigma_rule(rule, mitre_attack_data)
                        all_results.append(processed_rule)
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}", file=sys.stderr)

    # Print the result as a JSON array
    print(json.dumps(all_results, indent=4))


if __name__ == "__main__":
    main()
