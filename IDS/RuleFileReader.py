import os
import json
from Rule import Rule

def read_all_rules(directory: str) -> list :
    """Reads all rule files in the specified directory, validates, and parses them into Rule instances."""
    rules = []
    path_to_files = [f for f in os.listdir(directory) if f.endswith(".json") and f[:-5].isdigit()]

    for filename in path_to_files:
        file_path = os.path.join(directory, filename)
        try:
            with open(file_path, 'r') as file:
                rule_data = json.load(file)
                rules.append(Rule(rule_data))
        except json.JSONDecodeError as e:
            print(f"Error occurred while decoding JSON in {filename}: {e}")
        except FileNotFoundError:
            print(f"The file {filename} was not found.")
        except Exception as e:
            print(f"An error occurred with {filename}: {e}")

    return rules

