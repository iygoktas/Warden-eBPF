import yaml
import os

class RuleEngine:
    def __init__(self, rule_file_path):
        self.rule_file_path = rule_file_path
        self.rules = []

    def load_rules(self):
        if not os.path.exists(self.rule_file_path):
            print(f"[!] Rule file not found: {self.rule_file_path}")
            return False

        with open(self.rule_file_path, 'r') as file:
            data = yaml.safe_load(file)
            if data and "rules" in data:
                self.rules = data["rules"]
                print(f"[*] Successfully loaded {len(self.rules)} rules.")
                return True
            return False

    def analyze_path(self, filepath):
        for rule in self.rules:
            for keyword in rule.get("target_keywords", []):
                if keyword in filepath:
                    return rule.get("action"), rule.get("severity"), rule.get("name")
        return "ALLOW", "INFO", "Safe"

if __name__ == "__main__":
    engine = RuleEngine("../../rules/security_rules.yaml")
    engine.load_rules()
    
    test_path_1 = "/usr/bin/python3"
    test_path_2 = "/host_root/etc/shadow"

    action1, severity1, name1 = engine.analyze_path(test_path_1)
    print(f"Path: {test_path_1} | Action: {action1} | Severity: {severity1}")

    action2, severity2, name2 = engine.analyze_path(test_path_2)
    print(f"Path: {test_path_2} | Action: {action2} | Severity: {severity2} | Rule: {name2}")