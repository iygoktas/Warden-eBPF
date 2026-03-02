import os
import signal
import json
from datetime import datetime
from bcc import BPF
from rule_engine import RuleEngine

class Warden:
    def __init__(self):
        self.rule_engine = RuleEngine("../../rules/security_rules.yaml")
        self.rule_engine.load_rules()
        
        with open("../bpf/sensor.c", "r") as f:
            self.bpf_code = f.read()
            
        self.bpf = BPF(text=self.bpf_code)
        self.log_file = "../../logs/alerts.json"
        
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def log_alert(self, event_data):
        with open(self.log_file, "a") as f:
            json.dump(event_data, f)
            f.write("\n")

    def process_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        
        pid = event.pid
        comm = event.comm.decode('utf-8', 'replace')
        fname = event.fname.decode('utf-8', 'replace')
        
        action, severity, rule_name = self.rule_engine.analyze_path(fname)
        
        if action != "ALLOW":
            timestamp = datetime.utcnow().isoformat() + "Z"
            status = "DETECTED"

            print(f"[🚨 {severity}] {action} | Rule: {rule_name}")
            print(f"    Target: PID {pid} ({comm}) tried to open '{fname}'")
            
            if action == "KILL":
                try:
                    os.kill(pid, signal.SIGKILL)
                    status = "MITIGATED"
                    print(f"    [☠️] ACTION TAKEN: PID {pid} has been terminated!")
                except ProcessLookupError:
                    status = "ESCAPED"
                    print(f"    [!] Process {pid} already exited.")
                except PermissionError:
                    status = "FAILED_PERMISSION"
                    print(f"    [!] Need root privileges to kill PID {pid}.")
            
            alert_data = {
                "timestamp": timestamp,
                "rule_name": rule_name,
                "severity": severity,
                "action_required": action,
                "action_taken": status,
                "process_id": pid,
                "command": comm,
                "target_file": fname
            }
            self.log_alert(alert_data)
            
            print("-" * 60)

    def start(self):
        self.bpf["events"].open_perf_buffer(self.process_event)
        print("[*] Warden-eBPF Active. Zero-Trust Mitigation & JSON Logging Enabled...")
        print("-" * 60)
        
        while True:
            try:
                self.bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\n[*] Warden shutting down.")
                exit()

if __name__ == "__main__":
    warden = Warden()
    warden.start()