from datetime import datetime

class Logger:
    @staticmethod
    def log_findings(findings, output_file, context):
        if findings and output_file:
            with open(output_file, "a") as out:
                out.write(f"\n[{datetime.now()}] {context}:\n")
                out.write("\n".join(findings) + "\n") 