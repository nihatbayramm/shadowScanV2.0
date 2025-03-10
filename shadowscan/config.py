import json
import os

class Config:
    DEFAULT_CONFIG = {
        "threads": 4,
        "timeout": 5,
        "extensions": [".txt", ".env", ".yaml", ".json", ".conf"]
    }

    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.config = self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as f:
                return json.load(f)
        return self.DEFAULT_CONFIG

    def get(self, key):
        return self.config.get(key, self.DEFAULT_CONFIG.get(key)) 