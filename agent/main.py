# agent/main.py
import os
import yaml
import logging
from claude_client import ClaudeClient

logging.basicConfig(
    filename='logs/agent.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# === CONFIG ===
with open('config.yaml') as f:
    config = yaml.safe_load(f)

with open('prompts/system_prompt.txt') as f:
    SYSTEM_PROMPT = f.read()

scope_path = config.get('scope_file', 'scopes/current_scope.md')
if os.path.exists(scope_path):
    with open(scope_path) as f:
        SCOPE = f.read()
else:
    SCOPE = "⚠️ No scope loaded ! Create scopes/current_scope.md"

print("🚀 Phantom - Claude Ethical RedTeam v1.0 (Step 3)")
print(f"Scope actif :\n{SCOPE[:400]}...\n")

client = ClaudeClient(api_key=config['anthropic_api_key'], model=config['model'])

messages = [
    {"role": "user", "content": f"Scope authorized :\n{SCOPE}\n\nStarting mission DEF CON. Thin step by step. Always check the scop before each offensive action."}
]

while True:
    try:
        messages = client.think(
            messages=messages,
            system_prompt=SYSTEM_PROMPT,
            max_tokens=config.get('max_tokens', 8192)
        )
        
        cmd = input("\n[Enter = continue] | tape 'stop' | 'report' | 'cleanup' : ").strip().lower()
        if cmd == "stop":
            print("🛑 Mission complete.")
            break
        elif cmd == "report":
            messages.append({"role": "user", "content": "Generate a complete report of the pentest (Executive Summary + vulnérabilités + PoC + recommandations)."})
        elif cmd == "cleanup":
            messages.append({"role": "user", "content": "Execute cleanup_temp now."})
            
    except KeyboardInterrupt:
        print("\n👋 Bye.")
        break
    except Exception as e:
        logging.error(f"Erreur : {e}")
        print(f"Erreur critique : {e}")
        break
