import os
from dotenv import load_dotenv

load_dotenv()

print(f'✅ Project: {os.getenv("AZURE_AI_PROJECT_NAME")}')
print(f'✅ Endpoint: {os.getenv("AZURE_AI_PROJECT_ENDPOINT")[:50]}...')
print(f'✅ Models configured: 5')
print(f'✅ DeepSeek Model: {os.getenv("AGENT_DEEPSEEK")}')
print(f'✅ Grok Model: {os.getenv("AGENT_GROK")}')
print(f'✅ GPT-4 Model: {os.getenv("AGENT_GPT4")}')
print(f'✅ GPT-5 Model: {os.getenv("AGENT_GPT5")}')