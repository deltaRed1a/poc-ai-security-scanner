@"
# AI Security Scanner POC

Proof of concept using Azure AI Foundry agents for multi-model security scanning.

## Features

- 🤖 Multi-agent analysis using 4 AI models (DeepSeek, Grok, GPT-4, GPT-5)
- 🔍 Security vulnerability detection (OWASP Top 10)
- 🛡️ Responsible AI assessment (Microsoft RAI Standard)
- 🎯 Consensus-based false positive reduction
- 📊 Detailed reporting with CVSS scores and CWE mappings

## Quick Start

### 1. Setup Environment
``````powershell
# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
``````

### 2. Configure Azure

Your .env file is already configured with:
- Project: ai-scs
- Resource Group: OpenAI
- Region: eastus2

### 3. Run POC
``````powershell
python -m src.main
``````

## Expected Output

The POC will:
1. Initialize 4 AI agents from Azure AI Foundry
2. Analyze sample vulnerable code in parallel
3. Build consensus from all agent findings
4. Generate a detailed security report
5. Save results to ``output/`` folder

## Project Structure
``````
ai-scs/
├── config/
│   └── agents_config.yaml    # Agent configurations
├── src/
│   ├── agents/               # Agent management
│   ├── tools/                # Analysis tools
│   ├── consensus/            # Consensus engine
│   └── main.py               # Entry point
├── tests/                    # Test files
└── output/                   # Generated reports
``````

## Agents

1. **DeepSeek Security Expert** - General vulnerability detection
2. **Grok RAI Assessor** - Responsible AI risks
3. **GPT-4 Security Auditor** - OWASP Top 10 analysis
4. **GPT-5 Advanced Analyst** - Complex threat detection

## Output Files

- ``output/consensus_results.json`` - Detailed findings in JSON
- ``output/report.txt`` - Human-readable report

## Troubleshooting

**Error: "Connection string invalid"**
- Check AZURE_AI_PROJECT_CONNECTION_STRING in .env
- Verify project exists in Azure AI Foundry

**Error: "Model not found"**
- Verify model deployment names in Azure AI Foundry
- Check AGENT_* variables in .env match your deployments

## Next Steps

- [ ] Add GitHub repository scanning
- [ ] Implement PDF report generation
- [ ] Add automated PR creation
- [ ] Integrate with CI/CD pipelines

## License

MIT License - Microsoft Internal Use