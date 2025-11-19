"""
Azure AI Foundry Agent wrapper
"""
import os
import json
from typing import Dict, Any, List, Optional
from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import Agent, AgentThread, MessageRole
from azure.identity import DefaultAzureCredential
import time

class FoundryAgent:
    """Wrapper for Azure AI Foundry Agent"""
    
    def __init__(
        self,
        name: str,
        model: str,
        description: str,
        instructions: str,
        tools: List[Dict[str, Any]],
        temperature: float = 0.1
    ):
        self.name = name
        self.model = model
        self.description = description
        self.instructions = instructions
        self.tools = tools
        self.temperature = temperature
        
        # Initialize Azure AI Foundry client
        project_connection = os.getenv("AZURE_AI_PROJECT_CONNECTION_STRING")
        self.client = AIProjectClient.from_connection_string(
            credential=DefaultAzureCredential(),
            conn_str=project_connection
        )
        
        # Create agent
        self.agent = self._create_agent()
        self.thread = None
    
    def _create_agent(self) -> Agent:
        """Create Azure AI Foundry agent"""
        return self.client.agents.create_agent(
            model=self.model,
            name=self.name,
            instructions=self.instructions,
            tools=self.tools,
            temperature=self.temperature
        )
    
    def create_thread(self) -> str:
        """Create a new conversation thread"""
        self.thread = self.client.agents.create_thread()
        return self.thread.id
    
    def analyze_code(
        self,
        file_path: str,
        code_content: str,
        language: str,
        analysis_type: str = "security"
    ) -> Dict[str, Any]:
        """
        Analyze code using the agent
        
        Args:
            file_path: Path to the file
            code_content: Code to analyze
            language: Programming language
            analysis_type: Type of analysis (security, rai, both)
        
        Returns:
            Analysis results with findings
        """
        if not self.thread:
            self.create_thread()
        
        # Create analysis prompt
        prompt = self._build_analysis_prompt(
            file_path, code_content, language, analysis_type
        )
        
        # Send message to agent
        message = self.client.agents.create_message(
            thread_id=self.thread.id,
            role=MessageRole.USER,
            content=prompt
        )
        
        # Run agent
        run = self.client.agents.create_run(
            thread_id=self.thread.id,
            agent_id=self.agent.id
        )
        
        # Wait for completion
        while run.status in ["queued", "in_progress", "requires_action"]:
            time.sleep(1)
            run = self.client.agents.get_run(
                thread_id=self.thread.id,
                run_id=run.id
            )
            
            # Handle tool calls
            if run.status == "requires_action":
                self._handle_tool_calls(run)
        
        # Get response
        messages = self.client.agents.list_messages(thread_id=self.thread.id)
        
        # Parse response
        assistant_messages = [
            msg for msg in messages.data 
            if msg.role == MessageRole.ASSISTANT
        ]
        
        if assistant_messages:
            response_content = assistant_messages[0].content[0].text.value
            return self._parse_findings(response_content, file_path)
        
        return {"findings": [], "error": "No response from agent"}
    
    def _build_analysis_prompt(
        self,
        file_path: str,
        code_content: str,
        language: str,
        analysis_type: str
    ) -> str:
        """Build analysis prompt for agent"""
        return f"""
Analyze the following {language} code for {'security vulnerabilities' if analysis_type == 'security' else 'RAI risks' if analysis_type == 'rai' else 'security and RAI issues'}.

File: {file_path}
Language: {language}

Code:
```{language}
{code_content}
```

Use the analyze_code tool to perform the analysis, then provide findings in this JSON format:
{{
  "findings": [
    {{
      "finding_description": "Brief description",
      "severity": "Critical|High|Medium|Low",
      "cvss_score": 9.8,
      "cwe": ["CWE-89"],
      "target": {{
        "file_path": "{file_path}",
        "start_line": 10,
        "end_line": 15,
        "code_snippet": "vulnerable code here"
      }},
      "recommendation": {{
        "insecure_snippet": "current code",
        "secure_snippet": "fixed code",
        "rationale": "why this fixes the issue"
      }},
      "confidence": 0.95
    }}
  ]
}}

Return ONLY valid JSON. If no issues found, return {{"findings": []}}.
"""
    
    def _handle_tool_calls(self, run):
        """Handle tool calls from agent"""
        from src.tools.code_analyzer import CodeAnalyzerTool, FindingVerifierTool
        
        tool_outputs = []
        
        for tool_call in run.required_action.submit_tool_outputs.tool_calls:
            if tool_call.function.name == "analyze_code":
                args = json.loads(tool_call.function.arguments)
                result = CodeAnalyzerTool.execute(**args)
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps(result)
                })
            
            elif tool_call.function.name == "verify_finding":
                args = json.loads(tool_call.function.arguments)
                result = FindingVerifierTool.execute(**args)
                tool_outputs.append({
                    "tool_call_id": tool_call.id,
                    "output": json.dumps(result)
                })
        
        # Submit tool outputs
        if tool_outputs:
            self.client.agents.submit_tool_outputs_to_run(
                thread_id=self.thread.id,
                run_id=run.id,
                tool_outputs=tool_outputs
            )
    
    def _parse_findings(self, response: str, file_path: str) -> Dict[str, Any]:
        """Parse findings from agent response"""
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                findings_data = json.loads(json_match.group())
                return {
                    "agent": self.name,
                    "model": self.model,
                    "file_path": file_path,
                    "findings": findings_data.get("findings", [])
                }
        except Exception as e:
            print(f"Error parsing findings: {e}")
        
        return {
            "agent": self.name,
            "model": self.model,
            "file_path": file_path,
            "findings": [],
            "raw_response": response
        }
    
    def cleanup(self):
        """Cleanup agent resources"""
        if self.agent:
            self.client.agents.delete_agent(self.agent.id)