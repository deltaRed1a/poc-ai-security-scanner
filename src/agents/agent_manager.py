"""
Agent Manager for coordinating multiple Azure AI Foundry agents
"""
import yaml
from typing import List, Dict, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.agents.foundry_agent import FoundryAgent
from src.tools.code_analyzer import CodeAnalyzerTool, FindingVerifierTool

class AgentManager:
    """Manage multiple Azure AI Foundry agents"""
    
    def __init__(self, config_path: str = "config/agents_config.yaml"):
        self.config = self._load_config(config_path)
        self.agents: List[FoundryAgent] = []
        self._initialize_agents()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load agent configuration"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _initialize_agents(self):
        """Initialize all agents from config"""
        # Prepare tool definitions
        tools = [
            CodeAnalyzerTool.get_tool_definition(),
            FindingVerifierTool.get_tool_definition()
        ]
        
        for agent_config in self.config['agents']:
            agent = FoundryAgent(
                name=agent_config['name'],
                model=agent_config['model'],
                description=agent_config['description'],
                instructions=agent_config['instructions'],
                tools=tools,
                temperature=agent_config.get('temperature', 0.1)
            )
            self.agents.append(agent)
    
    def analyze_code_multi_agent(
        self,
        file_path: str,
        code_content: str,
        language: str,
        analysis_type: str = "security"
    ) -> List[Dict[str, Any]]:
        """
        Analyze code using all agents in parallel
        
        Returns:
            List of results from each agent
        """
        results = []
        
        # Use ThreadPoolExecutor for parallel agent execution
        with ThreadPoolExecutor(max_workers=len(self.agents)) as executor:
            # Submit all agent tasks
            future_to_agent = {
                executor.submit(
                    agent.analyze_code,
                    file_path,
                    code_content,
                    language,
                    analysis_type
                ): agent.name
                for agent in self.agents
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_agent):
                agent_name = future_to_agent[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"✓ {agent_name} completed analysis")
                except Exception as e:
                    print(f"✗ {agent_name} failed: {e}")
                    results.append({
                        "agent": agent_name,
                        "error": str(e),
                        "findings": []
                    })
        
        return results
    
    def cleanup(self):
        """Cleanup all agents"""
        for agent in self.agents:
            try:
                agent.cleanup()
            except Exception as e:
                print(f"Error cleaning up agent: {e}")