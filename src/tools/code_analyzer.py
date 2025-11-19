"""
Code analysis tool for Azure AI Foundry agents
"""
import json
from typing import Dict, Any
import re

class CodeAnalyzerTool:
    """Tool for analyzing code for security vulnerabilities"""
    
    @staticmethod
    def get_tool_definition() -> Dict[str, Any]:
        """Return tool definition for Azure AI Foundry"""
        return {
            "type": "function",
            "function": {
                "name": "analyze_code",
                "description": "Analyze source code for security vulnerabilities and return structured findings",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file being analyzed"
                        },
                        "code_snippet": {
                            "type": "string",
                            "description": "The code snippet to analyze"
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language (python, javascript, java, etc.)"
                        },
                        "analysis_type": {
                            "type": "string",
                            "enum": ["security", "rai", "both"],
                            "description": "Type of analysis to perform"
                        }
                    },
                    "required": ["file_path", "code_snippet", "language", "analysis_type"]
                }
            }
        }
    
    @staticmethod
    def execute(
        file_path: str,
        code_snippet: str,
        language: str,
        analysis_type: str
    ) -> Dict[str, Any]:
        """Execute code analysis and return results"""
        
        # Basic pattern-based detection for POC
        vulnerabilities = []
        
        # SQL Injection patterns
        if language.lower() == "python":
            if re.search(r'execute\s*\(\s*["\'].*%s.*["\'].*%', code_snippet):
                vulnerabilities.append({
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "pattern": "String formatting in SQL query",
                    "line_number": None
                })
            
            # XSS patterns
            if re.search(r'render_template.*\{\{.*\|safe\}\}', code_snippet):
                vulnerabilities.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "pattern": "Unsafe template rendering",
                    "line_number": None
                })
            
            # Hardcoded credentials
            if re.search(r'password\s*=\s*["\'][^"\']+["\']', code_snippet, re.IGNORECASE):
                vulnerabilities.append({
                    "type": "Hardcoded Credentials",
                    "severity": "High",
                    "pattern": "Plaintext password in code",
                    "line_number": None
                })
        
        # RAI-specific checks
        if analysis_type in ["rai", "both"]:
            # Prompt injection patterns
            if re.search(r'openai|anthropic|model\.generate|llm', code_snippet, re.IGNORECASE):
                if not re.search(r'input_validation|sanitize|filter', code_snippet, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "Prompt Injection Risk",
                        "severity": "High",
                        "pattern": "LLM input without validation",
                        "line_number": None,
                        "rai_category": "Safety"
                    })
        
        # Count lines for context
        line_count = len(code_snippet.split('\n'))
        
        return {
            "file_path": file_path,
            "language": language,
            "line_count": line_count,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_complete": True
        }


class FindingVerifierTool:
    """Tool for verifying security findings"""
    
    @staticmethod
    def get_tool_definition() -> Dict[str, Any]:
        """Return tool definition for Azure AI Foundry"""
        return {
            "type": "function",
            "function": {
                "name": "verify_finding",
                "description": "Verify if a security finding is valid and not a false positive",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "finding_description": {
                            "type": "string",
                            "description": "Description of the security finding"
                        },
                        "code_context": {
                            "type": "string",
                            "description": "Code snippet where the issue was found"
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["Critical", "High", "Medium", "Low", "Info"],
                            "description": "Proposed severity level"
                        }
                    },
                    "required": ["finding_description", "code_context", "severity"]
                }
            }
        }
    
    @staticmethod
    def execute(
        finding_description: str,
        code_context: str,
        severity: str
    ) -> Dict[str, Any]:
        """Execute finding verification"""
        
        # Simple verification logic for POC
        is_valid = True
        confidence = 0.85
        
        # Check for common false positive indicators
        if "test" in code_context.lower() or "mock" in code_context.lower():
            is_valid = False
            confidence = 0.3
            reason = "Code appears to be in test/mock context"
        elif "example" in code_context.lower() or "demo" in code_context.lower():
            is_valid = False
            confidence = 0.4
            reason = "Code appears to be example/demo code"
        else:
            reason = "Finding appears valid based on code analysis"
        
        return {
            "is_valid": is_valid,
            "confidence": confidence,
            "reason": reason,
            "recommended_action": "Review manually" if confidence < 0.7 else "Address immediately"
        }