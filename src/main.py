"""
POC Main Entry Point
"""
import os
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.agents.agent_manager import AgentManager
from src.consensus.consensus_engine import ConsensusEngine

# Load environment variables
load_dotenv()

console = Console()

# Sample vulnerable code for testing
SAMPLE_CODE = '''
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    """Vulnerable login function"""
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABILITY: SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(query)
    user = cursor.fetchone()
    
    if user:
        # VULNERABILITY: Hardcoded secret key
        secret_key = "hardcoded-secret-1234"
        return f"Welcome {user[1]}"
    
    return "Login failed"

@app.route('/profile/<user_id>')
def profile(user_id):
    """Display user profile"""
    # VULNERABILITY: Missing authorization check
    query = f"SELECT * FROM users WHERE id={user_id}"
    conn = sqlite3.connect('users.db')
    cursor = conn.execute(query)
    user = cursor.fetchone()
    
    # VULNERABILITY: XSS via unsafe rendering
    return render_template('profile.html', user_data=user)
'''

def main():
    """Main POC execution"""
    console.print("\n[bold blue]🔒 AI Security Scanner POC[/bold blue]")
    console.print("[cyan]Using Azure AI Foundry Multi-Agent System[/cyan]\n")
    
    try:
        # Initialize agent manager
        console.print("[yellow]Initializing agents...[/yellow]")
        agent_manager = AgentManager()
        console.print(f"[green]✓ Initialized {len(agent_manager.agents)} agents[/green]\n")
        
        # Display agents
        for agent in agent_manager.agents:
            console.print(f"  • {agent.name} ({agent.model})")
        console.print()
        
        # Analyze sample code
        console.print("[yellow]Starting multi-agent analysis...[/yellow]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing code with all agents...", total=None)
            
            results = agent_manager.analyze_code_multi_agent(
                file_path="app.py",
                code_content=SAMPLE_CODE,
                language="python",
                analysis_type="both"
            )
            
            progress.update(task, completed=True)
        
        console.print("\n[green]✓ Analysis complete[/green]\n")
        
        # Build consensus
        console.print("[yellow]Building consensus...[/yellow]")
        consensus_engine = ConsensusEngine(min_agreement=2)
        consensus_result = consensus_engine.build_consensus(results)
        
        # Generate and display report
        report = consensus_engine.generate_report(consensus_result)
        console.print("\n" + report)
        
        # Save detailed results
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        import json
        with open(output_dir / "consensus_results.json", 'w') as f:
            json.dump(consensus_result, f, indent=2)
        
        with open(output_dir / "report.txt", 'w') as f:
            f.write(report)
        
        console.print(f"\n[green]✓ Results saved to {output_dir}/[/green]")
        
        # Cleanup
        console.print("\n[yellow]Cleaning up agents...[/yellow]")
        agent_manager.cleanup()
        console.print("[green]✓ Cleanup complete[/green]\n")
        
    except Exception as e:
        console.print(f"\n[red]✗ Error: {e}[/red]")
        import traceback
        console.print(traceback.format_exc())

if __name__ == "__main__":
    main()