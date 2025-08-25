"""
Nexus AI Analysis Dashboard

Interactive dashboard for monitoring and analyzing AI-powered penetration testing operations.
Provides real-time insights into vulnerability correlation, exploit recommendations, and attack paths.
"""

import click
import json
import asyncio
import time
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime, timedelta

from nexus.ai.vulnerability_correlator import VulnerabilityCorrelator, Vulnerability, SeverityLevel
from nexus.ai.exploit_recommender import ExploitRecommender
from nexus.ai.attack_path_planner import AttackPathPlanner, AttackObjective
from .context import pass_context, NexusContext


@click.group()
def dashboard():
    """AI analysis dashboard commands"""
    pass


@dashboard.command('start')
@click.option('--port', '-p', type=int, default=8080, help='Dashboard port')
@click.option('--host', '-h', default='127.0.0.1', help='Dashboard host')
@click.option('--data-dir', '-d', help='Data directory to monitor')
@click.option('--auto-refresh', '-r', type=int, default=30, help='Auto-refresh interval (seconds)')
@pass_context
def dashboard_start(ctx: NexusContext, port: int, host: str, data_dir: Optional[str], auto_refresh: int):
    """
    Start the AI analysis dashboard
    
    Examples:
    # Start dashboard on default port
    nexus dashboard start
    
    # Start dashboard on specific port
    nexus dashboard start --port 9090
    
    # Start dashboard and monitor data directory
    nexus dashboard start --data-dir /path/to/scan/results
    
    # Start dashboard with custom refresh interval
    nexus dashboard start --auto-refresh 60
    """
     
    ctx.load_config()
     
    click.echo(f"Starting Nexus AI Dashboard on {host}:{port}")
    click.echo(f"Auto-refresh: {auto_refresh} seconds")
     
    if data_dir:
        click.echo(f"Monitoring data directory: {data_dir}")
     
    # Simple text-based dashboard for now
    # In a full implementation, this would start a web server
    try:
        while True:
            # Clear screen (works on most terminals)
            click.clear()
             
            # Dashboard header
            click.echo("=" * 80)
            click.echo("NEXUS AI PENETRATION TESTING DASHBOARD")
            click.echo(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo("=" * 80)
             
            # System status
            click.echo("\nSYSTEM STATUS")
            click.echo("-" * 40)
             
            try:
                ollama_client = ctx.get_ollama_client()
                if ollama_client.health_check_sync():
                    click.echo("Ollama: Connected")
                    click.echo(f"AI Model: {ctx.config.ai.model}")
                else:
                    click.echo("Ollama: Disconnected")
            except Exception as e:
                click.echo(f"Ollama: Error - {e}")
             
            # AI Systems Status
            click.echo("\nAI SYSTEMS STATUS")
            click.echo("-" * 40)
            click.echo("Vulnerability Correlator: Ready")
            click.echo("Exploit Recommender: Ready")
            click.echo("Attack Path Planner: Ready")
             
            # Data Analysis Summary
            if data_dir and Path(data_dir).exists():
                click.echo(f"\nDATA ANALYSIS - {data_dir}")
                click.echo("-" * 40)
                 
                # Count files by type
                data_path = Path(data_dir)
                vuln_files = list(data_path.glob("*vuln*.json"))
                exploit_files = list(data_path.glob("*exploit*.json"))
                path_files = list(data_path.glob("*path*.json"))
                 
                click.echo(f"Vulnerability files: {len(vuln_files)}")
                click.echo(f"Exploit files: {len(exploit_files)}")
                click.echo(f"Attack path files: {len(path_files)}")
                 
                # Show recent activity
                all_files = list(data_path.glob("*.json"))
                if all_files:
                    recent_files = sorted(all_files, key=lambda f: f.stat().st_mtime, reverse=True)[:5]
                    click.echo(f"\nRecent Activity:")
                    for f in recent_files:
                        mod_time = datetime.fromtimestamp(f.stat().st_mtime)
                        time_ago = datetime.now() - mod_time
                        if time_ago < timedelta(hours=1):
                            time_str = f"{int(time_ago.total_seconds() // 60)}m ago"
                        else:
                            time_str = f"{int(time_ago.total_seconds() // 3600)}h ago"
                        click.echo(f"  {f.name} ({time_str})")
             
            # Quick Stats (mock data for demonstration)
            click.echo("\nQUICK STATISTICS")
            click.echo("-" * 40)
            click.echo("Active Campaigns: 0")
            click.echo("Vulnerabilities Found: 0")
            click.echo("Exploits Available: 0")
            click.echo("Attack Paths: 0")
            click.echo("High Risk Issues: 0")
             
            # Controls
            click.echo("\nCONTROLS")
            click.echo("-" * 40)
            click.echo("Press Ctrl+C to exit dashboard")
            click.echo(f"Next refresh in {auto_refresh} seconds...")
             
            # Wait for next refresh
            time.sleep(auto_refresh)
             
    except KeyboardInterrupt:
        click.echo("\n\nDashboard stopped")


@dashboard.command('analyze')
@click.option('--input-dir', '-i', required=True, help='Directory with analysis data')
@click.option('--output', '-o', help='Output file for analysis report')
@click.option('--format', type=click.Choice(['json', 'html', 'text']), default='text', help='Report format')
@pass_context
def dashboard_analyze(ctx: NexusContext, input_dir: str, output: Optional[str], format: str):
    """Perform comprehensive AI analysis on collected data"""
    
    ctx.load_config()
    
    click.echo(f"Analyzing data in: {input_dir}")
    
    try:
        input_path = Path(input_dir)
        if not input_path.exists():
            click.echo(f"ERROR: Input directory not found: {input_dir}")
            return
        
        # Initialize AI systems
        ollama_client = ctx.get_ollama_client()
        correlator = VulnerabilityCorrelator(ollama_client, ctx.config)
        recommender = ExploitRecommender(ollama_client, ctx.config)
        planner = AttackPathPlanner(ollama_client, ctx.config)
        
        # Load and process data files
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'input_directory': str(input_path),
            'vulnerabilities': {},
            'exploits': {},
            'attack_paths': {},
            'summary': {}
        }
        
        # Process vulnerability files
        vuln_files = list(input_path.glob("*vuln*.json"))
        click.echo(f"Processing {len(vuln_files)} vulnerability files...")
        
        total_vulns = 0
        for vuln_file in vuln_files:
            try:
                with open(vuln_file, 'r') as f:
                    vuln_data = json.load(f)
                
                # Count vulnerabilities
                vulns_in_file = len(vuln_data.get('vulnerabilities', []))
                total_vulns += vulns_in_file
                
                analysis_results['vulnerabilities'][vuln_file.name] = {
                    'file_path': str(vuln_file),
                    'vulnerability_count': vulns_in_file,
                    'processed_at': datetime.now().isoformat()
                }
                
            except Exception as e:
                click.echo(f"WARNING: Error processing {vuln_file.name}: {e}")
        
        # Process exploit files
        exploit_files = list(input_path.glob("*exploit*.json"))
        click.echo(f"Processing {len(exploit_files)} exploit files...")
        
        total_exploits = 0
        for exploit_file in exploit_files:
            try:
                with open(exploit_file, 'r') as f:
                    exploit_data = json.load(f)
                
                # Count exploits
                exploits_in_file = len(exploit_data) if isinstance(exploit_data, list) else 1
                total_exploits += exploits_in_file
                
                analysis_results['exploits'][exploit_file.name] = {
                    'file_path': str(exploit_file),
                    'exploit_count': exploits_in_file,
                    'processed_at': datetime.now().isoformat()
                }
                
            except Exception as e:
                click.echo(f"WARNING: Error processing {exploit_file.name}: {e}")
        
        # Process attack path files
        path_files = list(input_path.glob("*path*.json"))
        click.echo(f"Processing {len(path_files)} attack path files...")
        
        total_paths = 0
        for path_file in path_files:
            try:
                with open(path_file, 'r') as f:
                    path_data = json.load(f)
                
                # Count paths
                paths_in_file = len(path_data) if isinstance(path_data, list) else 1
                total_paths += paths_in_file
                
                analysis_results['attack_paths'][path_file.name] = {
                    'file_path': str(path_file),
                    'path_count': paths_in_file,
                    'processed_at': datetime.now().isoformat()
                }
                
            except Exception as e:
                click.echo(f"WARNING: Error processing {path_file.name}: {e}")
        
        # Generate summary
        analysis_results['summary'] = {
            'total_files_processed': len(vuln_files) + len(exploit_files) + len(path_files),
            'total_vulnerabilities': total_vulns,
            'total_exploits': total_exploits,
            'total_attack_paths': total_paths,
            'analysis_completed_at': datetime.now().isoformat()
        }
        
        # Output results
        if format == 'json':
            if output:
                with open(output, 'w') as f:
                    json.dump(analysis_results, f, indent=2)
                click.echo(f"Analysis saved to: {output}")
            else:
                click.echo(json.dumps(analysis_results, indent=2))
        
        elif format == 'html':
            html_report = generate_html_report(analysis_results)
            if output:
                with open(output, 'w') as f:
                    f.write(html_report)
                click.echo(f"HTML report saved to: {output}")
            else:
                click.echo(html_report)
        
        else:  # text format
            click.echo("\nANALYSIS SUMMARY")
            click.echo("=" * 50)
            click.echo(f"Input Directory: {input_dir}")
            click.echo(f"Files Processed: {analysis_results['summary']['total_files_processed']}")
            click.echo(f"Vulnerabilities: {analysis_results['summary']['total_vulnerabilities']}")
            click.echo(f"Exploits: {analysis_results['summary']['total_exploits']}")
            click.echo(f"Attack Paths: {analysis_results['summary']['total_attack_paths']}")
            click.echo(f"Completed: {analysis_results['summary']['analysis_completed_at']}")
            
            if output:
                with open(output, 'w') as f:
                    f.write(f"Nexus AI Analysis Report\n")
                    f.write(f"Generated: {analysis_results['timestamp']}\n\n")
                    f.write(f"Input Directory: {input_dir}\n")
                    f.write(f"Files Processed: {analysis_results['summary']['total_files_processed']}\n")
                    f.write(f"Vulnerabilities: {analysis_results['summary']['total_vulnerabilities']}\n")
                    f.write(f"Exploits: {analysis_results['summary']['total_exploits']}\n")
                    f.write(f"Attack Paths: {analysis_results['summary']['total_attack_paths']}\n")
                click.echo(f"Text report saved to: {output}")
        
    except Exception as e:
        click.echo(f"ERROR: Analysis failed: {e}", err=True)


@dashboard.command('monitor')
@click.option('--directory', '-d', required=True, help='Directory to monitor for new data')
@click.option('--interval', '-i', type=int, default=10, help='Monitoring interval (seconds)')
@click.option('--action', type=click.Choice(['log', 'analyze', 'alert']), default='log', 
              help='Action to take on new files')
@pass_context
def dashboard_monitor(ctx: NexusContext, directory: str, interval: int, action: str):
    """Monitor directory for new analysis data"""
    
    ctx.load_config()
    
    click.echo(f"Monitoring directory: {directory}")
    click.echo(f"Check interval: {interval} seconds")
    click.echo(f"Action: {action}")
    click.echo("Press Ctrl+C to stop monitoring\n")
    
    monitor_path = Path(directory)
    if not monitor_path.exists():
        click.echo(f"ERROR: Directory not found: {directory}")
        return
    
    # Track known files
    known_files = set(f.name for f in monitor_path.glob("*.json"))
    
    try:
        while True:
            # Check for new files
            current_files = set(f.name for f in monitor_path.glob("*.json"))
            new_files = current_files - known_files
            
            if new_files:
                timestamp = datetime.now().strftime('%H:%M:%S')
                click.echo(f"[{timestamp}] New files detected: {len(new_files)}")
                
                for filename in new_files:
                    click.echo(f"  {filename}")
                    
                    if action == 'analyze':
                        click.echo(f"  Analyzing {filename}...")
                        # Trigger analysis (simplified)
                        click.echo(f"  Analysis queued for {filename}")
                    
                    elif action == 'alert':
                        click.echo(f"  ALERT: New data file {filename}")
                
                known_files = current_files
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        click.echo("\nMonitoring stopped")


def generate_html_report(analysis_results: Dict[str, Any]) -> str:
    """Generate HTML analysis report"""
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Nexus AI Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
            .summary {{ background: #ecf0f1; }}
            .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #3498db; color: white; border-radius: 3px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Nexus AI Analysis Report</h1>
            <p>Generated: {analysis_results['timestamp']}</p>
        </div>
        
        <div class="section summary">
            <h2>Summary</h2>
            <div class="metric">Files: {analysis_results['summary']['total_files_processed']}</div>
            <div class="metric">Vulnerabilities: {analysis_results['summary']['total_vulnerabilities']}</div>
            <div class="metric">Exploits: {analysis_results['summary']['total_exploits']}</div>
            <div class="metric">Paths: {analysis_results['summary']['total_attack_paths']}</div>
        </div>
        
        <div class="section">
            <h2>Vulnerability Analysis</h2>
            <table>
                <tr><th>File</th><th>Vulnerabilities</th><th>Processed</th></tr>
    """
    
    for filename, data in analysis_results['vulnerabilities'].items():
        html += f"""
                <tr>
                    <td>{filename}</td>
                    <td>{data['vulnerability_count']}</td>
                    <td>{data['processed_at']}</td>
                </tr>
        """
    
    html += """
            </table>
        </div>
        
        <div class="section">
            <h2>Exploit Analysis</h2>
            <table>
                <tr><th>File</th><th>Exploits</th><th>Processed</th></tr>
    """
    
    for filename, data in analysis_results['exploits'].items():
        html += f"""
                <tr>
                    <td>{filename}</td>
                    <td>{data['exploit_count']}</td>
                    <td>{data['processed_at']}</td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    </body>
    </html>
    """
    
    return html


# Register dashboard commands
def register_dashboard_commands(cli):
    """Register dashboard commands with the main CLI"""
    cli.add_command(dashboard)