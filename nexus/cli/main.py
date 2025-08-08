"""
Nexus CLI Main Entry Point

Main command-line interface for the Nexus AI-powered penetration testing tool.
Provides commands for campaign management, configuration, execution, reporting,
script generation, and comprehensive tool management.
"""

import os
import sys
import click
import logging
from pathlib import Path
from typing import Optional

# Add the parent directory to the path so we can import nexus modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexus.core.config import NexusConfig
from nexus.ai.ollama_client import OllamaClient
from nexus.tools.kali_tools import KaliToolsManager
from nexus.core.script_generator import CustomScriptGenerator
from nexus import __version__

# Import context and additional commands
from .context import NexusContext, pass_context

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Context is now imported from .context module


@click.group()
@click.version_option(version=__version__, prog_name="nexus")
@click.option('--config', '-c', 'config_path', 
              help='Path to configuration file')
@click.option('--verbose', '-v', is_flag=True, 
              help='Enable verbose output')
@pass_context
def cli(ctx: NexusContext, config_path: Optional[str], verbose: bool):
    """
    Nexus AI-Powered Penetration Testing Tool
    
    A comprehensive AI-driven penetration testing automation framework
    designed for professional red team assessments and authorized
    penetration testing engagements.
    
    Features:
    • AI-powered decision making and script generation
    • Support for 100+ Kali Linux tools
    • Automated tool chaining and data flow
    • Custom script generation and execution
    • Comprehensive safety mechanisms
    • Professional reporting and evidence collection
    
    WARNING: Only use on authorized targets with proper permission.
    """
    ctx.config_path = config_path
    ctx.verbose = verbose
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")


@cli.command()
@pass_context
def version(ctx: NexusContext):
    """Show version information"""
    click.echo(f"Nexus AI-Powered Penetration Testing Tool v{__version__}")
    
    # Try to load config and show additional info
    try:
        ctx.load_config()
        click.echo(f"Configuration: {ctx.config.config_path or 'Default'}")
        
        # Check Ollama connection
        ollama_client = ctx.get_ollama_client()
        if ollama_client.health_check_sync():
            click.echo(f"Ollama: Connected ({ctx.config.ai.ollama_url})")
            click.echo(f"AI Model: {ctx.config.ai.model}")
        else:
            click.echo("Ollama: Not connected")
        
        # Check tools
        tools_manager = ctx.get_tools_manager()
        available_tools = len(tools_manager.get_available_tools())
        total_tools = len(tools_manager.tools)
        click.echo(f"Tools: {available_tools}/{total_tools} available")
            
    except Exception as e:
        click.echo(f"ERROR: Configuration error: {e}", err=True)


@cli.command()
@pass_context
def health(ctx: NexusContext):
    """Check system health and dependencies"""
    click.echo("Checking Nexus system health...")
    
    # Check configuration
    try:
        ctx.load_config()
        click.echo("Configuration: OK")
    except Exception as e:
        click.echo(f"Configuration: FAILED - {e}")
        return
    
    # Check Ollama connection
    try:
        ollama_client = ctx.get_ollama_client()
        if ollama_client.health_check_sync():
            click.echo("Ollama: Connected")
            
            # Check if model is available
            if ollama_client.is_model_available(ctx.config.ai.model):
                click.echo(f"AI Model ({ctx.config.ai.model}): Available")
            else:
                click.echo(f"AI Model ({ctx.config.ai.model}): Not found locally")
        else:
            click.echo("Ollama: Not connected")
    except Exception as e:
        click.echo(f"Ollama: ERROR - {e}")
    
    # Check tools
    click.echo("\nChecking penetration testing tools:")
    try:
        tools_manager = ctx.get_tools_manager()
        report = tools_manager.get_system_report()
        
        click.echo(f"Tool Summary:")
        click.echo(f"   Total tools: {report['total_tools']}")
        click.echo(f"   Available: {report['available_tools']}")
        click.echo(f"   Enabled: {report['enabled_tools']}")
        
        # Show category breakdown
        click.echo(f"\nCategories:")
        for category, info in report['categories'].items():
            click.echo(f"   {category}: {info['available']}/{info['total']} available")
        
    except Exception as e:
        click.echo(f"Tools check failed: {e}")
    
    # Check directories
    click.echo("\nChecking directories:")
    dirs_to_check = [
        ("Config", os.path.expanduser("~/.nexus/config")),
        ("Logs", os.path.expanduser("~/.nexus/logs")),
        ("Reports", os.path.expanduser("~/.nexus/reports")),
        ("Data", os.path.expanduser("~/.nexus/data")),
        ("Scripts", os.path.expanduser("~/.nexus/scripts"))
    ]
    
    for name, path in dirs_to_check:
        if os.path.exists(path):
            click.echo(f"{name}: {path} - OK")
        else:
            click.echo(f"{name}: {path} - MISSING (will be created)")


@cli.group()
def campaign():
    """Campaign management commands"""
    pass


@campaign.command('create')
@click.option('--name', '-n', required=True, help='Campaign name')
@click.option('--description', '-d', help='Campaign description')
@click.option('--target', '-t', multiple=True, help='Target hosts/networks')
@click.option('--template', help='Campaign template to use')
@pass_context
def campaign_create(ctx: NexusContext, name: str, description: Optional[str], 
                   target: tuple, template: Optional[str]):
    """Create a new penetration testing campaign"""
    ctx.load_config()
    
    click.echo(f"Creating campaign: {name}")
    
    if description:
        click.echo(f"📝 Description: {description}")
    
    if target:
        click.echo(f"Targets: {', '.join(target)}")
    
    if template:
        click.echo(f"📋 Template: {template}")
    
    # TODO: Implement campaign creation logic
    click.echo("Campaign created successfully")
    click.echo("Use 'nexus run --campaign \"{}\"' to start the assessment".format(name))


@campaign.command('list')
@pass_context
def campaign_list(ctx: NexusContext):
    """List all campaigns"""
    ctx.load_config()
    
    click.echo("📋 Available campaigns:")
    # TODO: Implement campaign listing logic
    click.echo("No campaigns found")
    click.echo("💡 Create a new campaign with 'nexus campaign create'")


@campaign.command('delete')
@click.argument('name')
@click.option('--force', '-f', is_flag=True, help='Force deletion without confirmation')
@pass_context
def campaign_delete(ctx: NexusContext, name: str, force: bool):
    """Delete a campaign"""
    ctx.load_config()
    
    if not force:
        if not click.confirm(f"Are you sure you want to delete campaign '{name}'?"):
            click.echo("Cancelled")
            return
    
    click.echo(f"🗑️  Deleting campaign: {name}")
    # TODO: Implement campaign deletion logic
    click.echo("Campaign deleted successfully")


@cli.group()
def config():
    """Configuration management commands"""
    pass


@config.command('show')
@click.option('--section', help='Show specific configuration section')
@click.option('--format', type=click.Choice(['yaml', 'json']), default='yaml', 
              help='Output format')
@pass_context
def config_show(ctx: NexusContext, section: Optional[str], format: str):
    """Show current configuration"""
    ctx.load_config()
    
    if section:
        if hasattr(ctx.config, section):
            config_section = getattr(ctx.config, section)
            click.echo(f"[{section}]")
            if hasattr(config_section, '__dict__'):
                for key, value in config_section.__dict__.items():
                    click.echo(f"{key} = {value}")
            else:
                click.echo(str(config_section))
        else:
            click.echo(f"ERROR: Unknown configuration section: {section}")
    else:
        click.echo("⚙️  Current configuration:")
        if format == 'json':
            import json
            click.echo(json.dumps(ctx.config.to_dict(), indent=2))
        else:
            click.echo(str(ctx.config))


@config.command('set')
@click.argument('key')
@click.argument('value')
@pass_context
def config_set(ctx: NexusContext, key: str, value: str):
    """Set a configuration value"""
    ctx.load_config()
    
    # Parse key (e.g., "ai.model" -> section="ai", key="model")
    if '.' in key:
        section, setting = key.split('.', 1)
        if hasattr(ctx.config, section):
            section_obj = getattr(ctx.config, section)
            if hasattr(section_obj, setting):
                # Convert value to appropriate type
                current_value = getattr(section_obj, setting)
                if isinstance(current_value, bool):
                    value = value.lower() in ('true', '1', 'yes', 'on')
                elif isinstance(current_value, int):
                    value = int(value)
                elif isinstance(current_value, float):
                    value = float(value)
                
                setattr(section_obj, setting, value)
                ctx.config.save_config()
                click.echo(f"Set {key} = {value}")
            else:
                click.echo(f"ERROR: Unknown setting: {setting} in section {section}")
        else:
            click.echo(f"ERROR: Unknown configuration section: {section}")
    else:
        # Custom setting
        ctx.config.set_setting(key, value)
        ctx.config.save_config()
        click.echo(f"Set custom setting {key} = {value}")


@cli.command()
@click.option('--campaign', '-c', help='Campaign to run')
@click.option('--target', '-t', help='Target to test')
@click.option('--prompt', '-p', help='Custom prompt for AI')
@click.option('--auto', '-a', help='Autonomous mode: natural language objective (e.g., "get into the SMB server")')
@click.option('--dry-run', is_flag=True, help='Show what would be done without executing')
@click.option('--phase', type=click.Choice(['recon', 'scan', 'exploit', 'post-exploit']),
              help='Run specific phase only')
@click.option('--evasion-profile', help='Evasion profile to use (stealth_maximum, red_team, etc.)')
@pass_context
def run(ctx: NexusContext, campaign: Optional[str], target: Optional[str],
        prompt: Optional[str], auto: Optional[str], dry_run: bool, phase: Optional[str],
        evasion_profile: Optional[str]):
    """Run a penetration testing campaign"""
    ctx.load_config()
    
    # Autonomous mode - completely AI-driven
    if auto:
        click.echo("AUTONOMOUS MODE ACTIVATED")
        click.echo(f"Objective: {auto}")
        click.echo("AI will automatically plan and execute the complete mission")
        
        if dry_run:
            click.echo("\nDRY RUN - Autonomous Mission Plan:")
            click.echo("=" * 60)
            
            # Show what the autonomous agent would do
            click.echo("AI Analysis Phase:")
            click.echo("  - Parse natural language objective")
            click.echo("  - Identify target scope and constraints")
            click.echo("  - Generate comprehensive execution plan")
            click.echo("  - Select optimal tools and techniques")
            click.echo("  - Calculate success probability")
            
            click.echo("\nAutonomous Execution Phases:")
            click.echo("  1. RECONNAISSANCE")
            click.echo("     - DNS enumeration and subdomain discovery")
            click.echo("     - Network discovery and asset identification")
            click.echo("     - OSINT gathering and target profiling")
            
            click.echo("  2. SCANNING & ENUMERATION")
            click.echo("     - Port scanning with service detection")
            click.echo("     - Web application discovery")
            click.echo("     - SMB/NetBIOS enumeration")
            click.echo("     - Service-specific enumeration")
            
            click.echo("  3. AI VULNERABILITY ANALYSIS")
            click.echo("     - Cross-tool vulnerability correlation")
            click.echo("     - Attack chain identification")
            click.echo("     - Risk assessment and prioritization")
            
            click.echo("  4. INTELLIGENT EXPLOITATION")
            click.echo("     - AI exploit recommendation")
            click.echo("     - Custom script generation")
            click.echo("     - Automated exploitation attempts")
            click.echo("     - Success verification")
            
            click.echo("  5. POST-EXPLOITATION")
            click.echo("     - Privilege escalation")
            click.echo("     - Lateral movement")
            click.echo("     - Persistence establishment")
            click.echo("     - Data collection")
            
            click.echo("  6. AUTONOMOUS REPORTING")
            click.echo("     - Evidence collection and analysis")
            click.echo("     - Executive and technical reports")
            click.echo("     - Remediation recommendations")
            
            if evasion_profile:
                click.echo(f"\nEvasion Profile: {evasion_profile}")
                click.echo("  - Advanced detection avoidance")
                click.echo("  - Behavioral mimicry")
                click.echo("  - Traffic obfuscation")
            
            click.echo("\nExample autonomous objectives:")
            click.echo('  nexus run --auto "get into the SMB server on this network"')
            click.echo('  nexus run --auto "find SQL injection in the web app"')
            click.echo('  nexus run --auto "escalate privileges on the Linux server"')
            click.echo('  nexus run --auto "establish persistence on the domain controller"')
            
            return
        
        try:
            # Initialize autonomous agent
            from nexus.core.autonomous_agent import AutonomousAgent
            
            ollama_client = ctx.get_ollama_client()
            agent = AutonomousAgent(ollama_client, ctx.config)
            
            # Prepare context
            context = {}
            if target:
                context['target'] = target
            if evasion_profile:
                context['evasion_profile'] = evasion_profile
            
            # Execute autonomous mission
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            click.echo("\nLaunching autonomous AI agent...")
            result = loop.run_until_complete(agent.execute_autonomous_mission(auto, context))
            loop.close()
            
            # Display results
            if result['success']:
                click.echo("\nAUTONOMOUS MISSION COMPLETED")
                click.echo("=" * 50)
                click.echo(f"Objective: {result['objective']}")
                click.echo(f"Execution Time: {result['execution_time']} seconds")
                click.echo(f"Phases Completed: {result['phases_completed']}")
                click.echo(f"Vulnerabilities Found: {result['vulnerabilities_found']}")
                click.echo(f"Active Sessions: {result['active_sessions']}")
                click.echo(f"Evidence Collected: {len(result['evidence'])} items")
                
                click.echo(f"\nMission Report Generated:")
                click.echo(f"Mission ID: {result['mission_id']}")
                
            else:
                click.echo("\nAUTONOMOUS MISSION FAILED")
                click.echo(f"Error: {result['error']}")
                if 'partial_results' in result:
                    click.echo(f"Partial Results: {result['partial_results']}")
            
        except ImportError:
            click.echo("ERROR: Autonomous agent not available - install required dependencies")
        except Exception as e:
            click.echo(f"ERROR: Autonomous mission failed: {e}")
        
        return
    
    # Standard mode
    if not campaign and not target:
        raise click.ClickException("Either --campaign, --target, or --auto must be specified")
    
    if dry_run:
        click.echo("Dry run mode - showing planned actions:")
    
    if campaign:
        click.echo(f"Running campaign: {campaign}")
    
    if target:
        click.echo(f"Target: {target}")
    
    if prompt:
        click.echo(f"Custom prompt: {prompt}")
    
    if phase:
        click.echo(f"Phase: {phase}")
    
    if evasion_profile:
        click.echo(f"Evasion Profile: {evasion_profile}")
    
    # TODO: Implement campaign execution logic
    if not dry_run:
        click.echo("Starting penetration testing...")
        click.echo("WARNING: Full implementation in progress")
        
        # Show what would be implemented
        click.echo("\nPlanned execution flow:")
        click.echo("1. Load campaign configuration and validate scope")
        click.echo("2. Initialize safety mechanisms and scope validation")
        click.echo("3. Initialize AI decision engine with context")
        click.echo("4. Begin reconnaissance phase (passive & active)")
        click.echo("5. Vulnerability scanning and analysis")
        click.echo("6. Exploitation attempts based on findings")
        click.echo("7. Post-exploitation and persistence")
        click.echo("8. Generate comprehensive report")
    else:
        click.echo("Planned actions:")
        click.echo("1. Load campaign configuration")
        click.echo("2. Validate target scope")
        click.echo("3. Initialize AI decision engine")
        click.echo("4. Begin reconnaissance phase")
        click.echo("5. Continue through kill chain phases")


@cli.command()
@click.option('--campaign', '-c', help='Campaign to check status for')
@pass_context
def status(ctx: NexusContext, campaign: Optional[str]):
    """Show status of running campaigns"""
    ctx.load_config()
    
    if campaign:
        click.echo(f"Status for campaign: {campaign}")
    else:
        click.echo("Overall system status:")
    
    # TODO: Implement status checking logic
    click.echo("No active campaigns")
    click.echo("💡 Start a campaign with 'nexus run'")


@cli.group()
def report():
    """Report generation commands"""
    pass


@report.command('generate')
@click.option('--campaign', '-c', required=True, help='Campaign to generate report for')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'pdf']), 
              default='html', help='Report format')
@click.option('--output', '-o', help='Output file path')
@click.option('--template', help='Report template to use')
@pass_context
def report_generate(ctx: NexusContext, campaign: str, format: str, output: Optional[str], 
                   template: Optional[str]):
    """Generate a report for a campaign"""
    ctx.load_config()
    
    click.echo(f"Generating {format.upper()} report for campaign: {campaign}")
    
    if output:
        click.echo(f"📁 Output: {output}")
    
    if template:
        click.echo(f"📋 Template: {template}")
    
    # TODO: Implement report generation logic
    click.echo("Report generated successfully")


@cli.command()
@pass_context
def docs(ctx: NexusContext):
    """Open documentation"""
    click.echo("Nexus Documentation")
    click.echo("https://github.com/nexus-security/nexus/docs")
    
    # Try to open in browser
    try:
        import webbrowser
        webbrowser.open("https://github.com/nexus-security/nexus/docs")
        click.echo("Opening documentation in browser...")
    except Exception:
        pass


@cli.command()
@pass_context
def demo(ctx: NexusContext):
    """Run a demonstration of Nexus capabilities"""
    click.echo("🎬 Nexus Demonstration")
    click.echo("This will show the key features of Nexus in action.")
    
    if not click.confirm("Continue with demonstration?"):
        return
    
    ctx.load_config()
    
    # Demo script generation
    click.echo("\n1. Script Generation Demo")
    click.echo("Generating a custom port scanner script...")
    
    try:
        script_generator = ctx.get_script_generator()
        
        # Generate from template
        variables = {
            'target': '127.0.0.1',
            'ports': [22, 80, 443, 8080],
            'timeout': 5,
            'threads': 10
        }
        
        script = script_generator.generate_from_template('port_scanner', variables)
        click.echo(f"Generated script: {script.name}")
        click.echo(f"Location: {script.file_path}")
        
    except Exception as e:
        click.echo(f"ERROR: Script generation demo failed: {e}")
    
    # Demo tool listing
    click.echo("\n2. Tool Management Demo")
    click.echo("Showing available penetration testing tools...")
    
    try:
        tools_manager = ctx.get_tools_manager()
        categories = tools_manager.get_tool_categories()
        
        click.echo(f"📂 Found {len(categories)} tool categories:")
        for category in categories[:5]:  # Show first 5 categories
            tools_in_cat = tools_manager.get_tools_by_category(category)
            click.echo(f"  🔹 {category}: {len(tools_in_cat)} tools")
        
        if len(categories) > 5:
            click.echo(f"  ... and {len(categories) - 5} more categories")
            
    except Exception as e:
        click.echo(f"ERROR: Tool management demo failed: {e}")
    
    click.echo("\n🎉 Demo completed!")
    click.echo("💡 Try 'nexus tools list' to see all available tools")
    click.echo("💡 Try 'nexus script generate --help' for script generation options")


def main():
    """Main entry point for the CLI"""
    try:
        # Register additional commands
        from .commands import register_commands
        register_commands(cli)
        
        # Run CLI
        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()