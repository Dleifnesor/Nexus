"""
Nexus Evasion CLI Commands

Command-line interface for managing evasion profiles, techniques, and stealth operations.
"""

import click
import json
import asyncio
from typing import Optional, Dict, Any
from pathlib import Path

from nexus.core.evasion import EvasionManager, EvasionTechnique, DetectionRisk
from .context import pass_context, NexusContext


@click.group()
def evasion():
    """Evasion and stealth operation commands"""
    pass


@evasion.command('profiles')
@click.option('--format', type=click.Choice(['table', 'json']), default='table', help='Output format')
@pass_context
def evasion_profiles(ctx: NexusContext, format: str):
    """List available evasion profiles"""
    
    ctx.load_config()
    
    try:
        ollama_client = ctx.get_ollama_client()
        evasion_manager = EvasionManager(ollama_client, ctx.config)
        
        profiles = evasion_manager.get_available_profiles()
        
        if format == 'json':
            profile_data = {}
            for name, profile in profiles.items():
                profile_data[name] = {
                    'name': profile.name,
                    'description': profile.description,
                    'techniques': [t.value for t in profile.techniques],
                    'detection_risk': profile.detection_risk.value,
                    'stealth_rating': profile.stealth_rating,
                    'performance_impact': profile.performance_impact,
                    'complexity': profile.complexity
                }
            click.echo(json.dumps(profile_data, indent=2))
        else:
            click.echo("Available Evasion Profiles:")
            click.echo("=" * 60)
            
            for name, profile in profiles.items():
                stealth_percent = int(profile.stealth_rating * 100)
                impact_percent = int(profile.performance_impact * 100)
                
                click.echo(f"\nProfile: {profile.name}")
                click.echo(f"   Description: {profile.description}")
                click.echo(f"   Stealth Rating: {stealth_percent}%")
                click.echo(f"   Performance Impact: {impact_percent}%")
                click.echo(f"   Detection Risk: {profile.detection_risk.value}")
                click.echo(f"   Complexity: {profile.complexity}")
                click.echo(f"   Active Techniques: {len(profile.techniques)}")
                
                # Show techniques
                technique_names = [t.value.replace('_', ' ').title() for t in profile.techniques]
                click.echo(f"   Methods: {', '.join(technique_names[:3])}")
                if len(technique_names) > 3:
                    click.echo(f"            + {len(technique_names) - 3} more techniques")
        
    except Exception as e:
        click.echo(f"ERROR: Failed to list evasion profiles: {e}", err=True)


@evasion.command('set')
@click.argument('profile_name')
@pass_context
def evasion_set(ctx: NexusContext, profile_name: str):
    """
    Set active evasion profile
    
    Examples:
    # Set maximum stealth profile
    nexus evasion set stealth_maximum
    
    # Set red team profile
    nexus evasion set red_team
    
    # Set balanced stealth profile
    nexus evasion set stealth_balanced
    
    # List available profiles
    nexus evasion profiles
    """
     
    ctx.load_config()
     
    try:
        ollama_client = ctx.get_ollama_client()
        evasion_manager = EvasionManager(ollama_client, ctx.config)
         
        if evasion_manager.set_evasion_profile(profile_name):
            profile = evasion_manager.active_profile
            click.echo(f"Activated evasion profile: {profile.name}")
            click.echo(f"Stealth Rating: {profile.stealth_rating:.1%}")
            click.echo(f"Detection Risk: {profile.detection_risk.value}")
            click.echo(f"Performance Impact: {profile.performance_impact:.1%}")
            click.echo(f"Active Techniques: {len(profile.techniques)}")
             
            # Show warning for high-impact profiles
            if profile.performance_impact > 0.6:
                click.echo("WARNING: High performance impact - operations will be significantly slower")
             
            # Show complexity warning
            if profile.complexity in ['hard', 'expert']:
                click.echo(f"WARNING: {profile.complexity.title()} complexity profile - advanced configuration may be required")
        else:
            click.echo(f"ERROR: Unknown evasion profile: {profile_name}")
            click.echo("Use 'nexus evasion profiles' to see available profiles")
         
    except Exception as e:
        click.echo(f"ERROR: Failed to set evasion profile: {e}", err=True)


@evasion.command('status')
@click.option('--detailed', is_flag=True, help='Show detailed evasion status')
@pass_context
def evasion_status(ctx: NexusContext, detailed: bool):
    """Show current evasion status"""
    
    ctx.load_config()
    
    try:
        ollama_client = ctx.get_ollama_client()
        evasion_manager = EvasionManager(ollama_client, ctx.config)
        
        if not evasion_manager.active_profile:
            click.echo("ERROR: No active evasion profile")
            click.echo("Set a profile with 'nexus evasion set <profile_name>'")
            return
        
        profile = evasion_manager.active_profile
        
        click.echo("Current Evasion Status:")
        click.echo("=" * 40)
        click.echo(f"Active Profile: {profile.name}")
        click.echo(f"Description: {profile.description}")
        
        # Metrics
        click.echo(f"\nMetrics:")
        click.echo(f"Stealth Rating: {profile.stealth_rating:.1%}")
        click.echo(f"Performance Impact: {profile.performance_impact:.1%}")
        click.echo(f"Detection Risk: {profile.detection_risk.value}")
        click.echo(f"Complexity: {profile.complexity}")
        
        if detailed:
            click.echo(f"\nActive Techniques ({len(profile.techniques)}):")
            for technique in profile.techniques:
                technique_name = technique.value.replace('_', ' ').title()
                click.echo(f"  - {technique_name}")
            
            # Get evasion report
            report = evasion_manager.get_evasion_report()
            if 'statistics' in report:
                stats = report['statistics']
                click.echo(f"\nStatistics:")
                click.echo(f"Total Events: {stats['total_events']}")
                click.echo(f"Recent Events (24h): {stats['recent_events_24h']}")
                click.echo(f"Avg Detection Probability: {stats['average_detection_probability']:.1%}")
            
            if 'recommendations' in report and report['recommendations']:
                click.echo(f"\nRecommendations:")
                for rec in report['recommendations']:
                    click.echo(f"  - {rec}")
        
    except Exception as e:
        click.echo(f"ERROR: Failed to get evasion status: {e}", err=True)


@evasion.command('test')
@click.option('--target', '-t', required=True, help='Target for evasion testing')
@click.option('--operation', '-o', default='web_scan', help='Operation type to test')
@click.option('--requests', '-r', type=int, default=10, help='Number of test requests')
@pass_context
def evasion_test(ctx: NexusContext, target: str, operation: str, requests: int):
    """Test evasion techniques against a target"""
    
    ctx.load_config()
    
    click.echo(f"Testing evasion techniques against: {target}")
    click.echo(f"Operation type: {operation}")
    click.echo(f"Test requests: {requests}")
    
    try:
        ollama_client = ctx.get_ollama_client()
        evasion_manager = EvasionManager(ollama_client, ctx.config)
        
        if not evasion_manager.active_profile:
            click.echo("WARNING: No active evasion profile - using default techniques")
            evasion_manager.set_evasion_profile("stealth_minimal")
        
        async def run_evasion_test():
            results = []
            
            for i in range(requests):
                click.echo(f"Test request {i+1}/{requests}...")
                
                # Apply behavioral mimicry
                behavior = await evasion_manager.apply_behavioral_mimicry(operation)
                
                # Apply timing randomization
                delay = await evasion_manager.apply_timing_randomization(2.0)
                
                # Calculate detection probability
                operation_params = {
                    'request_rate': requests / 60,  # requests per minute
                    'payload_size': 100,
                    'target': target
                }
                detection_prob = evasion_manager.calculate_detection_probability(operation_params)
                
                result = {
                    'request_id': i + 1,
                    'delay': delay,
                    'detection_probability': detection_prob,
                    'user_agent': evasion_manager.get_random_user_agent(),
                    'behavior': behavior
                }
                results.append(result)
                
                # Log the test event
                evasion_manager.log_detection_event('evasion_test', {
                    'target': target,
                    'operation': operation,
                    'request_id': i + 1
                })
                
                # Wait for the calculated delay
                import time
                time.sleep(min(delay, 5.0))  # Cap at 5 seconds for testing
            
            return results
        
        # Run the test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        test_results = loop.run_until_complete(run_evasion_test())
        loop.close()
        
        # Analyze results
        avg_delay = sum(r['delay'] for r in test_results) / len(test_results)
        avg_detection = sum(r['detection_probability'] for r in test_results) / len(test_results)
        
        click.echo(f"\nTest Results:")
        click.echo(f"Average Delay: {avg_delay:.2f} seconds")
        click.echo(f"Average Detection Probability: {avg_detection:.1%}")
        
        # Risk assessment
        if avg_detection < 0.3:
            click.echo("RISK LEVEL: LOW - Excellent evasion performance")
        elif avg_detection < 0.6:
            click.echo("RISK LEVEL: MEDIUM - Moderate evasion performance")
        else:
            click.echo("RISK LEVEL: HIGH - Poor evasion performance - consider higher stealth profile")
        
        # Show sample requests
        click.echo(f"\nSample Request Details:")
        sample = test_results[0]
        click.echo(f"User Agent: {sample['user_agent']}")
        click.echo(f"Delay: {sample['delay']:.2f}s")
        click.echo(f"Detection Risk: {sample['detection_probability']:.1%}")
        
    except Exception as e:
        click.echo(f"ERROR: Evasion test failed: {e}", err=True)


@evasion.command('analyze')
@click.option('--target-info', '-i', required=True, help='Target information file (JSON)')
@click.option('--operation', '-o', required=True, help='Planned operation type')
@click.option('--output', help='Output file for analysis results')
@pass_context
def evasion_analyze(ctx: NexusContext, target_info: str, operation: str, output: Optional[str]):
    """Analyze target and generate AI-powered evasion strategy"""
    
    ctx.load_config()
    
    click.echo(f"Analyzing target for evasion strategy...")
    click.echo(f"Target info: {target_info}")
    click.echo(f"Operation: {operation}")
    
    try:
        # Load target information
        with open(target_info, 'r') as f:
            target_data = json.load(f)
        
        ollama_client = ctx.get_ollama_client()
        evasion_manager = EvasionManager(ollama_client, ctx.config)
        
        async def generate_strategy():
            strategy = await evasion_manager.generate_ai_evasion_strategy(target_data, operation)
            return strategy
        
        # Generate AI strategy
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ai_strategy = loop.run_until_complete(generate_strategy())
        loop.close()
        
        click.echo(f"\nAI-Generated Evasion Strategy:")
        click.echo("=" * 50)
        
        if 'timing_pattern' in ai_strategy:
            click.echo(f"Timing Pattern: {ai_strategy['timing_pattern']}")
        
        if 'encoding_method' in ai_strategy:
            click.echo(f"Encoding Method: {ai_strategy['encoding_method']}")
        
        if 'obfuscation' in ai_strategy:
            click.echo(f"Obfuscation: {ai_strategy['obfuscation']}")
        
        if 'mimicry' in ai_strategy:
            click.echo(f"Behavioral Mimicry: {ai_strategy['mimicry']}")
        
        if 'rationale' in ai_strategy:
            click.echo(f"\nAI Rationale:")
            click.echo(f"   {ai_strategy['rationale']}")
        
        # Recommend profile based on analysis
        recommended_profiles = []
        if 'stealth_required' in target_data and target_data['stealth_required']:
            recommended_profiles.append('stealth_maximum')
        elif 'security_controls' in target_data and target_data['security_controls']:
            recommended_profiles.append('red_team')
        else:
            recommended_profiles.append('stealth_balanced')
        
        if recommended_profiles:
            click.echo(f"\nRecommended Profiles:")
            for profile in recommended_profiles:
                click.echo(f"   - {profile}")
        
        # Save results if output specified
        if output:
            analysis_results = {
                'target_info': target_data,
                'operation_type': operation,
                'ai_strategy': ai_strategy,
                'recommended_profiles': recommended_profiles,
                'analysis_timestamp': ctx.config.get_timestamp()
            }
            
            with open(output, 'w') as f:
                json.dump(analysis_results, f, indent=2)
            click.echo(f"\nAnalysis results saved to: {output}")
        
    except FileNotFoundError:
        click.echo(f"ERROR: Target information file not found: {target_info}")
    except json.JSONDecodeError:
        click.echo(f"ERROR: Invalid JSON in target information file")
    except Exception as e:
        click.echo(f"ERROR: Evasion analysis failed: {e}", err=True)


@evasion.command('report')
@click.option('--format', type=click.Choice(['json', 'text']), default='text', help='Report format')
@click.option('--output', '-o', help='Output file for report')
@pass_context
def evasion_report(ctx: NexusContext, format: str, output: Optional[str]):
    """Generate comprehensive evasion report"""
    
    ctx.load_config()
    
    try:
        ollama_client = ctx.get_ollama_client()
        evasion_manager = EvasionManager(ollama_client, ctx.config)
        
        report = evasion_manager.get_evasion_report()
        
        if format == 'json':
            if output:
                with open(output, 'w') as f:
                    json.dump(report, f, indent=2)
                click.echo(f"Evasion report saved to: {output}")
            else:
                click.echo(json.dumps(report, indent=2))
        else:
            # Text format
            click.echo("Nexus Evasion Report")
            click.echo("=" * 50)
            
            if 'error' in report:
                click.echo(f"ERROR: {report['error']}")
                return
            
            # Active profile info
            if 'active_profile' in report:
                profile = report['active_profile']
                click.echo(f"\nActive Profile: {profile['name']}")
                click.echo(f"Description: {profile['description']}")
                click.echo(f"Stealth Rating: {profile['stealth_rating']:.1%}")
                click.echo(f"Detection Risk: {profile['detection_risk']}")
                click.echo(f"Performance Impact: {profile['performance_impact']:.1%}")
                click.echo(f"Active Techniques: {len(profile['techniques'])}")
            
            # Statistics
            if 'statistics' in report:
                stats = report['statistics']
                click.echo(f"\nStatistics:")
                click.echo(f"Total Events: {stats['total_events']}")
                click.echo(f"Recent Events (24h): {stats['recent_events_24h']}")
                click.echo(f"Average Detection Probability: {stats['average_detection_probability']:.1%}")
                click.echo(f"Techniques Active: {stats['techniques_active']}")
            
            # Recommendations
            if 'recommendations' in report and report['recommendations']:
                click.echo(f"\nRecommendations:")
                for i, rec in enumerate(report['recommendations'], 1):
                    click.echo(f"{i}. {rec}")
            
            if output:
                # Save text report
                with open(output, 'w') as f:
                    f.write("Nexus Evasion Report\n")
                    f.write("=" * 50 + "\n\n")
                    
                    if 'active_profile' in report:
                        profile = report['active_profile']
                        f.write(f"Active Profile: {profile['name']}\n")
                        f.write(f"Description: {profile['description']}\n")
                        f.write(f"Stealth Rating: {profile['stealth_rating']:.1%}\n")
                        f.write(f"Detection Risk: {profile['detection_risk']}\n\n")
                    
                    if 'statistics' in report:
                        stats = report['statistics']
                        f.write("Statistics:\n")
                        f.write(f"- Total Events: {stats['total_events']}\n")
                        f.write(f"- Recent Events (24h): {stats['recent_events_24h']}\n")
                        f.write(f"- Average Detection Probability: {stats['average_detection_probability']:.1%}\n\n")
                    
                    if 'recommendations' in report and report['recommendations']:
                        f.write("Recommendations:\n")
                        for i, rec in enumerate(report['recommendations'], 1):
                            f.write(f"{i}. {rec}\n")
                
                click.echo(f"Text report saved to: {output}")
        
    except Exception as e:
        click.echo(f"ERROR: Failed to generate evasion report: {e}", err=True)


# Register evasion commands
def register_evasion_commands(cli):
    """Register evasion commands with the main CLI"""
    cli.add_command(evasion)