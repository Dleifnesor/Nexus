"""
Nexus Advanced AI Commands

CLI commands for advanced AI capabilities including vulnerability correlation,
exploit recommendation, and attack path planning.
"""

import click
import json
import asyncio
from typing import Optional, List
from pathlib import Path

from nexus.ai.vulnerability_correlator import VulnerabilityCorrelator, Vulnerability, SeverityLevel, VulnerabilityType
from nexus.ai.exploit_recommender import ExploitRecommender
from nexus.ai.attack_path_planner import AttackPathPlanner, AttackObjective
from .context import pass_context, NexusContext


@click.group()
def ai():
    """Advanced AI-powered analysis and planning commands"""
    pass


@ai.group()
def vuln():
    """Vulnerability correlation and analysis commands"""
    pass


@vuln.command('correlate')
@click.option('--input', '-i', required=True, help='Input file with tool results (JSON)')
@click.option('--output', '-o', help='Output file for correlation results')
@click.option('--format', type=click.Choice(['json', 'table']), default='table', help='Output format')
@pass_context
def vuln_correlate(ctx: NexusContext, input: str, output: Optional[str], format: str):
    """Correlate vulnerabilities from multiple tool outputs"""
    
    ctx.load_config()
    
    click.echo("Analyzing vulnerabilities for correlation...")
    
    try:
        # Load tool results
        with open(input, 'r') as f:
            tool_results = json.load(f)
        
        # Initialize correlator
        ollama_client = ctx.get_ollama_client()
        correlator = VulnerabilityCorrelator(ollama_client, ctx.config)
        
        # Process tool results
        async def process_results():
            for tool_name, tool_output in tool_results.items():
                target_info = tool_output.get('target_info', {})
                await correlator.add_vulnerability_from_tool_output(tool_name, tool_output, target_info)
        
        # Run correlation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(process_results())
        loop.close()
        
        # Get results
        summary = correlator.get_vulnerability_summary()
        top_risks = correlator.get_top_risks(10)
        clusters = correlator.get_clusters_by_risk()
        
        if format == 'json':
            results = {
                'summary': summary,
                'top_risks': [
                    {
                        'id': v.vuln_id,
                        'name': v.name,
                        'severity': v.severity.value,
                        'host': v.host,
                        'exploitable': v.exploitable
                    } for v in top_risks
                ],
                'clusters': [
                    {
                        'id': c.cluster_id,
                        'type': c.cluster_type,
                        'risk_score': c.risk_score,
                        'vulnerability_count': len(c.vulnerabilities),
                        'description': c.description
                    } for c in clusters
                ]
            }
            
            if output:
                with open(output, 'w') as f:
                    json.dump(results, f, indent=2)
                click.echo(f"Results saved to: {output}")
            else:
                click.echo(json.dumps(results, indent=2))
        
        else:
            # Table format
            click.echo(f"\nVulnerability Summary:")
            click.echo(f"Total vulnerabilities: {summary['total']}")
            click.echo(f"Exploitable: {summary['exploitable']}")
            click.echo(f"Clusters identified: {summary['clusters']}")
            
            click.echo(f"\nTop Risk Vulnerabilities:")
            for i, vuln in enumerate(top_risks, 1):
                status = "CRITICAL" if vuln.severity == SeverityLevel.CRITICAL else "HIGH" if vuln.severity == SeverityLevel.HIGH else "MEDIUM"
                exploit = "EXPLOITABLE" if vuln.exploitable else "NOT_EXPLOITABLE"
                click.echo(f"{i:2d}. [{status}] [{exploit}] {vuln.name}")
                click.echo(f"     Host: {vuln.host} | Severity: {vuln.severity.value}")
            
            click.echo(f"\nVulnerability Clusters:")
            for i, cluster in enumerate(clusters[:5], 1):
                click.echo(f"{i}. {cluster.cluster_type} (Risk: {cluster.risk_score:.1f})")
                click.echo(f"   {cluster.description}")
                click.echo(f"   Vulnerabilities: {len(cluster.vulnerabilities)}")
        
    except Exception as e:
        click.echo(f"ERROR: Vulnerability correlation failed: {e}", err=True)


@ai.group()
def exploit():
    """Exploit recommendation commands"""
    pass


@exploit.command('recommend')
@click.option('--vuln-file', '-v', required=True, help='Vulnerability data file (JSON)')
@click.option('--target', '-t', help='Specific target host')
@click.option('--complexity', type=click.Choice(['trivial', 'easy', 'medium', 'hard', 'expert']), 
              help='Maximum exploit complexity')
@click.option('--stealth', is_flag=True, help='Prioritize stealthy exploits')
@click.option('--output', '-o', help='Output file for recommendations')
@pass_context
def exploit_recommend(ctx: NexusContext, vuln_file: str, target: Optional[str], complexity: Optional[str],
                     stealth: bool, output: Optional[str]):
    """Recommend exploits for discovered vulnerabilities"""
    
    ctx.load_config()
    
    click.echo("Generating exploit recommendations...")
    
    try:
        # Load vulnerability data
        with open(vuln_file, 'r') as f:
            vuln_data = json.load(f)
        
        # Initialize recommender
        ollama_client = ctx.get_ollama_client()
        recommender = ExploitRecommender(ollama_client, ctx.config)
        
        # Process vulnerabilities
        async def get_recommendations():
            all_recommendations = []
            
            for vuln_info in vuln_data.get('vulnerabilities', []):
                # Skip if target filter specified
                if target and vuln_info.get('host') != target:
                    continue
                
                # Create vulnerability object
                vuln = Vulnerability(
                    vuln_id=vuln_info.get('id', ''),
                    name=vuln_info.get('name', ''),
                    description=vuln_info.get('description', ''),
                    severity=SeverityLevel(vuln_info.get('severity', 'medium')),
                    vuln_type=VulnerabilityType(vuln_info.get('type', 'system')),
                    host=vuln_info.get('host', ''),
                    port=vuln_info.get('port'),
                    service=vuln_info.get('service'),
                    exploitable=vuln_info.get('exploitable', False)
                )
                
                # Get recommendations
                context = {
                    'stealth_required': stealth,
                    'max_complexity': complexity
                }
                
                recommendations = await recommender.recommend_exploits(vuln, context)
                all_recommendations.extend(recommendations)
            
            return all_recommendations
        
        # Run recommendations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        recommendations = loop.run_until_complete(get_recommendations())
        loop.close()
        
        if not recommendations:
            click.echo("No exploit recommendations found")
            return
        
        # Group by severity
        by_severity = {}
        for rec in recommendations:
            severity = rec.target_vulnerability.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(rec)
        
        # Display results
        click.echo(f"\nFound {len(recommendations)} exploit recommendations:")
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in by_severity:
                click.echo(f"\n{severity.upper()} Severity:")
                
                for rec in by_severity[severity][:5]:  # Top 5 per severity
                    success_percent = int(rec.success_probability * 100)
                    stealth_percent = int(rec.stealth_rating * 100)
                    
                    click.echo(f"  Target: {rec.name}")
                    click.echo(f"     Host: {rec.target_vulnerability.host}")
                    click.echo(f"     Success Rate: {success_percent}%")
                    click.echo(f"     Stealth Rating: {stealth_percent}%")
                    click.echo(f"     Complexity: {rec.complexity.value}")
                    
                    if rec.metasploit_module:
                        click.echo(f"     MSF Module: {rec.metasploit_module}")
        
        # Save detailed results
        if output:
            detailed_results = []
            for rec in recommendations:
                detailed_results.append({
                    'exploit_id': rec.exploit_id,
                    'name': rec.name,
                    'description': rec.description,
                    'target_host': rec.target_vulnerability.host,
                    'target_vulnerability': rec.target_vulnerability.name,
                    'success_probability': rec.success_probability,
                    'stealth_rating': rec.stealth_rating,
                    'complexity': rec.complexity.value,
                    'metasploit_module': rec.metasploit_module,
                    'execution_steps': rec.execution_steps,
                    'requirements': rec.requirements
                })
            
            with open(output, 'w') as f:
                json.dump(detailed_results, f, indent=2)
            click.echo(f"\nDetailed recommendations saved to: {output}")
        
    except Exception as e:
        click.echo(f"ERROR: Exploit recommendation failed: {e}", err=True)


@exploit.command('generate-script')
@click.option('--recommendation-id', '-r', required=True, help='Exploit recommendation ID')
@click.option('--recommendations-file', '-f', required=True, help='Recommendations file (JSON)')
@click.option('--output', '-o', help='Output script file')
@click.option('--attacker-ip', help='Attacker IP address')
@click.option('--callback-port', type=int, default=4444, help='Callback port')
@pass_context
def exploit_generate_script(ctx: NexusContext, recommendation_id: str, recommendations_file: str,
                           output: Optional[str], attacker_ip: Optional[str], callback_port: int):
    """Generate custom exploit script from recommendation"""
    
    ctx.load_config()
    
    click.echo(f"Generating exploit script for: {recommendation_id}")
    
    try:
        # Load recommendations
        with open(recommendations_file, 'r') as f:
            recommendations_data = json.load(f)
        
        # Find specific recommendation
        rec_data = None
        for rec in recommendations_data:
            if rec.get('exploit_id') == recommendation_id:
                rec_data = rec
                break
        
        if not rec_data:
            click.echo(f"ERROR: Recommendation not found: {recommendation_id}")
            return
        
        # Initialize recommender
        ollama_client = ctx.get_ollama_client()
        recommender = ExploitRecommender(ollama_client, ctx.config)
        
        # Generate script
        async def generate_script():
            # Create recommendation object (simplified)
            from nexus.ai.exploit_recommender import ExploitRecommendation, ExploitType, ExploitComplexity
            
            rec = ExploitRecommendation(
                exploit_id=rec_data['exploit_id'],
                name=rec_data['name'],
                description=rec_data['description'],
                exploit_type=ExploitType.REMOTE_CODE_EXECUTION,  # Default
                complexity=ExploitComplexity(rec_data.get('complexity', 'medium')),
                success_probability=rec_data['success_probability'],
                stealth_rating=rec_data['stealth_rating'],
                target_vulnerability=None,  # Simplified
                execution_steps=rec_data.get('execution_steps', []),
                payload_options=rec_data.get('payload_options', {})
            )
            
            context = {}
            if attacker_ip:
                context['attacker_ip'] = attacker_ip
            if callback_port:
                context['callback_port'] = callback_port
            
            script = await recommender.generate_exploit_script(rec, context)
            return script
        
        # Run generation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        script = loop.run_until_complete(generate_script())
        loop.close()
        
        if script:
            if output:
                with open(output, 'w') as f:
                    f.write(script)
                click.echo(f"Exploit script generated: {output}")
            else:
                click.echo("\nGenerated Exploit Script:")
                click.echo("=" * 50)
                click.echo(script)
                click.echo("=" * 50)
        else:
            click.echo("ERROR: Failed to generate exploit script")
        
    except Exception as e:
        click.echo(f"ERROR: Script generation failed: {e}", err=True)


@ai.group()
def attack():
    """Attack path planning commands"""
    pass


@attack.command('plan')
@click.option('--vuln-file', '-v', required=True, help='Vulnerability data file (JSON)')
@click.option('--environment', '-e', required=True, help='Target environment file (JSON)')
@click.option('--objective', type=click.Choice([obj.value for obj in AttackObjective]),
              required=True, help='Campaign objective')
@click.option('--max-paths', type=int, default=5, help='Maximum number of paths to generate')
@click.option('--stealth', is_flag=True, help='Prioritize stealthy attack paths')
@click.option('--output', '-o', help='Output file for attack paths')
@pass_context
def attack_plan(ctx: NexusContext, vuln_file: str, environment: str, objective: str,
               max_paths: int, stealth: bool, output: Optional[str]):
    """Plan attack paths to achieve campaign objectives"""
    
    ctx.load_config()
    
    click.echo(f"Planning attack paths for objective: {objective}")
    
    try:
        # Load data
        with open(vuln_file, 'r') as f:
            vuln_data = json.load(f)
        
        with open(environment, 'r') as f:
            env_data = json.load(f)
        
        # Initialize planner
        ollama_client = ctx.get_ollama_client()
        planner = AttackPathPlanner(ollama_client, ctx.config)
        
        # Process data
        async def plan_paths():
            # Convert vulnerability data
            vulnerabilities = []
            for vuln_info in vuln_data.get('vulnerabilities', []):
                vuln = Vulnerability(
                    vuln_id=vuln_info.get('id', ''),
                    name=vuln_info.get('name', ''),
                    description=vuln_info.get('description', ''),
                    severity=SeverityLevel(vuln_info.get('severity', 'medium')),
                    vuln_type=VulnerabilityType(vuln_info.get('type', 'system')),
                    host=vuln_info.get('host', ''),
                    port=vuln_info.get('port'),
                    service=vuln_info.get('service'),
                    exploitable=vuln_info.get('exploitable', False)
                )
                vulnerabilities.append(vuln)
            
            # Build attack graph
            await planner.build_attack_graph(vulnerabilities, env_data)
            
            # Plan attack paths
            constraints = {'stealth_required': stealth, 'max_paths': max_paths}
            paths = await planner.plan_attack_paths(AttackObjective(objective), env_data, constraints)
            
            return paths
        
        # Run planning
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        attack_paths = loop.run_until_complete(plan_paths())
        loop.close()
        
        if not attack_paths:
            click.echo("ERROR: No attack paths found")
            return
        
        # Display results
        click.echo(f"\nFound {len(attack_paths)} attack paths:")
        
        for i, path in enumerate(attack_paths[:max_paths], 1):
            success_percent = int(path.total_success_probability * 100)
            stealth_percent = int(path.stealth_score * 100)
            
            click.echo(f"\n{i}. {path.name}")
            click.echo(f"   Success Rate: {success_percent}%")
            click.echo(f"   Stealth Rating: {stealth_percent}%")
            click.echo(f"   Estimated Time: {path.estimated_time // 60} minutes")
            click.echo(f"   Steps: {len(path.edges)}")
            click.echo(f"   MITRE Techniques: {len(path.mitre_techniques)}")
            
            # Show path steps
            click.echo("   Path Steps:")
            for j, edge in enumerate(path.edges, 1):
                click.echo(f"     {j}. {edge.attack_technique}")
                click.echo(f"        {edge.source_node.host} -> {edge.target_node.host}")
        
        # Save detailed results
        if output:
            detailed_paths = []
            for path in attack_paths:
                detailed_paths.append({
                    'path_id': path.path_id,
                    'name': path.name,
                    'description': path.description,
                    'objective': path.objective.value,
                    'success_probability': path.total_success_probability,
                    'detection_risk': path.total_detection_risk,
                    'estimated_time': path.estimated_time,
                    'complexity_score': path.complexity_score,
                    'phases_covered': [p.value for p in path.phases_covered],
                    'mitre_techniques': path.mitre_techniques,
                    'required_tools': path.required_tools,
                    'execution_steps': path.execution_steps,
                    'steps': [
                        {
                            'technique': edge.attack_technique,
                            'source': edge.source_node.host,
                            'target': edge.target_node.host,
                            'success_probability': edge.success_probability,
                            'detection_probability': edge.detection_probability
                        } for edge in path.edges
                    ]
                })
            
            with open(output, 'w') as f:
                json.dump(detailed_paths, f, indent=2)
            click.echo(f"\nDetailed attack paths saved to: {output}")
        
    except Exception as e:
        click.echo(f"ERROR: Attack path planning failed: {e}", err=True)


@attack.command('graph')
@click.option('--vuln-file', '-v', required=True, help='Vulnerability data file (JSON)')
@click.option('--environment', '-e', required=True, help='Target environment file (JSON)')
@click.option('--output', '-o', help='Output file for graph visualization')
@click.option('--format', type=click.Choice(['dot', 'json']), default='json', help='Output format')
@pass_context
def attack_graph(ctx: NexusContext, vuln_file: str, environment: str, output: Optional[str], format: str):
    """Generate attack graph visualization"""
    
    ctx.load_config()
    
    click.echo("Generating attack graph...")
    
    try:
        # Load data
        with open(vuln_file, 'r') as f:
            vuln_data = json.load(f)
        
        with open(environment, 'r') as f:
            env_data = json.load(f)
        
        # Initialize planner
        ollama_client = ctx.get_ollama_client()
        planner = AttackPathPlanner(ollama_client, ctx.config)
        
        # Build graph
        async def build_graph():
            vulnerabilities = []
            for vuln_info in vuln_data.get('vulnerabilities', []):
                vuln = Vulnerability(
                    vuln_id=vuln_info.get('id', ''),
                    name=vuln_info.get('name', ''),
                    description=vuln_info.get('description', ''),
                    severity=SeverityLevel(vuln_info.get('severity', 'medium')),
                    vuln_type=VulnerabilityType(vuln_info.get('type', 'system')),
                    host=vuln_info.get('host', ''),
                    port=vuln_info.get('port'),
                    service=vuln_info.get('service'),
                    exploitable=vuln_info.get('exploitable', False)
                )
                vulnerabilities.append(vuln)
            
            graph = await planner.build_attack_graph(vulnerabilities, env_data)
            return graph
        
        # Run graph building
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        attack_graph = loop.run_until_complete(build_graph())
        loop.close()
        
        click.echo(f"Generated attack graph:")
        click.echo(f"   Nodes: {len(attack_graph.nodes)}")
        click.echo(f"   Edges: {len(attack_graph.edges)}")
        
        if output:
            if format == 'json':
                graph_data = {
                    'nodes': [
                        {
                            'id': node.node_id,
                            'host': node.host,
                            'privileges': node.privileges,
                            'value_score': node.value_score,
                            'network_position': node.network_position
                        } for node in attack_graph.nodes.values()
                    ],
                    'edges': [
                        {
                            'id': edge.edge_id,
                            'source': edge.source_node.node_id,
                            'target': edge.target_node.node_id,
                            'technique': edge.attack_technique,
                            'success_probability': edge.success_probability,
                            'detection_probability': edge.detection_probability,
                            'mitre_technique': edge.mitre_technique
                        } for edge in attack_graph.edges.values()
                    ]
                }
                
                with open(output, 'w') as f:
                    json.dump(graph_data, f, indent=2)
                click.echo(f"Attack graph saved to: {output}")
            
            elif format == 'dot':
                # Generate DOT format for Graphviz
                dot_content = "digraph AttackGraph {\n"
                dot_content += "  rankdir=LR;\n"
                dot_content += "  node [shape=box];\n\n"
                
                # Add nodes
                for node in attack_graph.nodes.values():
                    color = "red" if node.privileges in ["admin", "system"] else "yellow" if node.privileges == "user" else "lightblue"
                    dot_content += f'  "{node.node_id}" [label="{node.host}\\n{node.privileges}" fillcolor={color} style=filled];\n'
                
                dot_content += "\n"
                
                # Add edges
                for edge in attack_graph.edges.values():
                    dot_content += f'  "{edge.source_node.node_id}" -> "{edge.target_node.node_id}" [label="{edge.attack_technique}"];\n'
                
                dot_content += "}\n"
                
                with open(output, 'w') as f:
                    f.write(dot_content)
                click.echo(f"DOT graph saved to: {output}")
                click.echo("Use 'dot -Tpng graph.dot -o graph.png' to generate image")
        
    except Exception as e:
        click.echo(f"ERROR: Attack graph generation failed: {e}", err=True)


# Register AI commands with main CLI
def register_ai_commands(cli):
    """Register AI commands with the main CLI"""
    cli.add_command(ai)