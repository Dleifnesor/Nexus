"""
Nexus CLI Commands

Extended command implementations for Nexus including script generation,
tool management, and comprehensive penetration testing operations.
"""

import click
import json
import os
import asyncio
from typing import Optional, List
from pathlib import Path

from nexus.core.script_generator import CustomScriptGenerator, ScriptPurpose, ScriptLanguage
from nexus.tools.kali_tools import KaliToolsManager, ToolStatus
from nexus.ai.ollama_client import OllamaClient
from .context import pass_context, NexusContext


@click.group()
def script():
    """Script generation and management commands"""
    pass


@script.command('generate')
@click.option('--purpose', '-p', type=click.Choice([p.value for p in ScriptPurpose]), 
              required=True, help='Script purpose')
@click.option('--target', '-t', help='Target for the script')
@click.option('--language', '-l', type=click.Choice([l.value for l in ScriptLanguage]), 
              help='Script language (auto-detected if not specified)')
@click.option('--template', help='Use specific template')
@click.option('--output', '-o', help='Output file path')
@click.option('--execute', is_flag=True, help='Execute script after generation')
@pass_context
def script_generate(ctx: NexusContext, purpose: str, target: Optional[str], language: Optional[str],
                   template: Optional[str], output: Optional[str], execute: bool):
    """Generate custom penetration testing scripts using AI"""
    
    ctx.load_config()
    
    click.echo(f"Generating {purpose} script...")
    
    try:
        # Initialize script generator
        ollama_client = ctx.get_ollama_client()
        script_generator = CustomScriptGenerator(ollama_client, ctx.config)
        
        if template:
            # Generate from template
            variables = {}
            if target:
                variables['target'] = target
            
            # Collect additional variables interactively
            click.echo("Enter template variables (press Enter with empty value to finish):")
            while True:
                var_name = click.prompt("Variable name", default="", show_default=False)
                if not var_name:
                    break
                var_value = click.prompt(f"Value for {var_name}")
                variables[var_name] = var_value
            
            generated_script = script_generator.generate_from_template(template, variables)
        else:
            # Generate using AI
            target_info = {'target': target} if target else {}
            context = {
                'purpose': purpose,
                'language': language,
                'user_requirements': click.prompt("Describe specific requirements", default="")
            }
            
            # Run async generation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            generated_script = loop.run_until_complete(
                script_generator.generate_custom_script(
                    ScriptPurpose(purpose), target_info, context
                )
            )
            loop.close()
        
        click.echo(f"Generated script: {generated_script.name}")
        click.echo(f"File: {generated_script.file_path}")
        click.echo(f"🔤 Language: {generated_script.language.value}")
        
        # Save to custom output path if specified
        if output:
            with open(output, 'w') as f:
                f.write(generated_script.content)
            click.echo(f"💾 Saved to: {output}")
        
        # Execute if requested
        if execute:
            if click.confirm("Execute the generated script?"):
                click.echo("Executing script...")
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    script_generator.execute_script(generated_script.script_id)
                )
                loop.close()
                
                if result['success']:
                    click.echo("Script executed successfully")
                    if result['stdout']:
                        click.echo("Output:")
                        click.echo(result['stdout'])
                else:
                    click.echo("ERROR: Script execution failed")
                    if result['stderr']:
                        click.echo("Error:")
                        click.echo(result['stderr'])
        
    except Exception as e:
        click.echo(f"ERROR: Script generation failed: {e}", err=True)


@script.command('list')
@click.option('--purpose', '-p', type=click.Choice([p.value for p in ScriptPurpose]), 
              help='Filter by purpose')
@click.option('--language', '-l', type=click.Choice([l.value for l in ScriptLanguage]), 
              help='Filter by language')
@pass_context
def script_list(ctx: NexusContext, purpose: Optional[str], language: Optional[str]):
    """List generated scripts"""
    
    ctx.load_config()
    
    try:
        ollama_client = ctx.get_ollama_client()
        script_generator = CustomScriptGenerator(ollama_client, ctx.config)
        
        scripts = script_generator.list_generated_scripts()
        
        # Apply filters
        if purpose:
            scripts = [s for s in scripts if s.purpose.value == purpose]
        if language:
            scripts = [s for s in scripts if s.language.value == language]
        
        if not scripts:
            click.echo("No scripts found")
            return
        
        click.echo(f"📜 Found {len(scripts)} scripts:")
        click.echo()
        
        for script in scripts:
            status = "[EXECUTED]" if script.executed else "[NOT EXECUTED]"
            click.echo(f"- {script.name}")
            click.echo(f"   ID: {script.script_id}")
            click.echo(f"   Purpose: {script.purpose.value}")
            click.echo(f"   Language: {script.language.value}")
            click.echo(f"   Status: {status}")
            click.echo(f"   File: {script.file_path}")
            click.echo()
            
    except Exception as e:
        click.echo(f"ERROR: Failed to list scripts: {e}", err=True)


@script.command('execute')
@click.argument('script_id')
@click.option('--context', '-c', multiple=True, help='Execution context variables (key=value)')
@pass_context
def script_execute(ctx: NexusContext, script_id: str, context: tuple):
    """Execute a generated script"""
    
    ctx.load_config()
    
    try:
        ollama_client = ctx.get_ollama_client()
        script_generator = CustomScriptGenerator(ollama_client, ctx.config)
        
        # Parse context variables
        execution_context = {}
        for ctx_var in context:
            if '=' in ctx_var:
                key, value = ctx_var.split('=', 1)
                execution_context[key] = value
        
        click.echo(f"Executing script: {script_id}")
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            script_generator.execute_script(script_id, execution_context)
        )
        loop.close()
        
        if result['success']:
            click.echo("Script executed successfully")
            click.echo(f"Execution time: {result['execution_time']:.2f} seconds")
            
            if result['stdout']:
                click.echo("\n📤 Output:")
                click.echo(result['stdout'])
        else:
            click.echo("ERROR: Script execution failed")
            click.echo(f"Return code: {result['return_code']}")
            
            if result['stderr']:
                click.echo("\n📤 Error output:")
                click.echo(result['stderr'])
                
    except Exception as e:
        click.echo(f"ERROR: Script execution failed: {e}", err=True)


@script.command('delete')
@click.argument('script_id')
@click.option('--force', '-f', is_flag=True, help='Force deletion without confirmation')
@pass_context
def script_delete(ctx: NexusContext, script_id: str, force: bool):
    """Delete a generated script"""
    
    ctx.load_config()
    
    try:
        ollama_client = ctx.get_ollama_client()
        script_generator = CustomScriptGenerator(ollama_client, ctx.config)
        
        script = script_generator.get_script(script_id)
        if not script:
            click.echo(f"ERROR: Script not found: {script_id}")
            return
        
        if not force:
            if not click.confirm(f"Delete script '{script.name}'?"):
                click.echo("Cancelled")
                return
        
        if script_generator.delete_script(script_id):
            click.echo(f"Deleted script: {script.name}")
        else:
            click.echo(f"ERROR: Failed to delete script: {script_id}")
            
    except Exception as e:
        click.echo(f"ERROR: Script deletion failed: {e}", err=True)


@click.group()
def tools():
    """Tool management and execution commands"""
    pass


@tools.command('list')
@click.option('--category', '-c', help='Filter by category')
@click.option('--available-only', is_flag=True, help='Show only available tools')
@click.option('--format', type=click.Choice(['table', 'json']), default='table', 
              help='Output format')
@pass_context
def tools_list(ctx: NexusContext, category: Optional[str], available_only: bool, format: str):
    """List all Kali Linux tools"""
    
    ctx.load_config()
    
    try:
        tools_manager = KaliToolsManager()
        
        if format == 'json':
            report = tools_manager.get_system_report()
            click.echo(json.dumps(report, indent=2))
            return
        
        # Table format
        tools_info = tools_manager.tools
        
        # Apply filters
        if category:
            tools_info = {k: v for k, v in tools_info.items() if v.category == category}
        if available_only:
            tools_info = {k: v for k, v in tools_info.items() if v.available}
        
        if not tools_info:
            click.echo("No tools found matching criteria")
            return
        
        click.echo(f"Found {len(tools_info)} tools:")
        click.echo()
        
        # Group by category
        categories = {}
        for tool_name, tool_info in tools_info.items():
            cat = tool_info.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((tool_name, tool_info))
        
        for cat_name, cat_tools in sorted(categories.items()):
            click.echo(f"📂 {cat_name.upper().replace('_', ' ')}")
            
            for tool_name, tool_info in sorted(cat_tools):
                status = "[AVAILABLE]" if tool_info.available else "[NOT AVAILABLE]"
                enabled = "[ENABLED]" if tool_info.enabled else "[DISABLED]"
                version = f" (v{tool_info.version})" if tool_info.version else ""
                
                click.echo(f"  {status} {enabled} {tool_name}{version}")
                click.echo(f"      {tool_info.description}")
                click.echo(f"      Path: {tool_info.path}")
            click.echo()
            
    except Exception as e:
        click.echo(f"ERROR: Failed to list tools: {e}", err=True)


@tools.command('categories')
@pass_context
def tools_categories(ctx: NexusContext):
    """List tool categories"""
    
    ctx.load_config()
    
    try:
        tools_manager = KaliToolsManager()
        categories = tools_manager.get_tool_categories()
        
        click.echo("📂 Available tool categories:")
        click.echo()
        
        for category in categories:
            tools_in_cat = tools_manager.get_tools_by_category(category)
            click.echo(f"🔹 {category.replace('_', ' ').title()}: {len(tools_in_cat)} tools")
            
    except Exception as e:
        click.echo(f"ERROR: Failed to list categories: {e}", err=True)


@tools.command('info')
@click.argument('tool_name')
@pass_context
def tools_info(ctx: NexusContext, tool_name: str):
    """Get detailed information about a tool"""
    
    ctx.load_config()
    
    try:
        tools_manager = KaliToolsManager()
        tool_info = tools_manager.get_tool_info(tool_name)
        
        if not tool_info:
            click.echo(f"ERROR: Tool not found: {tool_name}")
            return
        
        status = "Available" if tool_info.available else "Not available"
        enabled = "Enabled" if tool_info.enabled else "Disabled"

        click.echo(f"Tool Information: {tool_name}")
        click.echo(f"Status: {status}")
        click.echo(f"Enabled: {enabled}")
        click.echo(f"Category: {tool_info.category}")
        click.echo(f"Description: {tool_info.description}")
        click.echo(f"Path: {tool_info.path}")
        click.echo(f"Default args: {' '.join(tool_info.default_args)}")
        click.echo(f"Timeout: {tool_info.timeout}s")
        
        if tool_info.version:
            click.echo(f"Version: {tool_info.version}")
            
    except Exception as e:
        click.echo(f"ERROR: Failed to get tool info: {e}", err=True)


@tools.command('execute')
@click.argument('tool_name')
@click.argument('target')
@click.option('--args', '-a', multiple=True, help='Additional arguments')
@click.option('--timeout', '-t', type=int, help='Execution timeout in seconds')
@click.option('--output', '-o', help='Save output to file')
@click.option('--format', type=click.Choice(['raw', 'json']), default='raw', 
              help='Output format')
@pass_context
def tools_execute(ctx: NexusContext, tool_name: str, target: str, args: tuple, timeout: Optional[int],
                 output: Optional[str], format: str):
    """Execute a tool against a target"""
    
    ctx.load_config()
    
    try:
        tools_manager = KaliToolsManager()
        
        if tool_name not in tools_manager.get_available_tools():
            click.echo(f"ERROR: Tool not available: {tool_name}")
            return
        
        click.echo(f"Executing {tool_name} against {target}")
        
        # Build execution parameters
        kwargs = {}
        if timeout:
            kwargs['timeout'] = timeout
        
        # Add custom arguments
        for i, arg in enumerate(args):
            kwargs[f'arg_{i}'] = arg
        
        # Execute tool
        result = tools_manager.execute_tool(tool_name, target, **kwargs)
        
        # Display results
        if result.status == ToolStatus.SUCCESS:
            click.echo("Tool executed successfully")
        else:
            click.echo(f"ERROR: Tool execution failed: {result.status.value}")

        click.echo(f"Execution time: {result.execution_time:.2f} seconds")
        click.echo(f"Command: {result.command}")
        
        if result.error_message:
            click.echo(f"ERROR: {result.error_message}")
        
        # Output results
        if format == 'json':
            output_data = {
                'tool': result.tool_name,
                'command': result.command,
                'status': result.status.value,
                'execution_time': result.execution_time,
                'raw_output': result.raw_output,
                'parsed_data': result.parsed_data,
                'error_message': result.error_message
            }
            
            if output:
                with open(output, 'w') as f:
                    json.dump(output_data, f, indent=2)
                click.echo(f"💾 Results saved to: {output}")
            else:
                click.echo("\n📤 Results:")
                click.echo(json.dumps(output_data, indent=2))
        else:
            # Raw format
            if output:
                with open(output, 'w') as f:
                    f.write(result.raw_output)
                click.echo(f"💾 Output saved to: {output}")
            else:
                if result.raw_output:
                    click.echo("\n📤 Output:")
                    click.echo(result.raw_output)
                    
    except Exception as e:
        click.echo(f"ERROR: Tool execution failed: {e}", err=True)


@tools.command('scan')
@click.argument('target')
@click.option('--category', '-c', help='Scan with tools from specific category')
@click.option('--tools', '-t', multiple=True, help='Specific tools to use')
@click.option('--output-dir', '-o', help='Output directory for results')
@click.option('--parallel', '-p', is_flag=True, help='Run tools in parallel')
@pass_context
def tools_scan(ctx: NexusContext, target: str, category: Optional[str], tools: tuple,
               output_dir: Optional[str], parallel: bool):
    """Run multiple tools against a target"""
    
    ctx.load_config()
    
    try:
        tools_manager = KaliToolsManager()
        
        # Determine tools to run
        if tools:
            selected_tools = list(tools)
        elif category:
            selected_tools = tools_manager.get_tools_by_category(category)
        else:
            # Default reconnaissance tools
            selected_tools = tools_manager.get_tools_by_category('network_scanner')
        
        # Filter available tools
        available_tools = [t for t in selected_tools if t in tools_manager.get_available_tools()]
        
        if not available_tools:
            click.echo("ERROR: No available tools found for scanning")
            return
        
        click.echo(f"Scanning {target} with {len(available_tools)} tools")
        click.echo(f"Tools: {', '.join(available_tools)}")
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            click.echo(f"📁 Output directory: {output_dir}")
        
        results = {}
        
        if parallel:
            click.echo("Running tools in parallel...")
            # TODO: Implement parallel execution
        else:
            click.echo("🔄 Running tools sequentially...")
            
            for tool_name in available_tools:
                click.echo(f"\nRunning {tool_name}...")
                
                result = tools_manager.execute_tool(tool_name, target)
                results[tool_name] = result
                
                if result.status == ToolStatus.SUCCESS:
                    click.echo(f"{tool_name} completed successfully")
                else:
                    click.echo(f"ERROR: {tool_name} failed: {result.status.value}")
                
                # Save individual results
                if output_dir:
                    result_file = os.path.join(output_dir, f"{tool_name}_result.json")
                    with open(result_file, 'w') as f:
                        json.dump({
                            'tool': result.tool_name,
                            'command': result.command,
                            'status': result.status.value,
                            'execution_time': result.execution_time,
                            'raw_output': result.raw_output,
                            'parsed_data': result.parsed_data
                        }, f, indent=2)
        
        # Generate summary
        successful = sum(1 for r in results.values() if r.status == ToolStatus.SUCCESS)
        total_time = sum(r.execution_time for r in results.values())
        
        click.echo(f"\nScan Summary:")
        click.echo(f"Successful: {successful}/{len(results)}")
        click.echo(f"Total time: {total_time:.2f} seconds")
        
        if output_dir:
            summary_file = os.path.join(output_dir, "scan_summary.json")
            with open(summary_file, 'w') as f:
                json.dump({
                    'target': target,
                    'tools_used': available_tools,
                    'successful_tools': successful,
                    'total_tools': len(results),
                    'total_execution_time': total_time,
                    'results': {k: v.status.value for k, v in results.items()}
                }, f, indent=2)
            click.echo(f"📄 Summary saved to: {summary_file}")
            
    except Exception as e:
        click.echo(f"ERROR: Scan failed: {e}", err=True)


# Add the command groups to the main CLI
def register_commands(cli):
    """Register additional commands with the main CLI"""
    from .ai_commands import register_ai_commands
    from .dashboard import register_dashboard_commands
    from .evasion_commands import register_evasion_commands
    
    cli.add_command(script)
    cli.add_command(tools)
    register_ai_commands(cli)
    register_dashboard_commands(cli)
    register_evasion_commands(cli)