#!/usr/bin/env python3
"""
GenIA - Vulnerability Validation System
A CrewAI-based solution for validating vulnerabilities through static and dynamic analysis.
"""

import click
import os
import sys
import zipfile
import tempfile
import shutil
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.align import Align

from src.crew import VulnerabilityValidationCrew
from src.utils.database import DatabaseManager
import logging

# Load environment variables
load_dotenv()

console = Console()
logger = logging.getLogger(__name__)

def extract_zip_to_temp(zip_path):
    """Extract ZIP file to a temporary directory and return the path."""
    temp_dir = tempfile.mkdtemp(prefix='genia_analysis_')
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        console.print(f"[green]✓[/green] ZIP extracted to temporary directory: {temp_dir}")
        return temp_dir
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to extract ZIP file: {e}")

def cleanup_temp_directory(temp_dir):
    """Clean up temporary directory."""
    try:
        shutil.rmtree(temp_dir)
        console.print(f"[green]✓[/green] Temporary directory cleaned up: {temp_dir}")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Failed to clean up temporary directory: {e}")



@click.command()
@click.option('--pdf', required=True, help='Path to the vulnerability report PDF')
@click.option('--source', help='Path to the source code directory')
@click.option('--url', help='Target application URL for dynamic testing')
@click.option('--model', default='gpt-4o-mini', help='LLM model to use (default: gpt-4o-mini)')
@click.option('--only-read', is_flag=True, help='Execute only the reader agent')
@click.option('--only-static', is_flag=True, help='Execute only the static analysis agent')
@click.option('--only-dynamic', is_flag=True, help='Execute only the dynamic analysis agent')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--output', '-o', help='Output file for results (optional)')
@click.option('--lang', default='en', help='Language for the final result (e.g., es for Spanish, en for English)')
def main(pdf, source, url, model, only_read, only_static, only_dynamic, verbose, output, lang):
    """GenIA - Vulnerability Validation System using CrewAI"""
    
    # Configure logging based on verbose flag
    if verbose:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Validate inputs
    if not Path(pdf).exists():
        console.print(f"[red]Error: PDF file '{pdf}' not found[/red]")
        sys.exit(1)
    
    # Check for conflicting flags
    exclusive_flags = [only_read, only_static, only_dynamic]
    if sum(exclusive_flags) > 1:
        console.print("[red]Error: Only one of --only-read, --only-static, --only-dynamic can be used[/red]")
        sys.exit(1)
    
    # Handle ZIP file extraction
    temp_dir = None
    original_source = source
    
    if source and source.lower().endswith('.zip'):
        if not Path(source).exists():
            console.print(f"[red]Error: ZIP file '{source}' not found[/red]")
            sys.exit(1)
        try:
            temp_dir = extract_zip_to_temp(source)
            source = temp_dir
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
    
    # Validate required arguments based on mode
    if only_static or (not only_read and not only_dynamic):
        if not source:
            console.print("[red]Error: --source is required for static analysis mode[/red]")
            sys.exit(1)
        if not Path(source).exists():
            console.print(f"[red]Error: Source directory '{source}' not found[/red]")
            sys.exit(1)
    
    if only_dynamic or (not only_read and not only_static):
        if not url:
            console.print("[red]Error: --url is required for dynamic analysis mode[/red]")
            sys.exit(1)
    
    # Display banner
    console.print(Panel.fit(
        "[bold blue]GenIA - Vulnerability Validation System[/bold blue]\n"
        "[dim]Powered by CrewAI and ReAct Methodology[/dim]",
        border_style="blue"
    ))
    
    # Initialize database
    try:
        db_manager = DatabaseManager()
        if db_manager.connect():
            console.print("[green]✓[/green] Database connection established")
        else:
            console.print("[yellow]⚠[/yellow] Database connection failed, results will be saved to file only")
    except Exception as e:
        console.print(f"[red]✗[/red] Database initialization failed: {e}")
        sys.exit(1)
    
    # Determine execution mode first
    if only_read:
        mode = "reader"
    elif only_static:
        mode = "static"
    elif only_dynamic:
        mode = "dynamic"
    else:
        mode = "full"
    
    # Create initial assessment document in database
    document_id = None
    try:
        logger.info(f"Creating assessment document with: pdf={pdf}, source={original_source if temp_dir else source}, url={url}, model={model}, mode={mode}")
        document_id = db_manager.create_assessment_document(
            pdf_path=pdf,
            source_path=original_source if temp_dir else source,
            target_url=url,
            model_used=model,
            execution_mode=mode
        )
        if document_id:
            logger.info(f"Assessment document created successfully with ID: {document_id}")
            console.print(f"[green]✓[/green] Assessment document created with ID: {document_id}")
        else:
            logger.error("create_assessment_document returned None")
            console.print(f"[yellow]⚠[/yellow] Failed to create initial document: create_assessment_document returned None")
    except Exception as e:
        logger.error(f"Exception during document creation: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        console.print(f"[yellow]⚠[/yellow] Failed to create initial document: {e}")
    
    # Initialize crew with database tracking
    crew = VulnerabilityValidationCrew(
        model=model,
        verbose=verbose,
        language=lang,
        document_id=document_id,
        db_manager=db_manager
    )
    
    console.print(f"[cyan]Execution mode:[/cyan] {mode}")
    console.print(f"[cyan]Model:[/cyan] {model}")
    console.print(f"[cyan]PDF:[/cyan] {pdf}")
    console.print(f"[cyan]Source:[/cyan] {original_source if temp_dir else source}")
    console.print(f"[cyan]URL:[/cyan] {url}")
    
    # Execute analysis
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Executing vulnerability validation...", total=None)
            
            result = crew.execute(
                pdf_path=pdf,
                source_path=source,
                target_url=url,
                mode=mode
            )
            
            progress.update(task, description="Saving results to database...")
            
            # Complete the assessment in the database
            if document_id:
                try:
                    db_manager.complete_assessment(document_id, result)
                    result_id = document_id
                    logger.info(f"Successfully completed assessment with ID: {result_id}")
                    console.print(f"[green]✓[/green] Assessment completed and saved with ID: {result_id}")
                except Exception as e:
                    logger.error(f"Failed to complete assessment: {e}")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
                    console.print(f"[red]✗[/red] Failed to complete assessment: {e}")
                    result_id = None
            else:
                logger.error("No document ID available - assessment creation failed")
                console.print(f"[red]✗[/red] Assessment creation failed - no document ID available")
                result_id = None
            
            progress.update(task, description="Analysis complete!")
        
        # Analysis completed - results saved to database
        
        # Save to file if requested
        if output:
            import json
            with open(output, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            console.print(f"[green]✓[/green] Results saved to {output}")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Analysis failed: {e}")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)
    finally:
        # Clean up temporary directory if it was created
        if temp_dir:
            cleanup_temp_directory(temp_dir)

if __name__ == '__main__':
    main()