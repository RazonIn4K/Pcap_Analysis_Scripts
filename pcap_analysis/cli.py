import typer
from typing import Optional, List
from enum import Enum
from pathlib import Path
import logging
import sys
import time
import os
import json
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax

from .core.config import Config
from .core.logging_config import configure_logging
from .core.dependencies import check_all_dependencies
from .core.errors import handle_error, PcapAnalysisError
# main module has been removed - functionality moved elsewhere

# Create Typer app
app = typer.Typer(
    help="Advanced PCAP Analysis Tool",
    add_completion=True
)

# Check if we're in a terminal that supports color
def supports_color():
    """Check if the terminal supports color."""
    # Check NO_COLOR environment variable
    if os.environ.get("NO_COLOR", ""):
        return False
    
    # Check if stdout is a TTY
    if not sys.stdout.isatty():
        return False
    
    # Check platform-specific terminal support
    plat = sys.platform
    supported_platform = plat != "Pocket PC" and (plat != "win32" or "ANSICON" in os.environ)
    
    # Check for Windows Terminal or ConEmu
    if plat == "win32":
        return supported_platform or "WT_SESSION" in os.environ or "ConEmuANSI" in os.environ
    
    return supported_platform

# Create console with appropriate settings
console = Console(highlight=supports_color(), emoji=supports_color())

class OutputFormat(str, Enum):
    """Output format options"""
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"
    HTML = "html"
    ALL = "all"

@app.command()
def analyze(
    pcap_file: Path = typer.Argument(
        ..., 
        exists=True, 
        dir_okay=False, 
        readable=True, 
        help="Path to the PCAP file to analyze"
    ),
    config_file: Optional[Path] = typer.Option(
        None, 
        "--config", 
        "-c", 
        help="Path to configuration file"
    ),
    output_dir: Path = typer.Option(
        "./output", 
        "--output-dir", 
        "-o", 
        help="Directory for output files"
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.JSON, 
        "--format", 
        "-f", 
        help="Output format"
    ),
    basic: bool = typer.Option(
        False, 
        "--basic", 
        "-b", 
        help="Perform basic analysis only"
    ),
    full: bool = typer.Option(
        False, 
        "--full", 
        help="Perform full analysis (all modules)"
    ),
    detect_web: bool = typer.Option(
        False, 
        "--detect-web", 
        help="Detect web-based attacks"
    ),
    detect_network: bool = typer.Option(
        False, 
        "--detect-network", 
        help="Detect network-based attacks"
    ),
    detect_malware: bool = typer.Option(
        False, 
        "--detect-malware", 
        help="Detect malware activity"
    ),
    time_filter: str = typer.Option(
        "", 
        "--time-filter", 
        "-t", 
        help="Time filter for analysis (Wireshark display filter format)"
    ),
    custom_signatures: Optional[Path] = typer.Option(
        None, 
        "--custom-signatures", 
        help="Path to custom detection signatures file"
    ),
    ioc_file: Optional[Path] = typer.Option(
        None, 
        "--ioc-file", 
        help="Path to IOC file for checking"
    ),
    visualize: bool = typer.Option(
        False, 
        "--visualize", 
        "-v", 
        help="Generate visualizations"
    ),
    verbose: bool = typer.Option(
        False, 
        "--verbose", 
        help="Enable verbose output"
    ),
    log_file: Optional[Path] = typer.Option(
        None, 
        "--log-file", 
        help="Path to log file"
    ),
    log_level: str = typer.Option(
        "INFO", 
        "--log-level", 
        help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    ),
):
    """
    Analyze a PCAP file for security threats and anomalies.
    
    This command performs comprehensive analysis of a PCAP file to detect
    various security threats and anomalies, including web attacks, network
    attacks, and malware activity.
    """
    start_time = time.time()
    
    # Configure logging
    log_level_num = getattr(logging, log_level.upper(), logging.INFO)
    logger = configure_logging(log_level_num, log_file, True)
    
    try:
        # Show banner
        console.print("[bold blue]PCAP Analyzer[/bold blue] - Advanced Network Security Analysis Tool", highlight=False)
        console.print(f"Analyzing file: [bold]{pcap_file}[/bold]")
        
        # Check dependencies
        with console.status("[bold green]Checking dependencies...[/bold green]"):
            check_all_dependencies()
        
        # Load configuration
        config = Config(config_file)
        
        # Override config with command line arguments
        if output_dir:
            config.set("output", "directory", str(output_dir))
        if output_format:
            config.set("output", "format", output_format.value)
        if visualize:
            config.set("output", "visualize", visualize)
        
        # Create output directory
        output_dir = Path(config.get("output", "directory"))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare analysis options
        options = {
            "basic": basic,
            "full": full,
            "detect_web": detect_web,
            "detect_network": detect_network,
            "detect_malware": detect_malware,
            "time_filter": time_filter,
            "custom_signatures": custom_signatures,
            "ioc_file": ioc_file,
            "visualize": visualize,
            "verbose": verbose
        }
        
        # Run analysis with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/bold green]"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[green]Analyzing PCAP file...", total=100)
            
            # Update progress callback
            def update_progress(percent, message):
                progress.update(task, completed=percent, description=f"[bold green]{message}[/bold green]")
            
            # Run analysis with imported functions or implement directly 
            # The main.analyze_pcap functionality needs to be reimplemented or imported from elsewhere
            # For now, we'll create a placeholder for results
            results = {"status": "Analysis function needs to be reimplemented"}
            
            # Complete progress
            progress.update(task, completed=100, description="[bold green]Analysis complete![/bold green]")
        
        # Generate output
        output_format_value = output_format.value
        output_base = output_dir / pcap_file.stem
        
        with console.status("[bold green]Generating output...[/bold green]"):
            # Output generation needs to be reimplemented
            console.print("[yellow]Output generation functionality needs to be reimplemented[/yellow]")
            
            # Save basic results as JSON for now
            output_file = f"{output_base}_analysis.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        
        # Show summary
        console.print("\n[bold green]Analysis Summary:[/bold green]")
        
        # Create summary table
        table = Table(title="Detection Results")
        table.add_column("Category", style="cyan")
        table.add_column("Detections", style="magenta")
        table.add_column("Severity", style="red")
        
        # Add rows for each category
        categories = {
            "Web Attacks": "web_attacks",
            "Network Attacks": "network_attacks",
            "Malware Activity": "malware_activity"
        }
        
        for category_name, category_key in categories.items():
            if category_key in results:
                detections = len(results[category_key])
                severity = "High" if detections > 5 else "Medium" if detections > 0 else "Low"
                table.add_row(category_name, str(detections), severity)
        
        console.print(table)
        
        # Show execution time
        execution_time = time.time() - start_time
        console.print(f"\nExecution time: [bold]{execution_time:.2f}[/bold] seconds")
        
        # Show output location
        console.print(f"Results saved to: [bold]{output_dir}[/bold]")
        
        return 0
        
    except PcapAnalysisError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        logger.error(f"Analysis failed: {e}")
        return e.error_code.value
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        logger.exception(f"Unexpected error: {e}")
        return 1

@app.command()
def check(
    pcap_file: Path = typer.Argument(
        ..., 
        exists=True, 
        dir_okay=False, 
        readable=True, 
        help="Path to the PCAP file to check"
    )
):
    """
    Perform a quick check of a PCAP file.
    
    This command performs a basic analysis of a PCAP file to provide
    a quick overview of its contents.
    """
    try:
        # Show banner
        console.print("[bold blue]PCAP Analyzer[/bold blue] - Quick Check", highlight=False)
        console.print(f"Checking file: [bold]{pcap_file}[/bold]")
        
        # Check dependencies
        with console.status("[bold green]Checking dependencies...[/bold green]"):
            check_all_dependencies()
        
        # Get basic file info
        with console.status("[bold green]Analyzing file...[/bold green]"):
            # get_file_info functionality needs to be reimplemented
            # For now, we'll create a simple placeholder
            file_info = {
                "name": pcap_file.name,
                "path": str(pcap_file),
                "size": pcap_file.stat().st_size,
                "modified": pcap_file.stat().st_mtime
            }
        
        # Show file info
        console.print("\n[bold green]File Information:[/bold green]")
        
        # Create info table
        table = Table()
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        
        for key, value in file_info.items():
            table.add_row(key, str(value))
        
        console.print(table)
        
        return 0
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1

@app.command()
def version():
    """Show version information."""
    # Since __init__.py with version info was removed, hardcode the version
    __version__ = "2.0.0"
    console.print(f"[bold blue]PCAP Analyzer[/bold blue] version [bold]{__version__}[/bold]")
    return 0

@app.command()
def accessibility(
    enable: bool = typer.Option(
        True, 
        "--enable/--disable", 
        help="Enable or disable accessibility mode"
    )
):
    """
    Configure accessibility settings.
    
    This command enables or disables accessibility features like
    high contrast mode and screen reader optimizations.
    """
    config_dir = get_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = config_dir / "accessibility.json"
    
    settings = {
        "high_contrast": enable,
        "screen_reader_optimized": enable,
        "reduce_animations": enable
    }
    
    with open(config_file, "w") as f:
        json.dump(settings, f, indent=2)
    
    if enable:
        console.print("[bold green]Accessibility mode enabled[/bold green]")
        console.print("The following features are now active:")
        console.print("• High contrast mode")
        console.print("• Screen reader optimizations")
        console.print("• Reduced animations")
    else:
        console.print("[bold yellow]Accessibility mode disabled[/bold yellow]")
    
    return 0

def main():
    """Entry point for the CLI."""
    return app()

if __name__ == "__main__":
    sys.exit(main())
