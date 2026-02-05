import typer
from rich.console import Console
from rich.table import Table
from core.models import Target, TargetType
from modules.recon_nmap import NmapScanner

app = typer.Typer(help="OWASP & Multi-Vector Security Scanner")
console = Console()

@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL/IP"),
    type: TargetType = typer.Option(TargetType.WEB, "--type", "-m", help="Scan profile")
):
    """
    Executes the active scanning modules against the target.
    """
    console.print(f"[bold green]Starting Scan on:[/bold green] {target}")
    
    current_target = Target(input=target, type=type)
    
    # Aici vom avea o listă lungă de module în viitor
    active_modules = [NmapScanner()]
    results = []

    with console.status("[bold green]Running security checks...[/bold green]"):
        for module in active_modules:
            if module.check_prerequisites():
                # Rulăm modulul
                module_results = module.run(current_target)
                results.extend(module_results)
            else:
                console.print(f"[bold red]Tool {module.required_tools} missing![/bold red]")

    # Afișarea rezultatelor
    if results:
        table = Table(title=f"Scan Results for {target}")
        table.add_column("Severity", style="red")
        table.add_column("Vulnerability", style="white")
        table.add_column("Tool", style="blue")
        
        for res in results:
            table.add_row(res.severity.value, res.name, res.tool_used)
        console.print(table)
    else:
        console.print("[yellow]No vulnerabilities found.[/yellow]")

if __name__ == "__main__":
    app()