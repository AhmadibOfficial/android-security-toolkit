import typer
from rich.console import Console
from ahmad_sec.commands import apk

app = typer.Typer(
    name="ahmad-sec",
    help="AHMAD-IB Android Security Toolkit",
    no_args_is_help=True,
)
console = Console()
app.add_typer(apk.app, name="apk")


@app.command()
def version():
    """Display the toolkit version."""
    console.print("AHMAD-IB Android Security Toolkit v0.1.0")


@app.command()
def info():
    """Display toolkit information."""
    console.print("AHMAD-IB ANDROID SECURITY LAB", style="bold")
    console.print("Android application security assessment toolkit")
    console.print("Research • Analysis • Evidence • Reporting")


if __name__ == "__main__":
    app()
