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


@app.command()
def workspace(
    port: int = typer.Option(8765, "--port", min=1, max=65535, help="Loopback listening port"),
    open_browser: bool = typer.Option(True, "--open-browser/--no-browser", help="Open local workspace"),
):
    """Open the local graphical interface for inspecting exported evidence."""
    from ahmad_sec.workspace import serve

    try:
        serve(port=port, open_browser=open_browser)
    except OSError as exc:
        console.print(f"Cannot start workspace: {type(exc).__name__}", markup=False)
        raise typer.Exit(code=2) from exc


if __name__ == "__main__":
    app()
