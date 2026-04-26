import typer
from typing import Annotated
from .utils import console, format_bytes
from rich.table import Table
from rich.panel import Panel
from pathlib import Path
import pandas as pd

unalloc_app = typer.Typer(help="Parsing unalloc tables from autopsy")


@unalloc_app.command()
def analyze_space(
    csv_path: Annotated[
        Path, typer.Argument(..., help="Path to the Autopsy CSV report")
    ],
    filter_unallocated: Annotated[
        bool,
        typer.Option("--all", "-a", help="Show all files instead of just unallocated"),
    ] = True,
):
    if not csv_path.exists():
        console.print(f"[bold red]Error:[/bold red] File {csv_path} not found.")
        raise typer.Exit(code=1)

    with console.status("[bold green]Parsing forensic data..."):
        # Load the CSV
        df = pd.read_csv(csv_path)

        # Standardize column names (Autopsy sometimes adds spaces or quotes)
        df.columns = df.columns.str.strip().str.replace('"', "")

        # Filter for unallocated space by default
        if filter_unallocated:
            df = df[df["Name"].str.contains("Unalloc", case=False, na=False)]

        total_bytes = df["Size"].sum()
        file_count = len(df)

    # Create Rich Table
    table = Table(title=f"Space Analysis: {csv_path.name}")
    table.add_column("Item Name", style="cyan")
    table.add_column("Size (Bytes)", justify="right", style="magenta")
    table.add_column("Human Readable", justify="right", style="green")

    # Show top 10 largest chunks to keep output clean
    top_chunks = df.sort_values(by="Size", ascending=False).head(10)

    for _, row in top_chunks.iterrows():
        table.add_row(str(row["Name"]), f"{row['Size']:,}", format_bytes(row["Size"]))

    console.print(table)

    # Summary Panel
    summary_text = (
        f"Total Entries: [bold]{file_count}[/bold]\n"
        f"Total Size: [bold yellow]{total_bytes:,} Bytes[/bold yellow]\n"
        f"Human Readable: [bold reverse green] {format_bytes(total_bytes)} [/bold reverse green]"
    )
    console.print(Panel(summary_text, title="Final Summary", expand=False))
