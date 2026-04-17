import typer
from ifn.mbr import mbr_app
from ifn.gpt import gpt_app

app = typer.Typer(help="MBR Partition Table Analyzer")

app.add_typer(mbr_app, name="mbr")
app.add_typer(gpt_app, name="gpt")


if __name__ == "__main__":
    app()
