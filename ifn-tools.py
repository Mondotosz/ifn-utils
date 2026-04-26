#!/mnt/home/mon/github/HEIG/IFN/tools/.venv/bin/python
import typer
from ifn.mbr import mbr_app
from ifn.gpt import gpt_app
from ifn.timezone import tz_app
from ifn.unalloc import unalloc_app

app = typer.Typer(help="MBR Partition Table Analyzer")

app.add_typer(mbr_app, name="mbr")
app.add_typer(gpt_app, name="gpt")
app.add_typer(tz_app, name="tz")
app.add_typer(unalloc_app, name="unalloc")


if __name__ == "__main__":
    app()
