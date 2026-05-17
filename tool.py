import typer

from ifn.cli import deps, fv, hives, image, index, lnk, mft, partitions, time, trash, vbr

app = typer.Typer(name="tool", help="HEIG-VD IFN forensics toolkit")
app.add_typer(partitions.app, name="partitions")
app.add_typer(vbr.app, name="vbr")
app.add_typer(lnk.app, name="lnk")
app.add_typer(trash.app, name="trash")
app.add_typer(mft.app, name="mft")
app.add_typer(index.app, name="index")
app.add_typer(hives.app, name="hives")
app.add_typer(fv.app, name="fv")
app.add_typer(image.app, name="image")
app.add_typer(time.app, name="time")
app.add_typer(deps.app, name="deps")


@app.callback()
def root_callback(
    ctx: typer.Context,
    json_out: bool = typer.Option(False, "--json", help="Output as JSON to stdout (for jq)"),
    simple: bool = typer.Option(False, "--simple", help="Plain output without colors or markup"),
) -> None:
    from ifn import context
    context.configure(json_out=json_out, simple=simple)


def main():
    app()


if __name__ == "__main__":
    main()
