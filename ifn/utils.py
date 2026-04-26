from rich.console import Console

console = Console()


def format_size(sectors: int | float) -> str:
    """Converts sectors to a human readable string (assuming 512b sectors)."""
    return format_bytes(sectors * 512)


def format_bytes(size: int | float) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if size < 1024.0:
            return f"{size:3.2f} {unit}"
        size /= 1024.0
    return f"{size:3.2f} PiB"
