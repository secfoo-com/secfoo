from pathlib import Path

def download(name):
    return (Path("/srv/downloads") / name).read_bytes()
