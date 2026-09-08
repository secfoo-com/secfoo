"""PyInstaller entry point. Kept separate from src/secfoo/cli.py since
PyInstaller needs a real script file to analyze, not a package:module
reference -- this just forwards straight into the real CLI.
"""

from secfoo.cli import main

if __name__ == "__main__":
    main()
