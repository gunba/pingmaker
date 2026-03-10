## Building from Source

Requires Python 3.12+, [Nuitka](https://nuitka.net/), and a C compiler (MSVC or MinGW):

```bash
pip install nuitka
python -m nuitka --standalone --onefile --windows-console-mode=disable --enable-plugin=tk-inter --include-data-file=skills.json=skills.json --output-filename=pingmaker.exe main.py
```

Produces a standalone `pingmaker.exe`.
