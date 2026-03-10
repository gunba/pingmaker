## Building from Source

Requires Python 3.12+, [Nuitka](https://nuitka.net/), and a C compiler (MSVC or MinGW):

```bash
pip install nuitka
python -m nuitka --standalone --onefile --windows-console-mode=disable --enable-plugin=tk-inter --include-data-file=skills.json=skills.json --include-package-data=pydivert --include-data-file=pydivert/windivert_dll/WinDivert.dll=pydivert/windivert_dll/WinDivert.dll --windows-icon-from-ico=pingmaker.ico --windows-company-name=Pingmaker --windows-product-name=Pingmaker --windows-file-description="Latency compensation for Aion 2" --windows-product-version=2.0.0 --windows-file-version=2.0.0 --output-filename=pingmaker.exe main.py
```

Produces a standalone `pingmaker.exe`.
