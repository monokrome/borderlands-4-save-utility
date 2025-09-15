# Borderlands 4 Save Encrypter and Decrypter

A tool to decrypt and encrypt Borderlands 4 save files for editing. Feel free to use this code in any way you see fit, just credit me! Enjoy.

## Requirements

- [Python 3.7+](https://www.python.org/downloads/) - Download and install Python
- [pip](https://pip.pypa.io/en/stable/installation/) - Usually comes with Python
- [pycryptodome](https://pypi.org/project/pycryptodome/) - Cryptography library (installed via pip)

## Installation (venv recommended)

```bash
pip install -r requirements.txt
```

## Usage

### View Help

To see detailed usage information with examples:

```bash
python blcrypt.py decrypt --help
python blcrypt.py encrypt --help
```

### Decrypt a Save File

Convert a `.sav` file to editable YAML:

```bash
python blcrypt.py decrypt -in 1.sav -out save.yaml -id YOUR_STEAM_ID
```

### Edit the YAML

Open `save.yaml` in any text editor and modify the values you want to change.

### Encrypt Back to Save File

Convert the edited YAML back to a `.sav` file:

```bash
python blcrypt.py encrypt -in save.yaml -out 1.sav -id YOUR_STEAM_ID
```

## Important Notes

- **Backup your save files** before using this tool
- Your Steam ID is the 17-digit number that starts with `7656119...`
- On Windows, you can find this ID as the folder location: `C:\Users\{username}\Documents\My Games\Borderlands 4\Saved\SaveGames` - the folder name in here is the ID to use
- The Steam ID **MUST** match the original save file owner
- If you get PKCS7 or zlib errors, verify your Steam ID is correct
- Encrypt/decrypt the **NUMBERED** saves (1.sav, 2.sav, etc.)
- Open an issue if you're having trouble and maybe I or someone else will assist/troubleshoot

## Examples

```bash
# Decrypt
python blcrypt.py decrypt -in 1.sav -id 7656..

# Edit the generated 1.yaml file values with any text editor

# Encrypt back
python blcrypt.py encrypt -in 1.yaml -id 7656..
```

## Troubleshooting

- **"PKCS7 padding error"**: Wrong Steam ID
- **"zlib decompression error"**: Wrong Steam ID or corrupted file
- **File size not multiple of 16**: File may be corrupted or not a valid BL4 save file

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

