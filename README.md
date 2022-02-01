# RonnieColemanYARAParser

This script is named after Ronnie Coleman, and peforms bulk lifts on arbitary file features using YARA console logging.

[![asciicast](https://asciinema.org/a/Zii6WwzVDhxCfNR2xW0EC7SC1.svg)](https://asciinema.org/a/Zii6WwzVDhxCfNR2xW0EC7SC1)

## Requirements

- Fresh compile of YARA 4.2.0-rc1
- Bunch of python crap

## Usage Examples

ronnie.py --things hash.md5 pe.timestamp pe.dll_name pe.export_timestamp pe.number_of_exports pe.rich_signature.key filesize --path ~/yarafiddling/samps

ronnie.py -t hash.md5 filesize pe.timestamp pe.dll_name  -p ~/yarafiddling/samps -s pe.dll_name

ronnie.py -t hash.md5 filesize pe.timestamp pe.entry_point --path ~/yarafiddling/samps

ronnie.py -t hash.md5 filesize pe.timestamp "uint16be(0)" --path ~/yarafiddling/samps --sort pe.timestamp 
