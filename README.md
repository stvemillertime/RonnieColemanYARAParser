# RonnieColemanYARAParser

This script is named after Ronnie Coleman, and peforms bulk lifts on arbitary file features using YARA console logging.

[![asciicast](https://asciinema.org/a/Zii6WwzVDhxCfNR2xW0EC7SC1.svg)](https://asciinema.org/a/Zii6WwzVDhxCfNR2xW0EC7SC1)

### Requirements

- Fresh compile of YARA 4.2.0-rc1 (https://yara.readthedocs.io/en/stable/gettingstarted.html)
- Bunch of python crap

### Notes

This was really designed for me to bulk build an on-demand table for file features I wanted, and to see the values I specified using YARA's own technology. This allows me to quickly view, stack, organize the "surface area" of a file so I can turn around with the ones I want and create YARA rules. This is a terrible script and bad python, does basically no input checking and no error handling, so beware that it will get jacked up if you try to do crazy things. 

- Start with PE features, things from modules, and top-level (non array) things that are easily parsed out by YARA.
- hash.md5 - this is the only hashing thing I included, it would probably be better not to do this at all, but c'est la vie
- If something doesnt work because of your terminal or whatever, maybe try putting it in quotes so argparse can do its thing
- Things I like: hash.md5, filesize, pe.timestamp pe.dll_name, pe.export_timestamp, pe.pdb_path, etc
- Go shop around in the manual for more good ones (https://yara.readthedocs.io/en/stable/modules/pe.html)

### Usage Examples

```ronnie.py --things hash.md5 pe.timestamp pe.dll_name pe.export_timestamp pe.number_of_exports pe.rich_signature.key filesize --path ~/yarafiddling/samps

ronnie.py -t hash.md5 filesize pe.timestamp pe.dll_name  -p ~/yarafiddling/samps -s pe.dll_name

ronnie.py -t hash.md5 filesize pe.timestamp pe.entry_point --path ~/yarafiddling/samps

ronnie.py -t hash.md5 filesize pe.timestamp "uint16be(0)" --path ~/yarafiddling/samps --sort pe.timestamp 
```

### Full Output Example

```
CTO-MBP\steve >> % python3 ronnie.py -t hash.md5 "uint16be(60)" filesize pe.timestamp pe.dll_name  --path ~/yarafiddling/samps --sort pe.timestamp                   

[Bleep Blop Directory] Folder scanned: /Users/steve/yarafiddling/samps

[:great-job:] LIGHT WEIGHT! Heres the sorted table:

+----------------------------------+----------------+----------+----------------------------------+--------------------------+
| hash.md5                         | uint16be(60)   | filesize | pe.timestamp                     | pe.dll_name              |
+----------------------------------+----------------+----------+----------------------------------+--------------------------+
| 0d7cefb89b6d31ab784bd4e0b0f0eaad | 0x1700 (5888)  | 6427399  |                                  |                          |
| 3a5a7ced739923f929234beefcef82b5 | 0xe00 (3584)   | 10608640 |                                  |                          |
| 77c73b8b1846652307862dd66ec09ebf | 0xf800 (63488) | 509952   |                                  |                          |
| 5bd5605725ec34984efbe81f8d39507a | 0x1 (1)        | 102912   | 1999-10-21 00:49:30 (940481370)  |                          |
| 802a7c343f0d58052800dd64e0c911cf | 0xe800 (59392) | 36528    | 2011-01-13 12:33:11 (1294939991) |                          |
| 91456bf6edbf9a24a1423bcbd6c7a5fe | 0xe800 (59392) | 35014    | 2011-01-16 08:28:36 (1295184516) |                          |
| c2d07d954f6e6126a784e7770ad32643 | 0xf000 (61440) | 914600   | 2018-11-07 04:59:27 (1541584767) | QuickSearchFile.dll      |
| 3ecfc67294923acdf6bd018a73f6c590 | 0xe000 (57344) | 71168    | 2020-04-12 16:57:49 (1586725069) |                          |
| 837ed1ac9dbae2d8ec134c28481e4a10 | 0x8000 (32768) | 56320    | 2021-03-19 08:17:39 (1616156259) |                          |
| e9d7ea2dd867d6f6de4a69aead9312e9 | 0x801 (2049)   | 241664   | 2021-04-30 13:10:02 (1619802602) | codecpacks.webp.exe      |
| c6e1e2b2ed1c962e82239dfcd81999f7 | 0xf000 (61440) | 601088   | 2070-05-29 07:31:01 (3168588661) | EnterpriseAppMgmtSvc.dll |
| 2689c5357ddcc8434dd03d99a3341873 | 0xf000 (61440) | 474112   | 2086-08-04 04:03:21 (3679286601) | FfuProvider.DLL          |
+----------------------------------+----------------+----------+----------------------------------+--------------------------+
```

### TO DO

- Make it so you can see the file name of the matched file
- Better error handling etc.
