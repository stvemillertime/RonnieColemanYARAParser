#!/usr/bin/env python
import pathlib
from posixpath import split
import sys
from datetime import datetime
import argparse
import os.path
import re
import pathlib
import subprocess
from prettytable import PrettyTable


'''

This script is named after Ronnie Coleman, and peforms bulk lifts on arbitary PE features using YARA console logging.

You could easily use pefile or a dozen other file parsing scripts and tools to parse out features from PEs, but this script uses YARA's built-in modules and rules.

Yes, it is very terrible, foolish, and probably stupid. You have been warned, and you need not impress upon me the wrongs I have done here.

-smiller

---

Usage: 

- python3 ronnie.py --things hash.md5 pe.timestamp pe.dll_name pe.export_timestamp pe.number_of_exports pe.rich_signature.key filesize  --path ~/yarafiddling/samps --sort pe.timestamp 

The things you put in have to be top level (not iteratable array) module or yara special stuff, and the script will build rules and run them against your corpus. Then grab the results and jam them back into the table. 

It does basically zero error handling and checking, and wont work with arrays, so things will probably get jacked up if you dont know what you're trying to look at. 

Recommend you just go to the yara documentation: https://yara.readthedocs.io/en/stable/modules/pe.html

Requirements: 

    1) recent compile of yara4.2.0 or better as long as it involves the console module 
    2) bunch of python crap

More usage examples: 

- ronnie.py --things hash.md5 pe.timestamp pe.dll_name pe.export_timestamp pe.number_of_exports pe.rich_signature.key filesize  --path ~/yarafiddling/samps --sort pe.timestamp 
- ronnie.py -t hash.md5 filesize pe.timestamp pe.dll_name  -p ~/yarafiddling/samps -s pe.dll_name  
- ronnie.py -t hash.md5 filesize pe.timestamp pe.entry_point --path ~/yarafiddling/samps 
- ronnie.py -t hash.md5 filesize pe.timestamp "uint16be(0)" --path ~/yarafiddling/samps --sort pe.timestamp 
- ronnie.py --thing hash.md5 pe.timestamp filesize "pe.imphash()" -p ~/yarafiddling/samps -s filesize

'''

def main(args = sys.argv[1:]):


    parser = argparse.ArgumentParser(prog = "ronnie.py", description="Ronnie Coleman doing bulk lifts on arbitary PE features using YARA console logging.")
    parser.add_argument('-t','--things', nargs='+', type=str, required=True, help='This is your input thing')
    parser.add_argument('-p','--path', type=pathlib.Path, required=True, help='File path to apply to.')
    parser.add_argument('-s','--sort', type=str, required=False, help='Thing to sort by.')
    parser.add_argument('--filenames',type=bool)
    args = parser.parse_args(args)
    # do shit with rule argument
    
    in_things = []
    in_things = args.things

    # make sure to change all this to reflect the location of your YARA 4.2 binary, and your rule file.
    config_yara_4_2 = "/Users/steve/yara-4.2.0-rc1/yara"
    config_yara_rule_file = "/Users/steve/yara-4.2.0-rc1/ruletemp_set2"

    #build yara rule fule
    yara_imports = "import \"pe\" import \"console\" import \"hash\"\n"
    f = open(config_yara_rule_file,"w")
    f.write(yara_imports)
    n = 0
    for thing in in_things:
        try:
            rule_base = "rule rule_" + re.sub('\W+','',thing) + "{ condition: filesize < 25MB" #make conditions or whatever rule structure you want
            if thing == "hash.md5":
                rule_base += (" and console.log(\"hash.md5:\"," + thing + "(0,filesize)" + ") }\n")
                f.write(rule_base)
                n+=1
            else:
                rule_base += (" and console.log(\"" + thing + ":\"," + thing + ")" + " }\n")
                f.write(rule_base)
                n+=1
        except:
            print("bad thing bad thing omgomg")
    f.close()

    # now try to do a bunch of stuff
    try: #TRYLOOP-ALL
        print("\n")
        if args.things and args.path:
            try: #TRYLOOP1
                input_things_for_columns = args.things
                out_table = PrettyTable()
                out_table.field_names = input_things_for_columns

                alt_table = PrettyTable()
                new_fields = []
                for i in out_table.field_names:
                    new_fields.append(i)
                new_fields.append("fullpath")
                alt_table.field_names = new_fields    
                
                
                os.chdir(args.path)
                for dir,subdirs,files in os.walk("."):
                    for f in files: 
                        if f in __file__: continue
                        fullpath = os.path.realpath( os.path.join(dir,f) )
                        # if you want this to be recursive over a directory tree you'll want to add a '-r'  as its own term in the subprocess run below. 
                        # and then you'll need to add some better directory handling stuff for the table.
                        run_yara_alt = subprocess.run([config_yara_4_2,config_yara_rule_file, fullpath],stdout=subprocess.PIPE).stdout.decode('utf-8')
                        list_of_results = run_yara_alt.split("\n")
                        omit = "rule_"
                        x = input_things_for_columns 
                        new_built_row = []
                        for r in list_of_results:
                            #if r != '' and not omit in r:
                            if r != '' and not omit in r:
                                new_built_row.append(r)
                                new_built_row.append(fullpath)

                        new_list = []

                        for index,thing in enumerate(input_things_for_columns):
                            sub1 = str(thing)
                            res1 = list(filter(lambda x: sub1 in x, new_built_row))
                            loc_col = str(res1).find(":")
                            sub_str = str(res1)[loc_col+1:]
                            mod = re.sub('[\[\]\']','',sub_str)                    
                            # if you have special things that require translation from decimal to hex or whatever, maybe do them here
                            # or comment the things out if you don't want to see extraneous values
                            if "timestamp" in str(res1):
                                new_list.append(str(datetime.fromtimestamp(int(mod))) + ' (' + mod + ')')
                                #new_list.append(str(datetime.fromtimestamp(int(mod)))) 
                            elif "entry_point" in str(res1):
                                new_list.append((hex(int(mod))))
                            elif "uint" in str(res1):
                                new_list.append((hex(int(mod))) + ' (' + mod + ')')
                                #new_list.append((hex(int(mod))))
                            else:    
                                new_list.append(mod)
                        
                        out_table.add_row(new_list)
                        out_table.align = "l"


                        path_split_str = fullpath #do a split on this if you need to grab a substring of the full path
                        alt_list = new_list
                        alt_list.append(path_split_str)
                        alt_table.add_row(alt_list)

                if args.sort:
                    try:
                        print("\n[:great-job:] LIGHT WEIGHT! Heres the sorted table:\n")
                        if args.sort == "filesize":
                            if args.filenames:
                                print(alt_table.get_string(sortby=(args.sort),sort_key=lambda row: int(row[0])))
                            else:
                                print(out_table.get_string(sortby=(args.sort),sort_key=lambda row: int(row[0])))
                        elif args.sort == "pe.machine":
                            print(out_table.get_string(sortby=(args.sort),sort_key=lambda row: int(row[0])))
                        else:
                            if args.filenames:
                                print(alt_table.get_string(sortby=(args.sort)))
                            else:
                                print(out_table.get_string(sortby=(args.sort)))
                    except:
                        print("\n[:boo-frown:] Warning: make sure you try to sort by one of the things you've selected")
                        print("\n[:thumbs-up:] Thumbs up on a cool unsorted table tho:\n")
                        print(out_table)
                else:
                    print("\n[:very-ok-emoji:] Thumbs up on a very ok unsorted table:\n")
                    if args.filenames:
                        print(alt_table)
                    else:
                        print(out_table)
                    print("\n")  
            except:
                print("Error in the file walking part #TRYLOOP1")
        #print(out_table)
    except:
        print("Error in #TRYLOOP-ALL.")

#### main main

if __name__ == '__main__':
    main()
