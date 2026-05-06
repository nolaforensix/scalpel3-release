# Karley Waguespack

# This is a utility for quickly creating a file of the type .abc

# Files of this type are used in a simple file validator within scalpel3. 

# These are not valid file types and merely serve to demonstrate how coding of validators work 

# this is an ASCII file type that follows this format: 
# [HEADER]      "0123456789##..."
# [FOOTER]      "9876543210##..."
#
# [BLOCK 1]     "[HEADER]AAAAAAAAAA..."
# [BLOCK 2]     "BBBBBBBBBB..."
# [BLOCK 3]     "CCCCCCCCCC..."
# ...
# [BLOCK 26]    "ZZZZZZZZZZ...[FOOTER]"

import sys


FILE_HEADER = "#0123456789#"
FILE_FOOTER = "#9876543210#"
#for this file type, there will always be 26 blocks (A-Z)
BLOCKS_NUM = 26

def create_abc_file(filename, blocksize):
    abc_file = open(filename + ".abc", "w")
    #write the header first
    abc_file.write(FILE_HEADER)
    #finish filling first block with A's
    for _ in range(blocksize - len(FILE_HEADER)):
        abc_file.write('A')
    #holds data to write to current block
    cur_data = 'B'
    #now enter a loop to write each block (B-Y)
    for _ in range(BLOCKS_NUM-2): 
        for _ in range(blocksize):
            abc_file.write(cur_data)
        cur_data = chr(ord(cur_data) + 1)
    #once finished, write the Z chars & leave space for footer
    for _ in range(blocksize - len(FILE_FOOTER)):
        abc_file.write('Z')
    #append footer
    abc_file.write(FILE_FOOTER)

    #close
    abc_file.close()


#get user specified file name and block size
user_file_name = sys.argv[1]
user_block_size = int(sys.argv[2])

#create the file type
create_abc_file(user_file_name, user_block_size)
