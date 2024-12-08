import subprocess as sp
from random import randint
import sys
import os
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python populate.py <user> <number>")

    current = 0
    for i in range(int(sys.argv[2])):
        print(f"\033[94mDownloading {current}/{sys.argv[2]}\033[0m")
        sp.run(f"curl https://picsum.photos/{randint(1, 6)}00/{randint(1, 6)}00 -L -o {os.getcwd()}/uploads/{sys.argv[1]}/src/sample{i}.jpg".split(), stdout=sp.DEVNULL)
        sp.run(f"cp {os.getcwd()}/uploads/{sys.argv[1]}/src/sample{i}.jpg {os.getcwd()}/uploads/{sys.argv[1]}/cmp/compressed_sample{i}.jpg".split(), stdout=sp.DEVNULL)
