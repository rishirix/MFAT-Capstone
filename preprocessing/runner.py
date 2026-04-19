#!/bin/python3

import subprocess
from pathlib import Path

dump_dir=Path("./dump").resolve()
image_name="Challenge.raw"

run=subprocess.run("docker ",shell=True,capture_output=True,text=True)

def determine_volatility_version(image_path):
    v3_check=subprocess.run(["vol","-f",image_path,"windows.info"],capture_output=True,text=True)
    
    if v3_check.returncode==0:
        return "v3"
    print()