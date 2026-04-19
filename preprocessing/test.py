#!/bin/python

import subprocess
from pathlib import Path

dump_dir=Path("./dump").resolve()
image_name="Challenge.raw"

command=["docker","run","-it","--rm","-v",f"{dump_dir}:/dump","vol3","-f",f"/dump/{image_name}","info"]
try:
    result=subprocess.run(command,capture_output=True,text=True,check=True)
    print(result.stdout)
except subprocess.CalledProcessError as e:
    print(f"Error running volatility: {e.stderr}")