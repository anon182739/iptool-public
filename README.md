To run
`torsocks -i python scan.py 2>&1 | tee log | grep -v torsocks`
To extract domains from log
`cat log | grep -v torsocks | sort | uniq`
