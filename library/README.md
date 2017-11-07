# Ansible modules for NIFCLOUD

* [nifcloud](documents/nifcloud.md)
* [nifcloud_fw](documents/nifcloud_fw.md)
* [nifcloud_lb](documents/nifcloud_lb.md)
* [nifcloud_volume](documents/nifcloud_volume.md)

## Test

* install necessary modules
```
# pip install unittest coverage nose
```

* execute tests
```
# nosetests --no-byte-compile --with-coverage > /dev/null 2>&1 && coverage report --include=./nifcloud*.py
```

* make anotated copies
```
# nosetests --no-byte-compile --with-coverage > /dev/null 2>&1 && coverage annotate --include=./nifcloud*.py
# cat *,cover
```

* results (2017/11/07)
```
Name                 Stmts   Miss  Cover
----------------------------------------
nifcloud.py            190     37    81%
nifcloud_fw.py         297      7    98%
nifcloud_lb.py         135     23    83%
nifcloud_volume.py     110     25    77%
----------------------------------------
TOTAL                  732     92    87%
```
