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

* results (2017/09/29)
```
Name                   Stmts   Miss  Cover
------------------------------------------
nifcloud.py            171     31    82%
nifcloud_fw.py         282      5    98%
nifcloud_lb.py         125     21    83%
nifcloud_volume.py     105     25    76%
------------------------------------------
TOTAL                    683     82    88%
```
