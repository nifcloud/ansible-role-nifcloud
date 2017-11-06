# Ansible modules for NIFTY Cloud

* [niftycloud](documents/niftycloud.md)
* [niftycloud_fw](documents/niftycloud_fw.md)
* [niftycloud_lb](documents/niftycloud_lb.md)
* [niftycloud_volume](documents/niftycloud_volume.md)

## Test

* install necessary modules
```
# pip install unittest coverage nose
```

* execute tests
```
# nosetests --no-byte-compile --with-coverage > /dev/null 2>&1 && coverage report --include=./niftycloud*.py
```

* make anotated copies
```
# nosetests --no-byte-compile --with-coverage > /dev/null 2>&1 && coverage annotate --include=./niftycloud*.py
# cat *,cover
```

* results (2017/11/01)
```
Name                   Stmts   Miss  Cover
------------------------------------------
niftycloud.py            190     37    81%
niftycloud_fw.py         297      7    98%
niftycloud_lb.py         135     23    83%
niftycloud_volume.py     110     25    77%
------------------------------------------
TOTAL                    732     92    87%
```
