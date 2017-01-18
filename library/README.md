# Ansible modules for NIFTY Cloud

* [niftycloud](documents/niftycloud.md)
* [niftycloud_volume](documents/niftycloud_volume.md)
* [niftycloud_lb](documents/niftycloud_lb.md)

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

* results (2016/8/22)
```
Name                   Stmts   Miss  Cover
------------------------------------------
niftycloud.py            165     31    81%
niftycloud_lb.py         116     21    82%
niftycloud_volume.py     100     23    77%
------------------------------------------
TOTAL                    381     75    80%
```
