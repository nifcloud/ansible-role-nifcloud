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

* results (2017/03/06)
```
Name                   Stmts   Miss  Cover
------------------------------------------
niftycloud.py            175     16    91%
niftycloud_lb.py         121     10    92%
niftycloud_volume.py     103     14    86%
------------------------------------------
TOTAL                    399     40    90%
```
