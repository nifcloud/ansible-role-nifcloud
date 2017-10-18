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

* results (2017/09/29)
```
Name                   Stmts   Miss  Cover
------------------------------------------
niftycloud.py            171     31    82%
niftycloud_fw.py         282      5    98%
niftycloud_lb.py         125     21    83%
niftycloud_volume.py     105     25    76%
------------------------------------------
TOTAL                    683     82    88%
```
