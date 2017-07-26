# Ansible modules for NIFTY Cloud

* [niftycloud](documents/niftycloud.md)
* [niftycloud_fw](documents/niftycloud_fw.md)
* [niftycloud_lan](documents/niftcloud_lan.md)
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

* results (2017/07/26)
```
Name                   Stmts   Miss  Cover
------------------------------------------
niftycloud.py            171     31    82%
niftycloud_fw.py         319      5    98%
niftycloud_lan.py        239      6    97%
niftycloud_lb.py         125     21    83%
niftycloud_volume.py     105     25    76%
------------------------------------------
TOTAL                    959     88    91%
```
