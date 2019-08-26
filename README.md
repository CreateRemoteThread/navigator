# navigator
the titans gave us fire. give it back.

## introduction
navigator is a python-based recon swiss army knife. it is intended to identify
interesting assets which other systems do not. in it's simplest form, you can
perform dns brute forcing of domains by passing it a file a on argv:

```sh
./navigator.py targets.txt
```

this will create targets.txt.db, which contains the table 'resolved', listing
the identified hosts and corresponding IP addresses. you can further refine
this result set by passing it the --scan or --vhosts arguments, along with a
--db argument to use an existing database:

```sh
./navigator.py --db targets.txt.db --vhosts
./navigator.py --db targets.txt.db --scan
```

the scan argument will update the db with the "scanned" table, which identifies
which ports are open from the set of 21,80,443,8080,8443,8081. i recommend
that you just use nmap.

the vhosts argument will perform vhost brute forcing againts each of the hosts
in the 'resolved' table, testing them against each other to identify load
balancing or unusual hosting arrangements.

### ImportError?
```sh
pip install -r requirements.txt
```

## extending
navigator is designed to be extremely extensible - plugins can be written in
complete isolation to the main application. to write a plugin, simply place
a python file into modules/. any code in the python file will be executed at
startup.

this file should contain one or more functions, which take a sqlite3 cursor
as the only argument (this is a cursor to the db used by navigator). for 
example:

```python
# modules/test.py:
def test_function(c):
  c.execute("select * from resolved")
  data_rows = c.fetchall()
  print data_rows
```

to call this function, just supply --plugin modules.test.test_function, and
this function will be called, with the correct sqlite cursor added. (don't
actually write this function.)

be a g o o d b o y e, don't do bad stuff.
