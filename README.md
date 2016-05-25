# dnsteal v 2.0

This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests. 

Below are a couple of different images showing examples of multiple file transfer and single verbose file transfer:

![Alt text](http://i.imgur.com/nJsoAMv.png)

* Support for multiple files
* Gzip compression supported
* Now supports the customisation of subdomains and bytes per subdomain and the length of filename

See help below:

![Alt text](http://i.imgur.com/GT5SV2L.png)

If you do not understand the help, then just use the program with default options!

```bash
python dnsteal.py 127.0.0.1 -z -v
```

This one would send 45 bytes per subdomain, of which there are 4 in the query. 15 bytes reserved for filename at the end.

```bash
python dnsteal.py 127.0.0.1 -z -v -b 45 -s 4 -f 15
```

This one would leave no space for filename.

```bash
python dnsteal.py 127.0.0.1 -z -v -b 63 -s 4 -f 0
```

~x90
