# dnsteal v 2.0

This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests. 

Below are a couple of different images showing examples of multiple file transfer and single verbose file transfer:

![Alt text](https://www.slimgr.com/images/2015/10/21/e5c21fddae495743f901804091d5b220.png)
![Alt text](https://www.slimgr.com/images/2015/10/21/96dc39537a81b3f4231cb8ef89a6895b.png)

* Support for multiple files
* Gzip compression supported
* Now supports the customisatio of subdomains and bytes per subdomain and the length of filename

See help below:

![Alt text](https://www.slimgr.com/images/2015/10/21/b8a6d39ea2ff93ee7d893ed5095a87a4.png)

If you do not understand the help, then just use the program with default options!

```bash
# python dnsteal.py 127.0.0.1 -z -v
```

This one would send 45 bytes per subdomain, of which there are 4 in the query. 15 bytes reserved for filename at the end.

```bash
# python dnsteal.py 127.0.0.1 -z -v -b 45 -s 4 -f 15
```

This one would leave no space for filename.

```bash
# python dnsteal.py 127.0.0.1 -z -v -b 63 -s 4 -f 0
```

~x90
