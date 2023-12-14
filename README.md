What is Munshin?
================

Munshin is a 'gatekeeper' app that can be used either as a socks proxy, an inetd replacement or a reverse proxy / port-forwarding firewall. Its basic function is to accept a connection, check a number of rules such as ip address, geolocation, reverse dns lookup, dynamic dns lookup, etc, etc, and then forward this connection to the appropriate host/port/socket if the rules are satisfied. Munshin can forward connections to/from unix sockets, tcp sockets, chains of other proxies, or launch an application to handle them in inetd fashion. Munshin can also handle TLS/SSL on either or both sides of the connection, allowing it to add a TLS layer to services/devices that lack one, or that have outdated or otherwise vulnerable SSL/TLS implementations.

Why is Munshin?
===============

If you are reading this then the internet is likely on fire. The internet is always on fire. Every week new backdoors and vulnerabilities are announced, and patching does nothing to help, in fact patches frequently introduce new vulns. Yet unfortunately circumstances frequently arise where a device or piece of software has to be made internet-visible, despite worries about its security. Perhaps something is already internet-facing, but needs to be patched, and cannot be patched until a scheduled shutdown at a production center. Perhaps something needs to be made quickly available to another party, but that party cannot be given VPN access. Perhaps you have a device that's vital to your daily work, but whose security you do not trust.

Munshin is intended to be a network sticking-plaster or puncture-repair kit for these situations. It does aim to provide perfect security, but rather aims to at least lower the attack surface of a device or host in situations where security is already at risk. Sometimes this would be as crude as limiting allowed connections to a particular country, but even that is better than nothing. Munshin can be set up before a target host/device to put a set of extra rules/checks in place before a connection is made to the final destination. It can apply extra layers of authentication based on IP, DNS lookups, geolocation, SSL client certificates, and other validation methods. It can apply TLS/SSL to connections to devices that don't support this or have outdated implementations. It can redirect connections to different destinations according to its ruleset, creating 'hidden' services that only certain peers can access.

It can also be used in the opposite direction, as a port-forwarder, socks proxy, or transparent proxy for local apps, that can apply rules against the user or exectuable path at the other end of the connection.

Much of what munshin can do can also be achieved via manipulating iptables firewall rules, but this can be risky, as a mistake in a firewall rule (which can potentially effect all ports on a host) can create a much larger hole in security than a mistake in setting up munshin.

Who is Munshin?
===============

Munshin is named after the Korean god of doors and gateways. The god Munshin falls into the class of deities known as 'Menshen' in China (gateway guardians whose images are painted on doors to prevent entry of evil forces).


USAGE
=====

When run without arguments munshin will read the config file '/etc/munshin.conf' and offer services defined in that.


CONFIG FILE
===========

The config file (default /etc/munshin.conf) can contain the following entries:

```
include <file path>
logfile <file path>
pidfile <file path>
regionfiles <file path>
region-files <file path>
config <name> <options>
forward <service port>:<tcp host>:<tcp port>   <options>         
forward <service port>:unix:<unix socket path> <options>         
forward <service port>:htauth:<tcp host>:<tcp port>   <options>         
forward <service port>:cmd:<command to run>    <options>         
forward <service port>:web_manager <options>         
```

The 'include' entry pulls in settings from another file.

The 'logfile' entry specifies a logfile path.

The 'pidfile' entry specifies a pidfile path.

The 'regionfiles' or 'region-files' entry specifies a search path for internet registrar files (see Geolocation Authentication below).

The 'config' entry allows creating a list of rules and options that can be included in a 'forward' entry by using the 'config=' option (see below).

The 'forward' entry defines a port-forward. 'service-port' is the port to be forwarded. if 'service-port' is postfixed with the letter 's' (e.g. 443s) then this port will use SSL/TLS encryption. Following the service port is the definition of the destination to forward connections to. 

Examples:


```
forward 80:192.168.5.10:80           - forward connections on port 80 to port 80 on 192.168.5.10 
forward 443s:192.168.5.10:80         - use TLS/SSL on port 443 and forward connections to port 80 on 192.168.5.10 
forward 443s:192.168.5.10:443s       - use TLS/SSL on port 443 and forward connections to port 443, also using TLS/SSL, on 192.168.5.10 
forward 443s:unix:/var/ep/webserv    - use TLS/SSL on port 443 and forward connections to unix socket /var/ep/webserv
forward 999:cmd:'/usr/bin/chatd -i'  - forward connections on port 999 to program '/usr/bin/chatd -i' (note use of quotes)
forward 8090s:htauth:192.168.5.11:80  - forward connections on port 8090 to port 80 on 192.168.5.11, using 'htauth' authentication frontend. 
```

'<options>' will be a list of rules and options relating to the particular forward rule. When a connection is made to a service port these 'forward' lines will be interrogated one by one until one is found that matches the connection. Thus the order of these rules in the config file is important.

Rules are options that specify whether a given 'forward' record should be considered for a particular incoming connection. Rules can require that the connection comes from a particular IP address, or authenticates in some way. This means that two hosts or two users connecting to the same port can match against different 'forward' rules and can be routed to different destinations. Rules have the form:


```
allow=<requirement> 
deny=<requirement> 
sufficient=<requirement>
suffice=<requirement>
required=<requirement>
require=<requirement>
abort=<requirement>
```

Multiple rules can exist in a single 'forward' record, and they are processed in order. 

'allow' and 'deny' rules can be overriden by later entries.

A 'sufficient' rule, if matched, instantly causes a 'forward' record to be selected. 

An 'abort' rule, if matched, instantly causes a forward record to be ignored.

A 'required' rule, if NOT matched, instantly causes a forward record to be ignored. 


Available rules for 'allow', 'deny', "sufficient' or 'required' options are:


```
all                      - allow or deny all connections
ip:<addresses>           - match IP address. 'addresses' can be a comma-seperated list of IP addresses or IP ranges (using /xx notation).
mac:<addresses>          - match MAC address. 'addresses' can be a comma-seperated list of MAC addresses.
region:<regions>         - match geolocation of remote host. 'regions' can be a comma-separated list of two-letter country codes, or registrar names
host:<host names>        - match hostname as looked up via DNS.
dyndns:<host names>      - match hostname as looked up via a method compatible with dynamic dns services.
dnslist:<dnsbl list>     - check if remote IP is in dns blocklists/allowlists.
user:<user names>        - check user as verified by TLS/SSL certificate, local connection credentials, or munauth methods.
process:<path>           - only works for local connections. Check process path. See 'Local Connections' below.
localuser:<user names>   - only works for local connections. Check local user. See 'Local Connections' below.
munauth:<config>         - check if connection is authenticated via the 'munauth' system
cert-issuer:<name>       - check if TLS/SSL certificate was issued by named issuer.
```

These rules will be discussed in detail in the 'AUTHENTICATION' section below.

In addition to 'rules' there are other options that modify the behavior of a 'forward' rule if it is selected for use.


```
config=<config name>  - include named config
idle=<seconds>        - idle timeout in seconds. munshin will disconnect if no traffic seen in *either direction* for this long
src-ttl=<value>       - set ttl on source (client) connection
src-tos=<value>       - set tos value on the source (client) connection
sttl=<value>          - set ttl on source (client) connection
stos=<value>          - set tos value on the source (client) connection
dst-ttl=<value>       - set ttl on destination (target) connection
dst-tos=<value>       - set tos value on the destination (target) connection
dttl=<value>          - set ttl on destination (target) connection
dtos=<value>          - set tos value on the destination (target) connection
ssllevel=<value>      - minimum SSL/TLS version. one of 'ssl', 'tls1', 'tls1.1', or 'tls1.2'
ssl-level=<value>     - minimum SSL/TLS version. one of 'ssl', 'tls1', 'tls1.1', or 'tls1.2'
sslcert=<value>       - path to SSL/TLS certificate file to use for encryption
ssl-cert=<value>      - path to SSL/TLS certificate file to use for encryption
sslkey=<value>        - path to SSL/TLS key file to use for encryption
ssl-key=<value>       - path to SSL/TLS key file to use for encryption
sslciphers=<list>     - list of permitted SSL/TLS ciphers to use
ssl-ciphers=<list>    - list of permitted SSL/TLS ciphers to use
ssl-dhparams=<path>   - path to dhparams file needed for perfect-forward-secrecy SSL/TLS ciphers
ssl-client-verify=<value>    - path to file or directory containing CA certificates for CLIENT certificate verification
ssl-verify=<value>    - path to file or directory containing CA certificates for CONNECTION certificatee verification
chuser=<name>         - switch user to user <name> (defaults to 'nobody' or uid 99)
chgroup=<name>        - switch user to user <name> (defaults to 'nobody' or uid 99)>
syslog=<level>:<msg>  - send syslog message <msg> with level <level>
confirms=<path>       - path to a file to store 'waiting connections'. This activates the 'connection confirm' feature. 
ippdb=<path>          - path to an IP address database that can be updated by munshins web frontend.
ip-db=<path>          - path to an IP address database that can be updated by munshins web frontend.
macdb=<path>          - path to a MAC address database that can be updated by munshins web frontend.
mac-db=<path>         - path to a MAC address database that can be updated by munshins web frontend.
otpdb=<path>          - path to one-time-password file that can be updated by munshins web frontend.
otp-db=<path>         - path to one-time-password file that can be updated by munshins web frontend.
authdb=<path>         - path to authentication credentials file
auth-db=<path>        - path to authentication credentials file
banner=<text>         - 'banner' used for web-based services.
```

The 'config' option can be used to include a list of options previously declared using the 'config' entry type, like so:


```
config local-only src-ttl=2 ip=192.168.*.*
80:127.0.0.1:8080 config=local-only
```

'idle' defines the number of seconds before munshin will cut an inactive connection. This means a connection that has no traffic *in either direction* so either party, the client or the destination, can keep the connection open by sending traffic.

'src-ttl' and 'dst-ttl' allow setting the tcp Time To Live (hops) value on either the incoming (client) connection, or on the forwarded connection to the destination. The TTL value is a value within an IP packet that is decremented every time the packet passes through a router (not a switch, a router). When it hits zero the packet is disacrded. This means that packets with low TTL values will not travel very far through the internet. Thus these settings provide a simple way to, for instance, limit accepted connections to hosts within a business by setting src-ttl to low values like 1 or 2. Similarly dst-ttl can be used to prevent forwarding connections outside of a business. Regardless of whether it has open access through firewalls a packet with a ttl of 1 or 2 will not travel very far through the internet, and if an organization has internal routers, it will not even leave the organization.

'src-tos' and 'dst-tos' allow setting the Type Of Service value for either the incoming (client) connection or the forwarded (destination) connection. Type Of Service is not much used in modern environments, but setting this value might allow for tracking packets through a network.

The 'ssl-level', 'ssl-cert', 'ssl-key', 'ssl-verify', 'ssl-ciphers', and 'ssl-dhparams' options all relate to TLS/SSL encryption of the incoming (client) connection. This feature must be turned on for a particular port using either the 's' suffix to the port definition in the standard config file or by using an ssl/tls protocol definition when using munshin as a inetd.

'ssl-level' can be one of:
* ssl    - ssl v3 and above
* ssl3   - ssl v3 and above
* tls    - tls v1 and above
* tls1   - tls v1 and above
* tls1.1  - tls v1.1 and above
* tls1.2  - tls v1.2 and above

'ssl-cert' and 'ssl-key' specify the paths to the server certificate and key files to use.

'ssl-verify' specifies the path to either a file containing concatanated CA certificates for use in verifying client certificates, or else to a directory containing single-file CA certificates for use in verifying client certificates.

'ssl-ciphers' is a comma-separated list of ciphers to use in encryption (get the names of these from your SSL library).

'ssl-dhparams' specifies the path to a file that provides Diffie Helman parameters for perfect-forward-secrecy.

'chuser' and 'chgroup' allow setting the user and group that the munshin service process runs as. This is particularly important if the destination is of the 'cmd:' type. If not specified munshin will try to switch to user 'nobody' and failing that will switch to uid '99'.




TTL and ToS
===========

The src-ttl, src-tos, dst-ttl and dst-tos allow setting IP packet values on either the 'source' (client) connection, or the 'destination' connection that the client is connecting to. The TTL value is is a number associated with a network packet that is decremented every time the packet passes through a router/gateway. When the number hits zero the packet is discarded. Thus, if you set up a munshin service/forward port to have a TTL of two, and getting to the internet requires more than two 'hops' thorugh multiple routers, then packets from the port will never be able to leave your local network. 

ToS sets another value, the 'type of service' which can be used to mark packets to be treated differently by firewall rules.

These features are activated via setsockopt, and will work on linux, and maybe on other O.S. supporting the `IP_TTL` and `IP_TOS` socket options. 


NETWORK NAMESPACES
==================

A munshin forward or service can be bound into a linux network namespace like so:


```
forward 8080:192.168.1.10:80 namespace=app_jail
```

In the above case the namespace must been setup as a directory named 'app_jail' in '/var/run/netns'. '/var/run/netns/app_jail' would then contain all the file descriptors for the namespace. If your namespaces are not set up that way, then you can instead supply the full path to a network namespace file descriptor:

```
forward 8080:192.168.1.10:80 namespace=/home/namespaces/jail1/net_fd
```


or use the pid of a process already in the namespace (e.g. the namespace 'init' process) like so:

```
forward 8080:192.168.1.10:80 namespace=pid:8244
```

Used in conjunction with socks5 or transparent proxy mode (see both below) this can be used to proxy apps 'trapped' in a network namespace with no external network accesss.


TRANSPARENT PROXY
=================

Under linux munshin supports 'transparent proxy' mode where the firewall redirects a connection to a munshin port rather than letting it connect directly to it's destination. This redirection has to be set up under ipchains, iptables or whatever else linux is using this month, and then configured in munshin as either:


```
forward 8080T:192.168.30.1:80
```
or

```
forward 8080:tproxy:192.168.30.1:80
```

in this use munshin will redirect anything sent to the port to 192.168.30.1 port 80. If you wish to allow hosts to connect to their intended destination, except with some extra logging, or perhaps applying 'allow/deny' rules, then you need to use the format:

```
service 8080T
```
or

```
service 8080:tproxy
```



INETD
=====

Munshin can be used in place of inetd, but only for TCP, SSL and unix connections (no UDP at current). If munshin is run as a link/symlink to 'inetd' or is invoked as `munshin -inetd` it will operate in inetd mode. In that case it parses the file `/etc/inetd.conf` instead of the usual munshin.conf config file. This file contains entries of the form:


```
<port>  <socket type> <protocol> <serivce settings> <user settings> <program> <program arg[0]> <program arg[n]>...

```

'port' can be a port name or a port number, or a path for unix sockets
'socket type' is currently always 'stream' as munshin does not currently support datagram sockets
'protocol' can be 'tcp', 'unix', 'ssl', 'ssl3', 'tls', 'tls1.1', 'tls1.2'. Additional arguments from the munshin config-file can be comma-appended to this, see examples below.
'service settings' would traditionally contain 'wait' or 'nowait' to indicate whether inetd should wait for a launched program to exit before allowing another connection. Munshin ignores these settings and always allows another connection. Other settings from the munshin config file can be comma-appended here.
'user settings' supports the formats 'user[.group]', 'user[:group]', or 'user[/group]' and specifies the user and group that a program should be run as. Other munshin config-settings can be comma-appended here.
'program' is the full path to the program that services this connection, followed by 'program arg[0]', which is the name the program will be run as (and appear as in a 'ps' listing) and then by it's arguments.

Munshin also supports the following lines in the inetd config file:

`!include <path>`  a line starting with '!include' includes another inetd-style config file (reads it and process its contents as though they were in the current file).
`!config <config>` a line starting iwth '!config' is equivalent to 'config' entries in the munshin config file, and allows declaring a configuration under a name.


Example
-------

The following example illustrates an inetd-style config file. munshin config values can be comma appended to the socket-type, protocol, service settings and user/group fileds.

```
!config smtps_config ssl-cert=/etc/ssl/mycert.pem ssl-key=/etc/ssl/mykey.key ssl-verify=/etc/ssl/clientCA.pem idle=60

ftp	 stream	tcp	nowait	nobody:users	/usr/sbin/tcpd	in.ftpd
2121 stream	tcp,ttl=2	nowait	root	/usr/sbin/tcpd	in.ftpd
telnet stream,require=region:local tls,ssl-cert=/etc/ssl/mycert.pem,ssl-key=/etc/ssl/mykey.key nowait root /sbin/telnetd /sbin/telnetd
smtps stream tls1.1,config=smtps_config nowait mail/spooler tcpd sendmail -v
```

Inetd Gothas/Differences from Inetd
-----------------------------------

Munshin doesn't hand the incoming socket over to the application it runs. This allows it to 1) Manage TLS/SSL on the incoming socket, 2) Implement 'idle timeouts' if the connection goes quiet. However, this comes at some costs. Firstly any application it runs *must* read on file descriptor 0 and write on file descriptor 1, it cannot both read and write on either of those descriptors. Secondly the app will not be able to call 'getpeerinfo' and lookup the remote IP and port of the connection it is servicing, as it does not have direct access to that connection. To help with the latter issue munshin exports the environment variable 'REMOTE_ADDRESS' to tell the program what machine it is talking to. Munshin also exports 'REMOTE_USER' if the user at the end of the connection is known.



CONFIRMED CONNECTIONS
=====================

If the 'confirms' option is supplied in a 'forward' rule, like this:


```
forward 8080:192.168.60.60:80 allow=confirms:/home/munshin/connections.queue
```

Then connections will be registered in the defined file (in this case '/home/munshin/connections.queue') and held in a waiting state until they are manually confirmed or denied using the web frontend (discussed in WEB FRONTEND below).



AUTHENTICATION
==============

Munshin has a number of methods of authentication that it can use to decide whether to allow a connection. If no rules are defined it defaults to 'allow=all'. Most of these authentication types are not really intended to be used as the only authentication, rather they are intended to be used in addition to, and to bolster, security provided by the destination.


The 'Coffee Shop' Instance
--------------------------

Most of munshin's authentication methods only authenticate an IP address, not a specific connection from that IP address. This means that anyone at a given IP is allowed access by these authentication methods. Thus care must be taken when using these authentication methods in situations where multiple hosts/people are operating behind the same IP (e.g. wifi in a coffee shop) and not all those parties can be trusted.

IP-based authentication methods are useful in situations where you control and trust certain hosts. But on their own they are risky if multiple untrusted parties exist behind a given IP. Ideally these authentication methods are intended to bolster the existing authentication of a device or service. If you have worries about password strength, potential manufacturer backdoor accounts or auth-bypass vulnerabilities, munshin can at least lower your risk and attack surface.

Consider the worst-case scenario: where you are using one of the IP-based authentication methods to protect a service that has no authentication of its own. You should not do this. However, if you have to for some crazy reason, and you're giving access to someone sitting in a coffee shop with untrusted people sharing the wifi connection, you have at least cut down your attack surface from everyone with internet access on Earth, to the people with access to the coffee-shop wifi. It's not good, but it's undeniably better than just sticking that service on the internet.


IP Authentication
-----------------

IP authentication is a simple method where list of IP addresses, or patterns that match IP addresses are specified in an allow or deny rule. Pattern matching is shell/fnmatch style. 

Examples:

```
	allow=ip:192.168.[1-3]*.* deny=ip:192.168.23.8
```

This system allows access by anyone at a given IP, so the warnings given in 'The Coffee Shop Instance' apply.


Host Authentication
-------------------

Host authentication is a simple method that looks up the hostname for an IP and matches against it using a pattern. 

Examples:

```
	allow=host:*.mydomain.com
```

This system allows access by anyone at a given IP, so the warnings given in 'The Coffee Shop Instance' apply.



DynDNS Authentication
---------------------

Dynamic DNS is a service for hosts that change their IP address regularly. It allows a host to register a hostname against its current IP. This is normally used either because the host is getting a dynamic IP lease from an ISP, or because the host is mobile. Munshin can lookup dynamic DNS entries and use them for host authentication, but this works in a slightly different way to standard 'Host Authentication'. In Dynamic DNS a host/user is given a special hostname within a particular DNS domain. However, this hostname won't be the one returned if one looks up the name of an IP through DNS. Instead munshin must look up the special hostname and see if its IP matches the incoming IP. This means that, unlike IP and Host Authentication discussed above, patterns and wildcards cannot be used in this authentication method, the special hostname must be supplied exactly. 

Dynamic DNS has the advantage that a host/user has to authenticate with the dynamic DNS service, so this gives an extra assurance that they are who they say they are. This is useful in situations where munshin is protecting a service that's using passwords, and the strength of the passwords might not be the best, (hopefully authetication to the dynamic DNS service isn't using the same passwords) or where there might be worries about auth-bypass vulnerabilities.


So, for example 'host1.mydomain.com' might be mapped to our external IP by a dyn-dns service. However if we look up our IP, we likely won't get this hostname. Thus the mushin config entry is:

```
	allow=dyndns:host1.mydomain.com
```

Which tells munshin not to look up the hostname for the incoming IP, but instead look up 'host1.mydomain.com' and if it's IP matches the incoming IP, allow the incoming connection.

Like most munshin authentication systems this allows access by anyone at a given IP, On it's own it's not enough in situations where multiple hosts/people are operating behind the same IP (e.g. wifi in a coffee shop). However, it can bolster existing authentication by provding a simple form of two-factor-authentication.

This system allows access by anyone at a given IP, so the warnings given in 'The Coffee Shop Instance' apply.



GeoLocation Authentication
--------------------------

Geolocation authentication looks up the country-code of the connecting IP address. To do this, the 'stats' files published by the Regional Internet Registries (ARIN, RIPENCC, APNIC, AFRINIC and LACNIC) have to be downloaded. The path to these files is then specified using the 'region-files' config entry. The 'region' rule can then be used to match against either the registry name, or the 2-letter country code for the IP.

First IP-registrar files, hereafter called 'region files' must be supplied to munshin. These files specify a mapping between IP-addresses and countries/registrars. A 'region-files' config entry specifies a path to search for them. For example:


```
	region-files /etc/ip-files/*.registrar:/usr/local/etc/extra.registrar
```

would load any files in '/etc/ip-files/' with the '.registrar' extension as 'region files' and also the file '/usr/local/etc/extra.registrar'.

If no 'region-files' entry is supplied in the config file, then munshin uses a default search path of '/etc/ip-regions/*:/usr/share/ip-regions/*', so the files can just be dropped into one of those directories.


Once region-files are set up, rules can be added to a 'forward' entry that specify only IPs belonging to certain countries or registrars are allowed access to the forward. For example:

```
	allow=region:apnic
```

Would allow any IPs handled by APNIC (i.e. IP addresses in the Asia-Pacific region).

```
	allow=region:GB
```

Would allow any IPs registered to Great Britain.

```
	allow=region:ripencc deny=region:RU
```

Would allow any IPs handled by RIPE NCC (Europe and West Asia) EXCEPT any IPs registered to Russia.




This system allows access by anyone at a given given country code!, so the warnings given in 'The Coffee Shop Instance' apply, but the issue is an entire country or registrar region rather than just a single coffee-shop! Thus great care should be taken when using it, and it should be used in combination with other types of authentication. A good use for this system is to bolster the strength of systems like SSH, which already have good authentication, but which you may wish to tighten further if you know all connections to them should only come from one country or region.



DNS List Authentication
-----------------------

DNS lists (usually dns blocklists) are services that allow looking up IP addresses through DNS to discover if they are listed as various types of 'bad' IP. Therefore this type of authentication rule is usually used as a 'deny' rule, like so:

```
	deny=dnslist:sbl.spamhaus.org,bl.blocklist.de
```

The system works by creating a special 'hostname' out of the IP-address that's being looked up, combined with the domain of the list. So if someone is connecting from 1.2.3.4 and we wanted to check the spamhaus 'SBL' blocklist, we'd look up '4.3.2.1.sbl.spamhaus.org'. If the IP address '1.2.3.4' is in the blocklist, spamhaus will reply with a 'fake' IP address, usually starting with '127.0.0'. Different fake IP responses can be used to indicate different types of 'Bad' IP that are in a list (e.g. Spam Host, open relay, tor node, malware C&C).

In a munshin rule, if only a list domain (like sbl.spamhaus.org) is used then ANY response from the DNS service, except for an NX ('no such item') response will activate the deny rule. However, munshin can utilize specific fake-ip responses like this:

```
	deny=dnslist:bl.blocklist.de:127.0.0.21,bl.blocklist.de:127.0.0.16
```

'bl.blocklist.de' returns different IPs depending on why the host was in the blocklist. Here we specify that we are only interested in the responses '127.0.0.21' (host has attempted bruteforce logins against other hosts) and '127.0.0.16' (host has launched portflood/DDoS attacks against other hosts).

DNS allowlists (or 'whitelists') do exist, but are rare. An example is 'list.dnswl.org'. You might use this like:

```
	allow=dnslist:list.dnswl.org
```

'list.dnswl.org' returns different codes indicating the type of whitelisted host, and its trustworthiness level.



MAC Address Authentication
--------------------------

Mac Address Authentication is a simple method where the local mac address of a device can be used in an allow/deny rule.

MAC addresses are only visible locally (they are not transmitted through the internet) so this rule type is only useful for managing access for hosts on the local network.



TLS/SSL Authentication
----------------------

As munshin can manage the TLS/SSL encryption of a connection, it can also do TLS/SSL authentication, in which the client provides a certificate that authenticates it as a particular host or user. This is a rare instance of munshin authentication that is specific to a connection, not just an IP address, so in the 'Coffee Shop Instance' it authenticates a specific individual connection, keeping everyone else there locked out. Obviously though it requires the client to be able to support TLS/SSL and certificates. 

Unfortunately, because SSL/TLS authentication is performed after connection acceptance, it cannot be used to select a 'forward' entry. You cannot have a 'forward' entry for one user, and another for a different user, and use SSL authentication to select between them. Instead, if a forward entry matches in all things other than its TLS/SSL setup it will be selected, and if Certificate authentication is required and the right certificate is not provided the connection will fail and the service will disconnect.

Setting this authentication system up requires an 'ssl-verify' path must be provided that contains CA certifiates to be used in authenticating the client's certificate. It can be a path to either a file containing concatanated CA certificates for use in verifying client certificates, or else to a directory containing single-file CA certificates. Just providing this will prevent any hosts that cannot provide a valid certificate from connecting. Further granularity of authentication can be obtained using the 'user' or 'cert-issuer' rules. So we have:

```
	forward 443s:192.168.1.1:80 ssl-verify=/etc/ssl/certs 
```
this will require the user to provide a valid certificate that matches a CA in /etc/ssl/certs


```
	forward 443s:192.168.1.1:80 ssl-verify=/etc/ssl/certs cert-issuer=MyOrg.CA
```
this will require the user to provide a valid certificate that matches a CA in /etc/ssl/certs, and that the certificate was issued by 'MyOrg.CA'


```
	forward 443s:192.168.1.1:80 ssl-verify=/etc/ssl/certs allow=user:jenny.testsuite
```
this will require the user to provide a valid certificate that matches a CA in /etc/ssl/certs, and that the 'CommonName' or 'User' field of the certificate is 'jenny.testsuite'.



MunAuth Authentication
----------------------

Native munshin authentication ('munauth') is based around the use of a hash of credentials and ip/connection details. This hash is included in a specially formatted message that can be passed to munshin in a number of ways (e.g. uploaded to publically accessible http servers or cloud storage sites). This is intended to allow scripted authentication.

In order to use this system a password must first be set for a user using 'munshin adduser'. e.g.:

```
munshin adduser test testing123
```

This will put the password into ~/.munshin.auth, unless the '-f' flag is used to specify an alternative file. If no password is provided, and randomly generated one will be created.

Now the connecting system needs to create a string that defines it's ip-address, which is signed with the user's password. The command:

```
munshin register -u test
```

will output a string to standard-out like

```
'test@99.88.99.88' sha256 '60F5890BBB47E47B' 'test' 2022-05-23T08:05:55 87727fe9000f175bc88757e11144437b53268002cbb513190a61a31355560728
```

This string identifies a user at a given IP address, the last component being a hash of the username, the ip-address, salt-values, and the user's password.

Munshin will try to obtain the user's external IP address by connecting to various free services. If this fails, or if an IP other than the user's current internet-facing IP is to be signed, the '-i' flag can be used:

```
munshin register -u test -i 99.88.99.88
```

This 'signed string' now needs to be put somewhere that the authenticating munshin can access.  This is usually on a third system that both the connection parties can access.  The register command supports directly POST-ing it to an https URL. For example, if an https server will allow us to post to a file/url called 'creds', and we have a username of 'user123' and password of 'password123' on that system, then the command is:

```
munshin register https://user123:password123@myhost/creds
```

Or PUT it to a https URL (instead of POST) use

```
munshin register https-put://user123:password123@myhost/creds
```

Or write it to a file on an SSH server 

```
munshin register ssh://user123:password123@myhost/creds
```

If host-setup entry exists in the ~/.ssh/config of the user munshin runs as, then that entry can be used:

```
munshin register ssh://authsystem
```


The authenticating munshin now has to be configured with paths to BOTH a url/filepath containing the user credentials, and a url/filepath containing the signed string, like so.

```
forward 8080:192.168.60.50:80 authfile=/home/munshin/users.creds allow=munauth:https://user123:password123@myhost/creds
```

the 'authfile' option points to a file containing the user details that were generated by the 'munshin useradd' command, and the 'allow=munauth:' option points to a url that contains the 'signed string' generated by the 'munshin register' command.

For example the https://kvdb.io service allows one to set and get short strings of data from a user-unique URL. Thus a user at a remote location can generate a munauth string using:


```
munshin register https://kvdb.io/XiTy3f67DZAHiiqjYom7DA/munauth
```

Another site can then be configured as:

```
forward 80:192.168.5.1:80 authfile=/etc/munshin.auth allow=munauth:https://kvdb.io/XiTy3f67DZAHiiqjYom7DA/munauth
```

When a connection is made on port 80, the munshin process will http GET from the given url, and retrive the munauth string. This string contains a hash that is a combination of the username, IP address and password. The authenticating munshin looks up the users password using the path supplied to 'authfile' and produces its own hash using the details it has, and if they match then this confirms that the given user at the given IP knows the shared password and access can be granted.

This system allows access by anyone at a given IP, so the warnings given in 'The Coffee Shop Instance' apply.



htauth Authentication
---------------------

'htauth' is a mode that allows the insertion of an http login step before connecting to an http/https system. It is intended for use with IoT devices and other systems that present an HTTP/Web interface, but which might have authentication-bypass vulnerabilities or factory applied backdoors, or other such security weaknesses. It adds and extra authentication step that is handled by munshin. As munshin uses 'Basic' authentication it should always be used in combination with munshin-supplied TLS encryption. So for example:

```
	forward 8090s:htauth:192.168.5.11:80
```

forwards port 8090 to 192.168.5.11 port 80. The 's' after '8090' specifies that communications on this port should be TLS encrypted, and the ':htauth:' parameter indicates that the 'htauth' authentication step should be used before the connection is set up.

'htauth' authentication can authenticate a single connection, so is more secure in the 'coffee shop' environment. However it has the disadvantage that it only works for forwarding to http/https services.



WEB FRONTEND
============

Munshin can provide a simple and ugly web frontend that supplies a number of services: Depending on configuration:

1) Users can register themselves at a given IP or MAC address, so that address can be trusted in future. 
2) Users can allow or deny 'waiting' connections.
3) Users can obtain a one-time-password that can be used with socks5 or htauth authentication.

The web frontend always requires authentication. It *should* always be configured to use TLS/HTTPS encryption, unless it's being used over trusted networks.

The web frontend can be made available on a given port by a config entry like this:


```
service 8080s:webmgr ssl-cert=/etc/ssl/my_cert.crt ssl-key=/etc/ssl/my_key.key ip-db=/tmp/ip.permit mac-db=/tmp/mac.permit script=/tmp/script.sh confirms=/tmp/confirms.db otp-db=/tmp/otp.db
```

This line defines that a web management frontend runs on port 8080 with TLS/SSL encryption enabled and all the features of the web frontend active. The 'ip-db' option defines a path to a file in which 'registered' IP addresses are stored, and the mac-db option does the same for MAC addresses (see 'IP or MAC address registration' below). The 'confirms' option specifies a path to a file to watch for 'waiting connections' that need to be confirmed via the web frontend (see 'Confirmed Connections' below). The 'otp-db' specifies a file that one-time-passwords generated from the web-frontend will be stored in (see one-time-passwords below).


IP or MAC address registration
------------------------------

If a web_manager entry has an ipdb or macdb configured, then it will offer users a button to register either their IP address or MAC address in the database.

This system allows access by anyone at a given IP, so the warnings given in 'The Coffee Shop Instance' apply.


Confirmed Connections
---------------------

If a forward has been configured with a 'confirm' option that defines a 'confirm queue' file, then users with the correct permissions will be presented with the option to allow or deny these queued connections.

If a web frontend user is configured with 'confirm-self' permissions, they they will be able to allow or deny connections from the same IP Addres as the one they are connected to the web frontend from, and will only be shown those connections in the web interface. If the user is configured with 'confirm-all' then they will be able to allow/deny all waiting connections.



LOCAL CONNECTIONS
=================

On linux munshin can authenticate against the system user and process exectuable path for connections over a unix socket, or over local TCP. As this is dependant on the /proc filesystem and/or unix PEERSOCK credentials this is a linux only feature.

you can allow or deny local processes with entries like:


```
forward 8080:myhost.xyz:80 allow=process:/usr/bin/links
```

and local users with entries like:

```
forward 8080:myhost.xyz:80 allow=localuser:nobody
```



