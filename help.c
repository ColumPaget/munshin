#include "help.h"
#include "config.h"

void PrintVersion()
{
    printf("munshin v%s\n",VERSION);
}

void PrintHelp()
{
    printf("usage:\n");
    printf("munshin [options]            run munshin server\n");
    printf("   options:  -f <path>       config file at <path> (default /etc/munshin.conf)\n");
    printf("             -?              this help\n");
    printf("             -help           this help\n");
    printf("             --help          this help\n");
    printf("             --help-config   print help for config file\n");
    printf("\n");
    printf("munshin adduser <name> [password] [options]         add user to authentication file\n");
    printf("   options:  -f <path>       add user to auth file at <path>\n");
    printf("\n");
    printf("munshin register <url> [options]                   register IP address by creating a 'signed string' and putting it to <url>\n");
    printf("   options:  -f <path>       register using user info in auth file at <path>\n");
    printf("             -u <user>       add user to file at <path>\n");
    printf("             -i <ip>         external ip address to register (autodetect if not supplied)\n");
    printf("\n");
}


void PrintHelpConfig()
{
printf("Default config file is: %s\n", GlobalConfig->ConfigFile); 
printf("\n");
printf("Config file can contain:\n");
printf("include <file path>       - include another config file\n");
printf("logfile <file path>       - path to logfile\n");
printf("pidfile <file path>       - path to pidfile\n");
printf("regionfiles <file path>   - path to regionfiles. Can include wildcards. Can include multiple paths separated by ':'\n");
printf("config <name> <options>   - create a configuration that can be used in multiple 'forward' or 'service' lines\n");
printf("forward <service port>:<tcp host>:<tcp port>   <options>                - create a TCP forwarding rule\n");
printf("forward <service port>:unix:<unix socket path> <options>                - create a forwarding rule from a TCP port TO a unix socket\n");
printf("forward <service port>:htauth:<tcp host>:<tcp port>   <options>         - create a forwarding rule with an http authentication demand. Usually this can only be forwarded to an http/https host\n");
printf("forward <service port>:socks5:<tcp host>:<tcp port>   <options>         - create a TCP forwarding rule using a socks5 interface for authentication\n");
printf("forward <service port>:cmd:<command to run>    <options>                - create a forwarding rule from a TCP port to a command (like inetd)\n");
printf("service <service port>:web_manager <options>                            - run a web management screen on a given port\n");
printf("service <service port>:socks5 <options>                                 - run a socks5 server on a given port\n"); 
printf("\n");
printf("allow/deny style options for forward/service entries:\n");
printf("  allow=<rule>             - allow connection if this rule matches (can be overriden by later rules)\n");
printf("  deny=<rule>              - deny connection if this rule matches (can be overriden by later rules)\n");
printf("  sufficent=<rule>         - allow connection immediately if this rule matches (cannot be overridden)\n");
printf("  suffice=<rule>           - allow connection immedialely if this rule matches (cannot be overridden)\n");
printf("  required=<rule>          - deny connection immediately if this rule fails (cannot be overridden)\n");
printf("  abort=<rule>             - deny connection immediately if this rule matches (cannot be overridden)\n");
printf("\n");
printf("rules for use with allow/deny style options\n");
printf("  all                      - allow or deny all connections\n");
printf("  ip:<addresses>           - match IP address. 'addresses' can be a comma-seperated list of IP addresses or IP ranges (using /xx notation). Wildcards are supported.\n");
printf("  mac:<addresses>          - match MAC address. 'addresses' can be a comma-seperated list of MAC addresses.\n");
printf("  region:<country codes>   - match geolocation of remote host. 'regions' can be a comma-separated list of two-letter country codes, or registrar names\n");
printf("  host:<host names>        - match hostname as looked up via DNS\n.");
printf("  dyndns:<host names>      - match hostname as looked up via a method compatible with dynamic dns services.\n");
printf("  dnslist:<dnsbl list>     - check if remote IP is in dns blocklists/allowlists.\n");
printf("  user:<user names>        - check user as verified by TLS/SSL certificate, local connection credentials, or munauth methods.\n");
printf("  process:<path>           - only works for local connections. Check process path.\n");
printf("  localuser:<user names>   - only works for local connections. Check local user.\n");
printf("  munauth:<config>         - check if connection is authenticated via the 'munauth' system\n");
printf("  cert-issuer:<name>       - check if TLS/SSL certificate was issued by named issuer.\n");
printf("\n");
printf("other options for forward/service entries:\n");
printf("  config=<config name>  - include previously defined named config\n");
printf("  idle=<seconds>        - idle timeout in seconds. munshin will disconnect if no traffic seen in *either direction* for this long\n");
printf("  src-ttl=<value>       - set ttl on source (client) connections\n");
printf("  src-tos=<value>       - set tos value on the source (client) connections\n");
printf("  sttl=<value>          - set ttl on source (client) connection\n");
printf("  stos=<value>          - set tos value on the source (client) connection\n");
printf("  dst-ttl=<value>       - set ttl on destination (target) connection\n");
printf("  dst-tos=<value>       - set tos value on the destination (target) connection\n");
printf("  dttl=<value>          - set ttl on destination (target) connection\n");
printf("  dtos=<value>          - set tos value on the destination (target) connection\n");
printf("  ssllevel=<value>      - minimum SSL/TLS version. one of 'ssl', 'tls1', 'tls1.1', or 'tls1.2'\n");
printf("  ssl-level=<value>     - minimum SSL/TLS version. one of 'ssl', 'tls1', 'tls1.1', or 'tls1.2'\n");
printf("  sslcert=<value>       - path to SSL/TLS certificate file to use for encryption\n");
printf("  ssl-cert=<value>      - path to SSL/TLS certificate file to use for encryption\n");
printf("  sslkey=<value>        - path to SSL/TLS key file to use for encryption\n");
printf("  ssl-key=<value>       - path to SSL/TLS key file to use for encryption\n");
printf("  sslciphers=<list>     - list of permitted SSL/TLS ciphers to use\n");
printf("  ssl-ciphers=<list>    - list of permitted SSL/TLS ciphers to use\n");
printf("  ssl-dhparams=<path>   - path to dhparams file needed for perfect-forward-secrecy SSL/TLS ciphers\n");
printf("  ssl-client-verify=<value>    - path to file or directory containing CA certificates for CLIENT certificate verification\n");
printf("  ssl-verify=<value>    - path to file or directory containing CA certificates for CONNECTION certificate verification\n");
printf("  chuser=<name>         - switch user to user <name> (defaults to 'nobody' or uid 99)\n");
printf("  chgroup=<name>        - switch user to user <name> (defaults to 'nobody' or uid 99)\n");
printf("  syslog=<level>:<msg>  - send syslog message <msg> with level <level>\n");
printf("  confirms=<path>       - path to a file to store 'waiting connections'. This activates the 'connection confirm' feature.\n");
printf("  ipdb=<path>           - path to an IP address database that can be updated by munshins web frontend.\n");
printf("  ip-db=<path>          - path to an IP address database that can be updated by munshins web frontend.\n");
printf("  macdb=<path>          - path to a MAC address database that can be updated by munshins web frontend.\n");
printf("  mac-db=<path>         - path to a MAC address database that can be updated by munshins web frontend.\n");
printf("  otpdb=<path>          - path to one-time-password file that can be updated by munshins web frontend.\n");
printf("  otp-db=<path>         - path to one-time-password file that can be updated by munshins web frontend.\n");
printf("  authdb=<path>         - path to authentication credentials file\n");
printf("  auth-db=<path>        - path to authentication credentials file\n");
printf("  banner=<text>         - 'banner' used for web-based services.\n");
}
