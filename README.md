***************************************
* yass - Yet Another SIP Scanner v0.1 *
***************************************

WHAT IS YASS:
--------------
yass is a simple command line SIP scanner for finding SIP clients
and SIP servers on a network.

PREQUISEITES:
--------------
netaddr should be installed
> pip install netaddr

USAGE:
-------
Usage: ./yass -l <Local_IP_address> -r <remote_IP_address> -p <remote_port> [options]
       ./yass -l <Local_IP_address> -r <remote_IP_address/subnet_prefix> -p <remote_port> [options]
       ./yass -l <Local_IP_address> -r <remote_IP_address_range> -p <remote_port> [options]
       ./yass -l <Local_IP_address> -f <file_of_IPs> -p <remote_port> [options]

yass is a simple command line SIP scanner for finding SIP clients
and SIP servers on a network.

Options:
  -h                This help text.
  -l <IP_address>   Local interface to be used in scanning
  -r <IP_address>   Target(s) to be scanned
     ex: 192.168.1.47
         192.168.1.1-192.168.1.9
         192.168.1.0/24
  -f <file_name>    Use file that contains previosly defined IPs. 
                    when using this option, -r can not be used.
  -p <remote_port>  Remote port of the target
      ex: 5060
          5060-5070
  -q <local_port>   Local port for scanning. Default is 5868
  -t <milliseconds> Timeout for each IP-port pair. Default value is 200ms
  -m <method>  0,   Use 0 for scanning target via unimplemented SIP messages     
               1,   Use 1 for scanning target via SIP OPTIONS message
  -o                Display only Open ports
  -c                Display only Closed ports