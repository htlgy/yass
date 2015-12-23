#!/usr/bin/python

import sys, getopt, socket, os.path, time, random, signal
#netaddr should be installed
#pip install netaddr
from netaddr import *

IPList = []
portList = []

def displayHelp ():
   print ("yass - yet another SIP scanner v0.1 \n"
          "by Hakan Tolgay - www.hakantolgay.com\n"
          "                  hakan@hakantolgay.com\n\n"

          "Usage: ./yass -l <Local_IP_address> -r <remote_IP_address> -p <remote_port> [options]\n"
          "       ./yass -l <Local_IP_address> -r <remote_IP_address/subnet_prefix> -p <remote_port> [options]\n"
          "       ./yass -l <Local_IP_address> -r <remote_IP_address_range> -p <remote_port> [options]\n"
          "       ./yass -l <Local_IP_address> -f <file_of_IPs> -p <remote_port> [options]\n\n"

          "yass is a simple command line SIP scanner for finding SIP clients\n"
          "and SIP servers on a network.\n\n"

          "Options:\n"
          "  -h                This help text.\n"
          "  -l <IP_address>   Local interface to be used in scanning\n"
          "  -r <IP_address>   Target(s) to be scanned\n"
          "     ex: 192.168.1.47\n"
          "         192.168.1.1-192.168.1.9\n"
          "         192.168.1.0/24\n"
          "  -f <file_name>    Use file that contains previously defined IPs.\n"
          "                    When using this option, -r can not be used.\n"
          "  -p <remote_port>  Remote port of the target\n"
          "      ex: 5060\n"
          "          5060-5070\n"
          "  -q <local_port>   Local port for scanning. Default is 5868\n"
          "  -t <milliseconds> Timeout for each IP-port pair. Default value is 200ms\n"
          "  -m <method>  0,   Use 0 for scanning target via unimplemented SIP messages\n"
          "               1,   Use 1 for scanning target via SIP OPTIONS message\n"
          #"  -w <file_name>    Write output to a file\n"
          "  -s <port_status>  \n"
          "            open,  Display only open ports\n"
          "            closed, Display only closed ports\n\n")

def isPortValid (port_range):
   #if it is a range then it should have max 1 -
   if port_range.count('-') > 1:
      print 'not a valid range'
      return 0

   #port should be between 0-65535
   for PORT in port_range.split('-'):
      if (not PORT.isdigit()) or (int(PORT) < 0) or (int(PORT) > 65535):
         return 0

   #if it is a range then first port should be lower than final port in range
   if port_range.count('-') == 1:
      numberOfPorts = port_range.split('-')
      if int(numberOfPorts[1])-int(numberOfPorts[0]) < 0:
         print 'port range should be <lower port-higher port>'
         return 0
   return 1

def isIPValid (ip_range):

   range=0
   IPs=[('')]

   if ip_range.count ('/'):
      #This seems to be a subnet range
      IPs[0]=ip_range.split('/')[0]
      subnet=ip_range.split('/')[1]
      if not(subnet.isdigit() and int(subnet)>0 and int(subnet)<=31):
         return 0 #subnet seems not to be valid
   elif ip_range.count('-'):
      #This seems to be a range
      IPs[0]=ip_range.split('-')[0]
      IPs.append(ip_range.split('-')[1])
      range=1
   else:
      IPs[0]=ip_range

   for ip in IPs:
      if ip.count('.') == 3:
         for octet in ip.split('.'):
            if (not octet.isdigit()) or int(octet) < 0 or int(octet) > 255:
               return 0
      else:
         return 0

   #if it is a range then first beginging IP address should be lower than end address
   if ip_range.count('-'):
      IPsAsNums = ip_range.split('-')
      if (int(IPsAsNums[1].replace (".","")) - int(IPsAsNums[0].replace (".",""))) < 0:
         #the begining address is bigger than the end address
         print 'the begining address is bigger than the end address'
         return 0

   return 1

def scanIP (target, source, dPort, lPort, timeout, method, portStatus):

   SIPClient="could not obtained"

   # This is an "Not Imlemented" SIP message. Per RFC 3261, UAC or UAS should reply to this
   notimplementedPing = ("PING sip:" + target + ":" + dPort + " SIP/2.0\r\n"
                         "Via: SIP/2.0/UDP " + source + ":" + lPort + ";rport;z9hG4bK-2538-1-0\r\n"
                         "Call-ID: "+str(random.randint(10000000, 99999999))+"@1.1.1.1\r\n"
                         "From: sip:yass@1.1.1.1\r\n"
                         "To: sip:yass@1.1.1.1\r\n"
                         "CSeq: 1 PING\r\n\r\n")
   # This is SIP Options message.
   sipOptions = ("OPTIONS sip:" + target + ":" + dPort + " SIP/2.0\r\n"
                 "Via: SIP/2.0/UDP " + source + ":" + lPort + ";rport;z9hG4bK-2538-1-0\r\n"
                 "Content-Length: 0\r\n"
                 "From: sip:yass@1.1.1.1\r\n"
                 "To: sip:yass@1.1.1.1\r\n"
                 "Accept: application/sdp\r\n"
                 "User-Agent: yass_agent\r\n"
                 "Contact: sip:yass@" + source + ":" + dPort + "\r\n"
                 "CSeq: 1 OPTIONS\r\n"
                 "Call-ID: "+str(random.randint(10000000, 99999999))+"@1.1.1.1\r\n"
                 "Max-Forwards: 70\r\n\r\n")

   if method==0:  #Not Imlemented SIP message was choosed
      MESSAGE=notimplementedPing
   if method==1:  #SIP Options was choosed
      MESSAGE=sipOptions
   
   try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   except socket.error:
      print 'Failed to create socket'
      sys.exit()
   s.bind ((source,int(lPort)))
   s.sendto(MESSAGE, (target, int(dPort)))
   try:
      s.settimeout(timeout)
      # receive data from client (data, addr)
      data_received = s.recvfrom(1024)
      msg = data_received[0]
      s.close()
      #if it is not timed out we should be here
      #if SIP client info is available, then print it
      for line in msg.split("\n"):
         if "User-Agent:" in line:
            SIPClient = ((line.split(":"))[1]).rstrip()
      if portStatus != 'closed':
         print target, '  ', dPort, '  ', SIPClient, '  Open'
   except socket.timeout:
      if portStatus != 'open':
         print target, '  ', dPort, '  N/A',  '  Closed'
   except socket.error as exc:
      print exc
   s.close()


def getScanListPorts (portRange):
   portIndex=0

   #Generate a list of ports needs to be scanned
   beginPort=int((portRange.split('-'))[0])
   portList.append(beginPort)

   if portRange.count('-'):
      endPort=int((portRange.split('-'))[1])
      for portIndex in range(1,(endPort-beginPort)+1):
         portList.append(beginPort+portIndex)
   else:
      endPort=''

def getScanListIP (IPrange):

   if IPrange.count ('/'):
      #This seems to be a subnet range
      for IP in IPNetwork(IPrange):
         IPList.append(str(IP))
   elif IPrange.count('-'):
      #This seems to be a range
      beginIP = IPrange.split('-')[0]
      endIP = IPrange.split('-')[1]
      for  IP in IPSet(IPRange(beginIP,endIP)):
         IPList.append(str(IP))
   else:
      IPList.append(IPrange)

def getScanListFomFile (file):

   portIndex=0
   IPListFile = open(file, 'r')

   for line in IPListFile:
      line = str(line.rstrip('\n'))
      if isIPValid(str(line)):
         getScanListIP(line)

def exit_gracefully(signum, frame):
    signal.signal(signal.SIGINT, original_sigint)

    try:
        if raw_input("\nDo you really want to stop scan and quit? (y/n)> ").lower().startswith('y'):
            sys.exit(1)

    except KeyboardInterrupt:
        print("Ok ok, quitting")
        sys.exit(1)

    # restore the exit gracefully handler here
    signal.signal(signal.SIGINT, exit_gracefully)

def main(argv):

   LocalIP   = ''
   RemoteIP  = ''
   dPORT     = ''     #destination port
   lPORT     = '5868' #default local port
   fileOfIPs = ''
   rcvTimeout  = 0.200
   isParmsCorrect = 0
   outputFile = ''
   sipScanMethod = 1  # 0 Scan with Unimplemented SIP packets
                      # 1 Scan with SIP Options 
                      # Default is 1
   status     = 'all'

   try:
      opts, args = getopt.getopt (argv, "hl:r:p:q:t:f:m:s:")
   except getopt.GetoptError:
      displayHelp()
      sys.exit(2)

   for opt, arg in opts:
      if opt== '-h':
         displayHelp()
         sys.exit()
      if opt == '-l':
         LocalIP = arg
      elif opt == '-r':
         RemoteIP = arg
      elif opt == '-p':
         dPORT = arg
      elif opt == '-q':
         lPORT = arg
      elif opt == '-t':
         if arg.isdigit() and arg!=0:
            rcvTimeout = float(arg)/1000.0
         else:
            print "Timeout value: " , arg , " is not valid. Using default value " , rcvTimeout, "instead"
      elif opt == '-f':
         fileOfIPs = arg
      #to be implemented in the future
      #elif opt == '-w':
      #   outputFile == arg
      elif opt== '-m':
         if arg=="0" or arg=="1":
            sipScanMethod=int(arg)
         else:
            print "Method provided (", arg ,") is not valid. Using default value ", sipScanMethod
      elif opt == '-s':
         if arg=='open' or arg=="closed":
            status = arg
         else:
            displayHelp()
            sys.exit()

   if not isPortValid(dPORT):
      print 'Remote port must be in range of 1-65535\n'
      displayHelp()
      sys.exit()
   elif not isPortValid(lPORT):
      print 'Local port must be between 1-65535'
      displayHelp()
      sys.exit()
   elif  (not isIPValid(RemoteIP) and fileOfIPs==''):
      print 'Remote IP or IP range is not valid\n'
      displayHelp()
      sys.exit()
   elif not isIPValid(LocalIP):
      print 'Local IP is not valid\n'
      displayHelp()
      sys.exit()
   elif (not os.path.exists(fileOfIPs)) and RemoteIP=='' :
      print 'The IP list file is not exists\n'
      displayHelp()
      sys.exit()
   else:
      isParmsCorrect = 1


   if isParmsCorrect:
      getScanListPorts(dPORT)
      if RemoteIP!='':
         getScanListIP (RemoteIP)
      elif fileOfIPs!='':
         getScanListFomFile (fileOfIPs)

      threads = []
      for IP in IPList:
         for port in portList:
            scanIP (IP, LocalIP, str(port), lPORT, rcvTimeout, sipScanMethod,status)
            time.sleep (25.0 / 1000.0); #this delay is required
if __name__ == "__main__":
   original_sigint = signal.getsignal(signal.SIGINT)
   signal.signal(signal.SIGINT, exit_gracefully)
   main(sys.argv[1:])
