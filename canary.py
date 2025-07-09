import pyshark
import netifaces
import ipaddress
import json
import base64
import requests

class pckt():
    def __init__(self, time_stamp:str='',ipsrc:str='',ipdst:str='', srcport:str='', dstport:str='', transport_layer:str='',highest_layer:str=''):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstport = dstport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer

class apiServer():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port



intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intF)

def commServer(packet, server:apiServer):
    '''
    Determine if we communicate to our remote reporting canary

    Args:
        packet: captures pyshark
        server: apiServer
    
        return True | False if packet communication is to reporting server
    '''
    if ((hasattr(packet, 'ip')) and (hasattr('packet', 'tcp'))):
        if ((packet.ip.src == server.ip) or (packet.ip.dst == server.ip)):
            return True
        else:
            return False


    
server = apiServer('192.168.1.131', '8080')

def priv_addr_ip(ip_address:str)->bool:
    '''
    Determines if the given IP address is private RFC-1918

    Args:
        ip_address: The ip to check
    
    Return:
        True: If the ip is private RFC-1918
    '''
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private

def dispatch(message:pckt):
    temp = json.dumps(message.__dict__)

    jsonString = temp.encode('ascii')
    b64 = base64.b64encode(jsonString)

    jsonPayload = b64.decode('utf8').replace(" ' ", ' " ')
    print(jsonPayload)
    
    try:
        x = requests.get(f'http://{server.ip}:{server.port}/api/{jsonPayload}')

    except ConnectionError as err:
        pass
        # do logging to local file TODO:
        pass


def filters(packet):
    '''
    Filters packet on below stuff

    Args:
        packet: The packet from the capture
    '''
    # check to see if we are communicating to our canary
    if commServer(packet, server) is True:
        # Bail out
        return 
    if hasattr(packet, 'icmp'):
        # we were pinged
        packt = pckt()
        packt.ipdst = packet.ip.dst
        packt.ipsrc = packet.ip.src
        packt.highest_layer = packet.highest_layer
        packt.time_stamp = packet.sniff_timestamp
        dispatch(packt)

    if packet.transport_layer == 'TCP' or packet.transport_layer == 'UDP':
        packt = pckt()
        if hasattr(packet, 'ipv6'):
            '''
                Bail if ipv6
            '''
            return None
        if hasattr(packet, 'ip'):
            if (priv_addr_ip(packet.ip.src) is True) and (priv_addr_ip(packet.ip.dst) is True):
                # 
                packt.ipsrc = packet.ip.src
                packt.ipdst = packet.ip.dst
                packt.time_stamp = packet.sniff_timestamp
                packt.highest_layer = packet.highest_layer 
                packt.transport_layer = packet.transport_layer

                if hasattr(packet, 'UDP'):
                    pckt.dstport = packet.udp.dstport
                    pckt.srcport = packet.udp.srcport
                
                if hasattr(packet, 'tcp'):
                    pckt.dstport = packet.tcp.dstport
                    pckt.srcport = packet.tcp.srcport
                dispatch(packt)

        


for packet in capture.sniff_continuously():
    # print(packet)
    filters(packet)