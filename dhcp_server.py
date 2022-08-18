import json
import random
import socket
import struct
import threading
import time


def getLeaseTimeInBytes(lease_time):
    t = str(hex(lease_time))
    t = t[2:]
    while len(t) < 8:
        t = '0' + t
    macb = b''
    for i in range(0, 8, 2):
        m = int(t[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb


class Client:
    def __init__(self, mac, ip, leaseTime):
        self.mac = mac
        self.ip = ip
        self.leaseTime = leaseTime

    def updateLeaseTime(self, t):
        self.leaseTime = t


class DHCPDiscover:
    def __init__(self, data):
        self.data = data
        self.transID = ''
        self.mac = ''
        self.rawMac = ''
        self.decodedTransID = ''
        self.unpack()

    def unpack(self):
        self.decodedTransID = str(struct.unpack('BBBB', self.data[4:8]))
        self.transID = self.data[4:8]
        self.rawMac = self.data[28:34]
        self.mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", self.data[28:34])

    def printDiscover(self):
        print('{0:20s} : {1:15s}'.format("transition ID", self.decodedTransID))
        print('{0:20s} : {1:15s}'.format("mac address", self.mac))


class DHCPOffer:
    def __init__(self, transID, IP, mac, serverIP):
        self.transID = transID
        self.IP = socket.inet_aton(IP)
        self.mac = mac
        self.serverIP = socket.inet_aton(serverIP)

    def buildPacket(self):
        OP = bytes([0x02, 0x01, 0x06, 0x00])
        XID = self.transID
        SECS = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        YIADDR = self.IP
        SIADDR = self.serverIP
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = self.mac
        CHADDR2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = b'\x35\x01\x02'
        End = bytes([0xff])

        package = OP + XID + SECS + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR5 + Magiccookie + DHCPOptions1 + End

        return package


class DHCPRequest:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.serverIP = ''
        self.mac = ''
        self.rawMac = ''
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.transID:
            self.rawMac = self.data[28:34]
            self.offerIP = '.'.join(map(lambda x: str(x), self.data[12:16]))
            self.serverIP = '.'.join(map(lambda x: str(x), self.data[20:24]))
            self.mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", self.data[28:34])

    def printReq(self):
        key = ['DHCP Server', 'Offered IP address', 'mac']
        val = [self.serverIP, self.offerIP, self.mac]
        for i in range(3):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))


class DHCPAck:
    def __init__(self, transID, IP, serverIP, mac):
        self.transID = transID
        self.IP = socket.inet_aton(IP)
        self.mac = mac
        self.serverIP = socket.inet_aton(serverIP)

    def buildPacket(self, res, lease_time):
        OP = b'\x02\x01\x06\x00'
        XID = self.transID
        SECS = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        YIADDR = self.IP
        SIADDR = self.serverIP
        GIADDR = b'\x00\x00\x00\x00'
        CHADDR1 = self.mac
        CHADDR2 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        CHADDR5 = bytes(192)
        MagicCookie = b'\x63\x82\x53\x63'
        package = OP + XID + SECS + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR5 + MagicCookie
        if res:
            DHCPOptions1 = b'\x35\x01\x05'
            DHCPOptions4 = getLeaseTimeInBytes(lease_time)
            package += DHCPOptions1 + DHCPOptions4
        else:
            DHCPOptions1 = b'\x35\x01\x06'
            package += DHCPOptions1
        End = bytes([0xff])

        package += End

        return package


def ip_to_int(ip):
    val = 0
    for i, s in enumerate(ip.split('.')):
        val += int(s) * 256 ** (3 - i)
    return val


def int_to_ip(val):
    octets = []
    for i in range(4):
        octets.append(str(val % 256))
        val = val >> 8
    return '.'.join(reversed(octets))


def findIPs(start, end, mode):
    res = []
    if mode == "range":
        s = ip_to_int(start)
        e = ip_to_int(end) + 1
    else:
        s = ip_to_int(start) + 1
        e = ip_to_int(end)
    for i in range(s, e):
        res.append(int_to_ip(i))
    return res


def subnet_calculator(addr, mask):
    addr = [int(x) for x in addr.split(".")]
    mask = [int(x) for x in mask.split(".")]
    netw = [addr[i] & mask[i] for i in range(4)]
    bcas = [(addr[i] & mask[i]) | (255 ^ mask[i]) for i in range(4)]
    return '.'.join(map(str, netw)), '.'.join(map(str, bcas))


MAX_BYTES = 65535
Src = "192.168.1.1"
Dest = "255.255.255.255"
clientPort = 67
serverPort = 68
ip_pool = []
dedicated_ips = []
reserve_random = False  # false means not reserved


def countdown(client):
    global updated_time
    while updated_time:
        timer = '{:02d}'.format(updated_time)
        print(client.mac, client.ip, timer)
        time.sleep(1)
        updated_time -= 1

    if not reserve_random:
        ip_pool.append(dedicated_ips[0])
        print(client.ip + "     is not for    " + client.mac + "    any more")
        dedicated_ips.remove(dedicated_ips[0])
    del client


if __name__ == '__main__':
    f = open('configs.json')
    configs = json.load(f)
    ip_pool = []
    if configs['pool_mode'] == "range":
        start = configs['range']['from']
        end = configs['range']['to']
        ip_pool = findIPs(start, end, "range")
    else:
        ip_block = configs['subnet']['ip_block']
        subnet_mask = configs['subnet']['subnet_mask']
        network, broadcast = subnet_calculator(ip_block, subnet_mask)
        ip_pool = findIPs(network, broadcast, 'subnet')

    reservation_list = configs['reservation_list']
    reserved_macs = reservation_list.keys()
    reserved_ips = reservation_list.values()
    for f in reserved_ips:
        for d in ip_pool:
            if d == f:
                ip_pool.remove(d)

    black_list = configs['black_list']

    print("DHCP server is running.")
    print("_________________________________________________")
    dest = (Dest, serverPort)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('', clientPort))
    last_mac = ''
    last_ip = ''
    while True:
        discoverData, _ = sock.recvfrom(MAX_BYTES)
        print('receive DHCP-DISCOVER----------------------------')
        dhcp_discover = DHCPDiscover(discoverData)
        dhcp_discover.printDiscover()

        if not last_mac == dhcp_discover.mac:
            offerIP = ""
            if dhcp_discover.mac in black_list:
                print("mac is in black list")
                break
            if dhcp_discover.mac in reserved_macs:
                offerIP = reservation_list[dhcp_discover.mac]
                dedicated_ips.append(offerIP)
            else:
                ip_index = random.randint(0, len(ip_pool) - 1)
                offerIP = ip_pool[ip_index]
                dedicated_ips.append(ip_pool[ip_index])
                del ip_pool[ip_index]
        else:
            offerIP = last_ip

        print('send DHCP-OFFER-----------------------------------')
        dhcp_offer = DHCPOffer(dhcp_discover.transID, offerIP, dhcp_discover.rawMac, Src)
        sock.sendto(dhcp_offer.buildPacket(), ('<broadcast>', 68))
        print('receive DHCP-REQUEST------------------------------')
        requestData, address = sock.recvfrom(MAX_BYTES)
        dhcp_request = DHCPRequest(requestData, dhcp_offer.transID)
        dhcp_request.printReq()
        print('send DHCP-ACK-------------------------------------')
        dhcp_ack = DHCPAck(dhcp_request.transID, dhcp_request.offerIP, dhcp_request.serverIP, dhcp_request.rawMac)
        sock.sendto(dhcp_ack.buildPacket(True, configs['lease_time']), ('<broadcast>', 68))

        t = int(configs['lease_time'])
        c = Client(dhcp_discover.mac, offerIP, t)
        last_mac = dhcp_request.mac
        if not last_ip == offerIP:
            t1 = threading.Thread(target=countdown, args=(c,))
            updated_time = t
            t1.start()

        else:
            updated_time = t

        last_ip = dhcp_request.offerIP
        print("DONE.    waiting for new client.")
