import random
import socket
import struct
from random import randint
from uuid import getnode as get_mac


def getMac():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12:
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb


class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t)

    def buildPacket(self):
        OP = b'\x01\x01\x06\x00'
        XID = self.transactionID
        SECS = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        CHADDR1 = getMac()
        CHADDR2 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        CHADDR5 = bytes(192)
        MagicCookie = b'\x63\x82\x53\x63'
        DHCPOptions1 = b'\x35\x01\x01'
        End = b'\xff'  # End Option

        package = OP + XID + SECS + CHADDR1 + CHADDR2 + CHADDR5 + MagicCookie + DHCPOptions1 + End

        return package


class DHCPOffer:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.offerIP = ''
        self.ServerIP = ''
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.transID:
            self.offerIP = '.'.join(map(lambda x: str(x), self.data[16:20]))
            self.ServerIP = '.'.join(map(lambda x: str(x), self.data[20:24]))

    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address']
        val = [self.ServerIP, self.offerIP]
        for i in range(2):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))


class DHCPRequest:
    def __init__(self, transID, offerIP, serverIP):
        self.transactionID = transID
        self.offerIP = offerIP
        self.serverIP = serverIP

    def buildPacket(self):
        macb = getMac()
        OP = b'\x01'
        HTYPE = b'\x01'
        HLEN = b'\x06'
        HOPS = b'\x00'
        XID = self.transactionID
        SECS = b'\x00\x00\x00\x00'
        CIADDR = self.offerIP
        YIADDR = b'\x00\x00\x00\x00'
        SIADDR = self.serverIP
        GIADDR = b'\x00\x00\x00\x00'
        CHADDR1 = macb
        CHADDR2 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        CHADDR5 = bytes(192)
        MagicCookie = b'\x63\x82\x53\x63'
        DHCPOptions1 = b'\x35\x01\x03'
        End = b'\xff'  # End option

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR5 + MagicCookie + DHCPOptions1 + End

        return package


class DHCPAck:
    def __init__(self, data, transID):
        self.data = data
        self.transID = transID
        self.IP = ''
        self.serverIP = ''
        self.leaseTime = ''
        self.res = ''
        self.unpack()

    def unpack(self):
        if self.data[4:8] == self.transID:
            self.IP = '.'.join(map(lambda x: str(x), self.data[16:20]))
            self.serverIP = '.'.join(map(lambda x: str(x), self.data[20:24]))
            self.res = str(struct.unpack('BBB', self.data[240:243]))
            if self.res == "(53, 1, 5)":
                self.leaseTime = str(struct.unpack('!L', self.data[243:247])[0])

    def printAck(self):
        key = ['DHCP Server', 'IP address']
        val = [self.serverIP, self.IP]
        for i in range(2):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))
        if self.res == "(53, 1, 5)":
            print('{0:20s} : {1:15s}'.format("result", "ACK"))
            print('{0:20s} : {1:15s}'.format('lease time (s)', self.leaseTime + "s"))
        else:
            print("result : NACK")


MAX_BYTES = 65535
Src = "192.168.1.1"
Dest = "255.255.255.255"
clientPort = 67
serverPort = 68
if __name__ == '__main__':
    # defining the socket
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # broadcast

    try:
        dhcps.bind(('', 68))  # we want to send from port 68
    except Exception as e:
        print('port 68 in use...')
        dhcps.close()
        input('press any key to quit...')
        exit()

    ordinal = lambda n: "%d%s" % (n, "tsnrhtdd"[(n // 10 % 10 != 1) * (n % 10 < 4) * n % 10::4])
    print("DHCP Client is running.")
    print("______________________________________________________________")
    while True:
        # buiding and sending the DHCPDiscover packet
        i = 0
        initial_interval = 2
        backoff_cutoff = 5
        while True:
            i += 1
            print('send ' + ordinal(i) + ' DHCP-DISCOVER----------------------------------------')
            discoverPacket = DHCPDiscover()
            dhcps.sendto(discoverPacket.buildPacket(), ('<broadcast>', 67))

            s_b = False
            print("receive DHCP-OFFER--------------------------------------------")

            dhcps.settimeout(initial_interval)
            try:
                offerData, address = dhcps.recvfrom(MAX_BYTES)
                offerPacket = DHCPOffer(offerData, discoverPacket.transactionID)
                offerPacket.printOffer()
                break
            except socket.timeout:
                print("tried initial_interval   :", initial_interval)
                initial_interval = round((round(random.uniform(0.01, 1), 2) * 2 * initial_interval) + 1, 1)
                if initial_interval >= backoff_cutoff:
                    initial_interval = backoff_cutoff

        print('send DHCP-REQUEST---------------------------------------------')
        requestPacket = DHCPRequest(discoverPacket.transactionID, offerPacket.data[16:20], offerPacket.data[20:24])
        dhcps.sendto(requestPacket.buildPacket(), ('<broadcast>', 67))

        print('receive DHCP-ACK----------------------------------------------')
        dhcps.settimeout(5)
        try:
            ackData, _ = dhcps.recvfrom(MAX_BYTES)
            ackPacket = DHCPAck(ackData, requestPacket.transactionID)
            ackPacket.printAck()
            break
        except socket.timeout:
            print("receive DHCP-ACK timeout.\n")

    print('DHCP DONE.')
