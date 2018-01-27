#!/usr/bin/env python
#-*- coding: utf-8 -*-
#############################################################################
# PyDNSProxy Configuration.
# - Code by Jioh L. Jung (ziozzang@gmail.com)
#############################################################################
#
# Functions: DNS Proxy + SNI/HTTP Proxy + Very Basic Authenticate
#
# Code from
#   - Basic SNI Proxy code from Phus Lu <phus.lu@gmail.com> https://github.com/phuslu/sniproxy/
#   - DNSProxy code from Crypt0s's FakeDNS. https://github.com/Crypt0s/FakeDns


import asyncio
import io
import logging
import struct
import ipaddress
import socket
import re
import sys
import os
import urllib.request
import re


#############################################################################
# Configuration.
#############################################################################
#  Auth IP list.
# if IP is in list or block, DNS and SNI proxy working.
#   else, ith doesn't reply.
auth_list = ["10.2.3.4", "10.3.4.5"]  # per IP Auth.
auth_block = ["10.1.0.0/16", "10.98.76.0/24"] # Block by
# Passphase for SNIProxy Open. dns query of this Record, the gate will be open!
passphase = "open.the.gate.sesami"

filter_exist_dns = True

if "AUTH_LIST" in os.environ:
    auth_list = os.environ["AUTH_LIST"].split(",")
if "AUTH_BLOCK" in os.environ:
    auth_block = os.environ["AUTH_BLOCK"].split(",")
if "PASSPHASE" in os.environ:
    passphase = os.environ["PASSPHASE"].strip()
if "FILTER_EXIST_DNS" in os.environ:
    if os.environ["FILTER_EXIST_DNS"].lower()[0] in ["t","y","1"]:
        filter_exist_dns = True
    else:
        filter_exist_dns = False
# IP Checker.
def get_external_ip():
    if "EXT_IP" in os.environ:
        return os.environ["EXT_IP"]
    site = urllib.request.Request("http://checkip.dyndns.org/")
    cont = urllib.request.urlopen(site).read().decode("utf-8")
    grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', cont)
    address = grab[0]
    return address

def get_local_ip():
    if "SELF_IP" in os.environ:
        return os.environ["SELF_IP"]
    return [(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) \
       for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

# Check If IP is in Allow IP List.
def _check_ip_exist(ip):
    if ip in auth_list:
        return True
    for i in auth_block:
        if ipaddress.IPv4Address(ip) in ipaddress.ip_network(i):
            return True
    return False

# Check Client IP and check passphase
def check_client_ip(ip, host=None):
    # TODO: do auth functions
    if host is None:
        return _check_ip_exist(ip)
    if host.endswith("."):
        host = host[:-1]
    if _check_ip_exist(ip):
        return True
    if host == passphase:
        logging.info("Add to Auth list: %s" % ip)
        auth_list.append(ip)
        return True
    return False

# Extract target hostname from HTTP/HTTPS header
def extract_server_name(packet):
    if packet.startswith(b'\x16\x03'):
        # For SNI Proxy Packet(HTTPS)
        logging.debug("Query is HTTPS")
        stream = io.BytesIO(packet)
        stream.read(0x2b)
        session_id_length = ord(stream.read(1))
        stream.read(session_id_length)
        cipher_suites_length, = struct.unpack('>h', stream.read(2))
        stream.read(cipher_suites_length+2)
        extensions_length, = struct.unpack('>h', stream.read(2))
        extensions = {}
        while True:
            data = stream.read(2)
            if not data:
                break
            etype, = struct.unpack('>h', data)
            elen, = struct.unpack('>h', stream.read(2))
            edata = stream.read(elen)
            if etype == 0:
                server_name = edata[5:].decode()
                return server_name
    else:
        stream = packet.split(b"\r\n\r\n", 1)
        if len(stream) <2:
           return
        else:
           stream = stream[0]
        stream = stream.decode("utf-8").lower()
        if stream.startswith("get") or stream.startswith("post") or \
           stream.startswith("put") or stream.startswith("delete") or \
           stream.startswith("head") or stream.startswith("set") or \
           stream.startswith("patch") or stream.startswith("options"):
            # Check Real HTTP Header.(Include RESTful Request)
            logging.debug("Query is HTTP")
            hdrs = [i.strip() for i in stream.split("\r\n")]
            for i in hdrs[1:]:
              k, v = i.split(":",1)
              if k == "host":
                return v.strip().lower()

# AsyncIO Controller Class
class Controller(object):
    def __init__(self, loop=None):
        self._loop = loop or asyncio.get_event_loop()
        self.servers = []  # Servers to close.

    def add_server(self, server):
        self.servers.append(server)

    def get_loop(self):
        return self._loop

    def start(self, and_loop=True):
        if and_loop:
            self._loop.run_forever()

    def stop(self, and_loop=True):
        for i in self.servers:
            i.close()
        if and_loop:
            self._loop.close()

# DNS Query parsing. (A record only)
class DNSQuery:
    def __init__(self, data):
      self.data = data
      self.domain = b''

      tipo = ((data[2]) >> 3) & 15   # Opcode bits
      if tipo == 0:                     # Standard query
          ini = 12
          lon = (data[ini])
          while lon != 0:
            self.domain += data[ini+1:ini+lon+1] + b'.'
            ini += lon+1
            lon = (data[ini])
      logging.debug("DNS Query Parsed: {0}".format(self.domain))
      self.domain = self.domain.decode("ascii")

# DNS response generating.
class DNSResponse:
    def __init__(self, query, rules):
        self.rules = rules
        self.data = query.data
        self.packet = b''
        ip = None
        match_status = False
        result_none = False

        for rule in self.rules.block_list:  # zone searching
            if (rule == query.domain[:-1]) or query.domain.endswith("."+rule+"."):
                logging.debug(">> Matched Request(BLOCK): " + query.domain)
                match_status = True
                result_none = True
                break
        if False == match_status:  # Exact Match
            for rule in self.rules.exact_list.keys():
                if rule == query.domain[:-1]:
                    match_status = True
                    ip = self.rules.exact_list[rule]
                    logging.debug(">> Matched Request(EXACT): " + query.domain + ":" + ip)
                    break
        if False == match_status:  # Forward Match
            for rule in self.rules.forw_list:  # zone searching
                if (rule == query.domain[:-1]) or query.domain.endswith("."+rule+"."):
                    match_status = True
                    try:
                        ip = socket.gethostbyname(query.domain)
                        logging.debug(">> Matched Request(FORW): " + query.domain + ":" + ip)
                    except:
                        result_none = True
                        logging.debug(">> Matched Request(FORW): " + query.domain + ": FAILED")
                    break
        if False == match_status:  # Zone searching.
            for rule in self.rules.zone_list.keys():  # zone searching
                if (rule == query.domain[:-1]) or query.domain.endswith("."+rule+"."):
                    match_status = True
                    ip = self.rules.zone_list[rule]
                    logging.debug(">> Matched Request(ZONE): " + query.domain + ":" + ip)
                    break
        if False == match_status:  # RegEx searching.
            for rule in self.rules.reallow_list:
                result = rule[0].match(query.domain)
                if result is not None:
                    match_status = True
                    ip = rule[1]
                    logging.debug(">> Matched Request(RE/ALLOW): " + query.domain + ":" + ip)
                    break
        if False == match_status:  # RegEx searching.
            for rule in self.rules.reblock_list:
                result = rule.match(query.domain)
                if result is not None:
                    match_status = True
                    result_none = True
                    logging.debug(">> Matched Request(RE/BLOCK): " + query.domain + ": BLOCKED")
                    break
        if (filter_exist_dns and match_status) and (result_none == False):  # Check Really domain exist, if flag set
            try:
                iptmp = socket.gethostbyname(query.domain)
                logging.debug(">> Check domain exist.. OK / Real: %s" % iptmp)
            except:
                ip = None
                logging.debug(">> Check domain exist.. Failed")

        if ip is None and result_none == False:  # We didn't find a match, get the real ip
            try:
                ip = socket.gethostbyname(query.domain)
                logging.debug(">> Unmatched request: " + query.domain + ":" + ip)
            except:  # That domain doesn't appear to exist, build accordingly
                logging.debug(">> Unable to parse request")
                result_none = True

        if result_none:
            # Build the response packet
            self.packet += self.data[:2] + b'\x81\x83'                         # Reply Code: No Such Name
            #                                                                  0 answer rrs   0 additional, 0 auth
            self.packet += self.data[4:6] + b'\x00\x00' + b'\x00\x00\x00\x00'  # Questions and Answers Counts
            self.packet += self.data[12:]                                      # Original Domain Name Question

        # Quick Hack
        if self.packet == b'':
            # Build the response packet
            self.data[:2] #transaction ID
            self.packet += self.data[:2] + b'\x81\x80'
            self.packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'   # Questions and Answers Counts
            self.packet += self.data[12:]                                          # Original Domain Name Question
            self.packet += b'\xc0\x0c'                                             # Pointer to domain name
            self.packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type,
            #                                                                      ttl and resource data length -> 4 bytes
            self.packet += ipaddress.ip_address(ip).packed

class ruleEngine:
    def __init__(self,file):
        self.reallow_list = []   # Regular Express Allow
        self.reblock_list = []   # Regular Expression Block/Dis-Allow
        self.zone_list = {} # Zone: Startswith *
        self.exact_list = {} # Exact Match Startswith =
        self.block_list = [] # Block Startswith -
        self.forw_list = [] # Forward: Startwith >
        logging.debug('>> Parse rules...')
        extip = None
        localip = None
        with open(file,'r') as rulefile:
            rules = rulefile.readlines()
            for rule in rules:
                if rule[0] == "#": # Process Comment
                    continue
                elif rule[0] == "-": # Blocking
                    self.block_list.append(rule[1:].strip())
                    logging.debug('>> BLOCK: %s' % (rule[1:].strip(),))
                    continue
                elif rule[0] == ">": # Forward
                    self.forw_list.append(rule[1:].strip())
                    logging.debug('>> FORWARD: %s' % (rule[1:].strip(),))
                    continue
                elif rule[0] == "^": # RegEx Block
                    self.reblock_list.append(re.compile(rule[1:].strip()))
                    logging.debug('>> RE/BLOCK: %s' % (rule[1:].strip(),))
                    continue
                splitrule = rule.split()
                if(len(splitrule)) <2:
                    continue
                if splitrule[1] == 'self':  # self will be local IP
                    if localip is None:
                        localip = get_local_ip()
                    splitrule[1] = localip
                elif splitrule[1] == 'extip':  # extip will be public IP
                    if extip is None:
                        extip = get_external_ip()
                    splitrule[1] = extip

                if rule[0] == "*":  # Zone
                    self.zone_list[splitrule[0][1:]] = splitrule[1]
                    logging.debug('>> ZONE: %s -> %s' % (splitrule[0][1:], splitrule[1]))
                elif rule[0] == "=":  # Exact
                    self.exact_list[splitrule[0][1:]] = splitrule[1]
                    logging.debug('>> EXACT: %s -> %s' % (splitrule[0][1:], splitrule[1]))
                elif rule[0] == "~":  # RegEx Allow
                    self.reallow_list.append([re.compile(splitrule[0][1:]),splitrule[1]])
                    logging.debug('>> RE/ALLOW: %s -> %s' % (splitrule[0], splitrule[1]))
            n = str(len(rules))
            logging.debug(">> %s rules parsed" % n)

# DNS Packet Handler.
class DNSPacketHandler:
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        query_res = DNSQuery(data)
        if False == check_client_ip(address[0], query_res.domain):  # Authentication
            return
        response = DNSResponse(query_res, rules).packet
        self.transport.sendto(response, address)

# DNS Server Class
class DNSServers(object):
    def __init__(self, controller, host, port):
        self.controller = controller
        self._port = port
        self._server_core = self.controller.get_loop().create_datagram_endpoint(
           DNSPacketHandler, local_addr=(host, port))

    def warmup(self):
        self._server, _transport = self.controller.get_loop().run_until_complete(self._server_core)
        self.controller.add_server(self._server)
        logging.info('Listening UDP Socket on {0}'.format(self._port))

# Proxy Server Class
class ProxyServers(object):
    def __init__(self, controller, host, port):
        self.controller = controller
        self._port = port
        self._server_core = asyncio.start_server(self.handle_connection, port=self._port)

    def warmup(self):
        self._server = self.controller.get_loop().run_until_complete(self._server_core)
        self.controller.add_server(self._server)
        logging.info('Listening established on {0}'.format(self._server.sockets[0].getsockname()))

    @asyncio.coroutine
    def io_copy(self, reader, writer):
        while True:
            data = yield from reader.read(4096)
            if not data:
                logging.debug("Connection End!!!")
                break
            writer.write(data)
        writer.close()

    @asyncio.coroutine
    def handle_connection(self, reader, writer):
        peername = writer.get_extra_info('peername')
        logging.info('Accepted connection from {}'.format(peername))
        data = yield from reader.read(1024)
        server_name = extract_server_name(data)
        logging.info('Attmpt open_connection to {}'.format(server_name))
        if False == check_client_ip(peername[0]) or (server_name is None):
            writer.close()
            logging.info('Connection Refused or Banned.')
            return
        remote_reader, remote_writer = yield from asyncio.open_connection(server_name, self._port)
        remote_writer.write(data)
        asyncio.async(self.io_copy(reader, remote_writer))
        yield from self.io_copy(remote_reader, writer)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ctl = Controller()

    path = 'dns.conf'

    # Specify a config path.
    if len(sys.argv) == 2:
        path = sys.argv[1]

    if not os.path.isfile(path):
        print ('>> Please create a "dns.conf" file or specify a config path: pydnsproxy.py [configfile]')
        exit()

    rules = ruleEngine(path)

    server_dns = DNSServers(ctl, "0.0.0.0", 53)
    if not ("ONLY_DNS_SERVER" in os.environ):
        server_443 = ProxyServers(ctl, None, 443)
        server_80  = ProxyServers(ctl, None, 80)

    try:
        server_dns.warmup()
        if not ("ONLY_DNS_SERVER" in os.environ):
            server_443.warmup()
            server_80.warmup()
        ctl.start()
    except KeyboardInterrupt:
        pass # Press Ctrl+C to stop
    finally:
        ctl.stop()

