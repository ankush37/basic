import socket
import asyncio
import dnslib
import time
# from res import resolve_a
from cache import LRUCache
import random
from resoution import resolve_a, resolve_ns, select_server
from logs import log_info, log_error, log_warning
from sc import get_predictions

# signal.signal


cache = LRUCache(10000)
cache.load_from_file("cache.txt")
cache.print_cache()

#13 root namserver
server_list = [
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "192.0.14.129",
    "199.7.83.42",
    "202.12.27.33"
]


class UDPServerProtocol:
    def __init__(self, black):
        self.black = black
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        question = dnslib.DNSRecord.parse(data)
        qname = str(question.questions[0].qname)
        if qname.endswith("."):
            qname = qname[:-1]
        if qname.startswith("www."):
            qname = qname[4:]
        print(f"Received request for {question.questions[0].qname}")
        # print(question.questions[0].qname)
        # print(type(question.questions[0].qname))
        # print(str(question.questions[0].qname), self.black[1])

        response = dnslib.DNSRecord()
        response.header = question.header
        response.header.qr = 1
        response.questions = question.questions

        domain = str(question.questions[0].qname)

        if domain in cache.cache:
            resolved_rr = cache.get(domain)
            for rr in resolved_rr:
                response.add_answer(rr)
            self.transport.sendto(response.pack(), addr)
            print(f"Resolved {domain} from cache")
            log_info(f"{domain}---{addr}---{str(resolved_rr[0].rdata)}")
            return

        if (qname in self.black or (qname + "www.") in self.black):
            log_info(f"Malicious domain from {addr} for {question.questions[0].qname}")
            response = dnslib.DNSRecord()
            response.header = question.header
            response.header.qr = 1
            response.questions = question.questions
            response.header.rcode = getattr(dnslib.RCODE, "NXDOMAIN")
            self.transport.sendto(response.pack(), addr)
            return
        
        response = dnslib.DNSRecord()
        response.header = question.header
        response.header.qr = 1
        response.questions = question.questions

        domain = str(question.questions[0].qname)
        
        if question.questions[0].qtype == 1:
            # if domain in cache.cache:
            #     resolved_rr = cache.get(domain)
            #     for rr in resolved_rr:
            #         response.add_answer(rr)
            #     self.transport.sendto(response.pack(), addr)
            #     print(f"Resolved {domain} from cache")
            #     log_info(f"{domain}---{addr}---{str(resolved_rr[0].rdata)}")
            #     return
            temp = [domain[:-1] if domain.endswith(".") else domain]
            if get_predictions(domain) == 1:
                log_info(f"DGA detected from {addr} for {question.questions[0].qname}")
                response = dnslib.DNSRecord()
                response.header = question.header
                response.header.qr = 1
                response.questions = question.questions
                response.header.rcode = getattr(dnslib.RCODE, "NXDOMAIN")
                self.transport.sendto(response.pack(), addr)
                return
            
            try:
                resolved_rr = resolve_a(domain, server=select_server(server_list), cache=cache)
            except Exception as e:
                log_error(f"{domain}---{addr}---{str(e)}")
                response.header.rcode = getattr(dnslib.RCODE, "NXDOMAIN")
                self.transport.sendto(response.pack(), addr)
                return
            if resolved_rr:
                for rr in resolved_rr:
                    response.add_answer(rr)
                log_info(f"{domain}---{addr}---{str(resolved_rr[0].rdata)}")
            else:
                response.header.rcode = getattr(dnslib.RCODE, "NXDOMAIN")
                log_info(f"{domain}---{addr}---'NXDOMAIN'")
        elif question.questions[0].qtype == 2:
            ns = resolve_ns(domain)
            if ns:
                for i in ns:
                    response.add_answer(i)
            else:
                response.header.rcode = getattr(dnslib.RCODE, "NXDOMAIN")
            
        self.transport.sendto(response.pack(), addr)

    def connection_lost(self, exc):
        cache.save_to_file("cache.txt")
        print("Connection closed")

async def main():
    with open("blacklist.txt", "r") as f:
        black = f.read()
    black = black.split("\n")
    # print(data)

    print("Starting UDP server")
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(black),
        local_addr=('localhost', 53)
    )
    log_info("Starting UDP server")
    try:
        while True:
            await asyncio.sleep(1)
        
    except asyncio.CancelledError:
        pass
        # print("Success dumped")
    finally:
        transport.close()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("Server closed")