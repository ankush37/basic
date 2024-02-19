import socket
import dnslib
import random
from logs import log_info, log_error, log_warning

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

def select_server(serverlist):
    return random.choice(serverlist)

def resolve_a(domain, server, cache, timeout=8):
    print(f"Resolving {domain} with {server}")
    q = dnslib.DNSRecord.question(domain, "A")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)

    s.sendto(q.pack(), (server, 53))
    data, addr = s.recvfrom(1024)
    s.close()
    res = dnslib.DNSRecord.parse(data)

    if (len(res.rr) > 0):
        print(f"Resolved: {str(res.rr[0].rdata)}")
        cache.put(domain, res.rr)
        return res.rr
    
    elif (len(res.ar) > 0):
        # print(res.ar[0].rdata)
        server_l = []
        for i in res.ar:
            if i.rtype == 1:
                server_l.append(str(i.rdata))
        while server_l:
            s = select_server(server_l)
            try:
                a = resolve_a(domain, s, cache, timeout=2)
                return a
            except socket.timeout:
                server_l.remove(s)
                log_warning(f"Timeout for {s}")
                continue
        return None

    elif (len(res.auth) > 0):
        # print(res.auth[0].rdata)
        server_domain = select_server(res.auth)
        if str(server_domain.rdata) in cache.cache:
            d = str(server_domain.rdata)
            rr = cache.get(d)
            ips = [str(i.rdata) for i in rr if i.rtype==1]
            # server_ip = cache.get(server_domain)
            while ips:
                s = select_server(ips)
                try:
                    a = resolve_a(domain, s, cache, timeout=2)
                    return a
                except socket.timeout:
                    ips.remove(s)
                    log_warning(f"Timeout for {s}")

                    continue
            return None
        # return resolve_a(domain, server_domain, cache)
        try:
            # print(server_domain.rtype)
            if (server_domain.rtype==6):
                return [server_domain,]
            rr = resolve_a(str(server_domain.rdata), select_server(server_list), cache, timeout=2)
        except socket.timeout:
            return None
        ips = [str(i.rdata) for i in rr if i.rtype==1]
        return resolve_a(domain, select_server(ips), cache, timeout=2)
    
    else:
        return None
    


def resolve_ns(domain, server, cache):
    print(f"Resolving {domain} with {server}")
    q = dnslib.DNSRecord.question(domain, "NS")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.sendto(q.pack(), (server, 53))
        data, addr = s.recvfrom(1024)
        s.close()
        res = dnslib.DNSRecord.parse(data)
        # print(res)

        if (len(res.rr) > 0):
            print(f"Resolved: {str(res.rr[0].rdata)}")
            # cache.put(domain, str(res.rr[0].rdata))
            return res.rr
        
        elif (len(res.ar) > 0):
            # print(res.ar[0].rdata)
            server_l = []
            for i in res.ar:
                if i.rtype == 1:
                    server_l.append(str(i.rdata))
            return resolve_ns(domain, server_l[0])

        elif (len(res.auth) > 0):
            print(res.auth[0].rdata)
            return resolve_ns(domain, resolve_a(str(res.auth[0].rdata)))
        
        else:
            return None
    except Exception as e:
        print(e)
        return None
    finally:
        s.close()