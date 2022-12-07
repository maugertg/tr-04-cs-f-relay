import ipaddress


def get_ip_type(address):
    try:
        ip = ipaddress.ip_address(address)

        if isinstance(ip, ipaddress.IPv4Address):
            return "ip"
        elif isinstance(ip, ipaddress.IPv6Address):
            return "ipv6"
    except ValueError:
        print(f"{address} is an invalid IP address")


ips = ["10.10.10.35", "fe80::ad4a:c963:5d9f:54ee", "fe80::d076:857e:a3c5:fd51"]


for ip in ips:
    ip_obj = ipaddress.ip_address(ip)
    # print(dir(ip_obj))
    print(ip_obj._version)
    print(get_ip_type(ip))
