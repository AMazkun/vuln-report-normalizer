import socket
from getmac import get_mac_address as gma
import ipaddress
import psutil
from typing import List, Optional, Any


def get_mac_from_scapy(ip):
    # print("get_mac_from_scapy")
    # pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    # ans, _ = srp(pkt, timeout=2, verbose=0)
    # print(ans)
    # for sent, received in ans:
    #     return received.hwsrc
    mac = gma(ip=ip)
    return mac
    return None


def get_hostname_from_socket(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def get_all_real_ip4() -> List[str]:
    ipv4_set = set()
    for iface, addrs in psutil.net_if_addrs().items():
        # пропускаем docker, br-, veth
        if iface.startswith(("docker", "br-", "veth")):
            continue

        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                ip_obj = ipaddress.ip_address(addr.address)
                # исключаем loopback и link-local
                if not ip_obj.is_loopback and not ip_obj.is_link_local:
                    ipv4_set.add(str(ip_obj))

    # сортируем по числовому порядку
    return sorted(ipv4_set, key=lambda ip: tuple(int(x) for x in ip.split(".")))

def get_router_ip():
    """
    Получает IP-адрес роутера, используя информацию о сокете.
    """
    try:
        # Создаем сокет для соединения с внешним сервером.
        # Мы не будем отправлять данные, а просто используем его
        # для определения локального IP-адреса, который будет
        # использоваться для маршрутизации.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)) # Подключаемся к общедоступному DNS-серверу Google
        router_ip = s.getsockname()[0]
        s.close()
        return router_ip
    except socket.error:
        return "Не удалось получить IP-адрес роутера."


def find_interface_by_broadcast(network_range) -> List[str]:
    target_net = ipaddress.ip_network(network_range, strict=False)
    interface_pool = []
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        for addr in iface_addrs:
            if addr.family.name == 'AF_INET' and addr.broadcast:
                try:
                    broadcast_ip = ipaddress.ip_address(addr.broadcast)
                    if broadcast_ip in target_net:
                        interface_pool.append(iface_name)
                except ValueError:
                    continue
    if len(interface_pool) == 0:
        interface_pool.append("")

    return interface_pool

