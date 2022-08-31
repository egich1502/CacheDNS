import time
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from dnslib import DNSRecord
from cache import Cache

ROOT_SERVER = '8.8.8.8'
CACHE_FILE = 'cache.txt'


class Server:
    def __init__(self, cache, host_ip='127.0.0.1', port=53):
        self.server = socket(AF_INET, SOCK_DGRAM)
        self.server.settimeout(2)
        self.server.bind((host_ip, port))
        self.cache = cache

    def start(self):
        while True:
            data, address = self.get_packet()
            response = self.handle_packet(data)
            self.clear_cache(time.time())
            self.server.sendto(response, address)

    def clear_cache(self, time_now):
        if time_now - self.cache.TIME_CACHE_CLEANED > 30:
            self.cache.remove_old_records()

    def get_packet(self):
        try:
            return self.server.recvfrom(256)
        except timeout:
            return self.get_packet()
        except Exception as e:
            self.server.close()
            print(e)
            exit()

    def handle_packet(self, package: bytes) -> bytes:
        ip = ROOT_SERVER
        byte_response = None
        response = None
        while response is None or len(response.rr) == 0:
            parsed_packet = DNSRecord.parse(package)
            cache_record = self.cache.get_if_exist(parsed_packet)
            if cache_record:
                return cache_record
            try:
                byte_response = parsed_packet.send(ip, timeout=4)
            except timeout:
                ip = ROOT_SERVER
                continue
            response = DNSRecord.parse(byte_response)
            if response.header.rcode == 3:
                return byte_response
            self.cache.add_records(response.ar)
            ip = next((str(x.rdata) for x in response.ar if x.rtype == 1), -1)
            if ip == -1 and len(response.rr) == 0:
                resp = self.handle_packet(DNSRecord.question(str(response.auth[0].rdata)).pack())
                ip = str(DNSRecord.parse(resp).rr[0].rdata)
        self.cache.add_records(response.rr)
        return byte_response


def main():
    cache = Cache.load_cache(CACHE_FILE)
    try:
        Server(cache).start()
    except (KeyboardInterrupt, SystemExit):
        print('Exit. Cache saved.')
        cache.save_cache(CACHE_FILE)


if __name__ == '__main__':
    main()
