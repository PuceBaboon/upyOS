"""
  $Id: dhcpd.py,v 1.1 2026/02/16 23:52:40 gaijin Exp $

Minimal DHCP Server for MicroPython
Based on RFC2131 and RFC2132
"""
import socket
import struct
import time

# DHCP Message Types
DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPNAK = 6
DHCPACK = 5

# DHCP Options
DHCP_OPT_SUBNET_MASK = 1
DHCP_OPT_ROUTER = 3
DHCP_OPT_DNS = 6
DHCP_OPT_LEASE_TIME = 51
DHCP_OPT_MESSAGE_TYPE = 53
DHCP_OPT_SERVER_ID = 54
DHCP_OPT_REQUESTED_IP = 50
DHCP_OPT_END = 255

# DHCP Ports
PORT_DHCP_SERVER = 67
PORT_DHCP_CLIENT = 68

class DHCPServer:
    def __init__(self, server_ip='192.168.172.104', subnet_mask='255.255.255.0',
                 router_ip='192.168.172.51', dns_ip='192.168.172.49',
                 pool_start='192.168.172.202', pool_end='192.168.172.210'):
        """
        Initialize DHCP Server
        
        Args:
            server_ip: Server IP address
            subnet_mask: Network subnet mask
            router_ip: Default gateway
            dns_ip: DNS server
            pool_start: Start of IP pool to assign
            pool_end: End of IP pool to assign
        """
        self.server_ip = server_ip
        self.subnet_mask = subnet_mask
        self.router_ip = router_ip
        self.dns_ip = dns_ip
        
        # Parse IP pool range
        self.pool = self._generate_ip_pool(pool_start, pool_end)
        self.leases = {}  # {mac_address: (ip, expiry_time)}
        self.offers = {}  # {mac_address: ip}
        
        # Socket for DHCP server
        self.sock = None
        
    def _generate_ip_pool(self, start_ip, end_ip):
        """Generate list of IPs in the pool"""
        def ip_to_int(ip_str):
            parts = [int(x) for x in ip_str.split('.')]
            return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        
        def int_to_ip(n):
            return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"
        
        start_int = ip_to_int(start_ip)
        end_int = ip_to_int(end_ip)
        
        return [int_to_ip(i) for i in range(start_int, end_int + 1)]
    
    def _get_available_ip(self):
        """Get an available IP from the pool"""
        taken_ips = set(self.leases.values()) | set(self.offers.values())
        for ip in self.pool:
            if ip not in taken_ips:
                return ip
        return None
    
    def _ip_to_bytes(self, ip_str):
        """Convert IP string to 4 bytes"""
        return bytes([int(x) for x in ip_str.split('.')])
    
    def _build_dhcp_packet(self, request_packet, message_type, client_mac, client_ip):
        """Build a DHCP response packet"""
        # Parse request header (first 240 bytes of DHCP packet)
        xid = request_packet[4:8]  # Transaction ID
        flags = request_packet[10:12]
        
        # Build response packet
        response = bytearray(240)
        response[0] = 2  # DHCP reply
        response[1:4] = request_packet[1:4]  # HW type, HW len, Hops
        response[4:8] = xid  # Transaction ID
        response[8:10] = b'\x00\x00'  # Seconds
        response[10:12] = flags  # Broadcast/Unicast flag
        response[12:16] = self._ip_to_bytes(client_ip)  # Client IP
        response[16:20] = self._ip_to_bytes(self.server_ip)  # Server IP
        response[20:24] = self._ip_to_bytes(self.server_ip)  # Gateway IP
        response[28:34] = client_mac  # Client MAC
        
        # Magic cookie
        response[236:240] = b'\x63\x82\x53\x63'
        
        # Build options
        options = bytearray()
        
        # Message Type
        options += bytes([DHCP_OPT_MESSAGE_TYPE, 1, message_type])
        
        # Server Identifier
        options += bytes([DHCP_OPT_SERVER_ID, 4]) + self._ip_to_bytes(self.server_ip)
        
        # Subnet Mask
        options += bytes([DHCP_OPT_SUBNET_MASK, 4]) + self._ip_to_bytes(self.subnet_mask)
        
        # Router
        options += bytes([DHCP_OPT_ROUTER, 4]) + self._ip_to_bytes(self.router_ip)
        
        # DNS
        options += bytes([DHCP_OPT_DNS, 4]) + self._ip_to_bytes(self.dns_ip)
        
        # Lease Time (1 hour)
        lease_time = 3600
        options += bytes([DHCP_OPT_LEASE_TIME, 4]) + struct.pack('>I', lease_time)
        
        # End option
        options += bytes([DHCP_OPT_END])
        
        return response + options
    
    def _parse_dhcp_packet(self, packet):
        """Parse incoming DHCP packet"""
        if len(packet) < 240:
            return None
        
        message_type = None
        requested_ip = None
        client_mac = packet[28:34]
        xid = packet[4:8]
        
        # Parse options
        i = 240
        while i < len(packet):
            option = packet[i]
            if option == DHCP_OPT_END:
                break
            if option == 0:  # Padding
                i += 1
                continue
            
            length = packet[i + 1] if i + 1 < len(packet) else 0
            value = packet[i + 2:i + 2 + length]
            
            if option == DHCP_OPT_MESSAGE_TYPE:
                message_type = value[0]
            elif option == DHCP_OPT_REQUESTED_IP:
                requested_ip = '.'.join(str(b) for b in value)
            
            i += 2 + length
        
        return {
            'message_type': message_type,
            'requested_ip': requested_ip,
            'client_mac': client_mac,
            'xid': xid
        }
    
    def start(self):
        """Start the DHCP server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind(('0.0.0.0', PORT_DHCP_SERVER))
            print(f"DHCP Server started on {self.server_ip}:67")
            self._run()
        except OSError as e:
            print(f"Failed to bind DHCP socket: {e}")
    
    def _run(self):
        """Main server loop"""
        while True:
            try:
                packet, addr = self.sock.recvfrom(1024)
                self._handle_request(packet, addr)
            except OSError:
                pass
            except KeyboardInterrupt:
                break
            time.sleep(0.1)
    
    def _handle_request(self, packet, addr):
        """Handle incoming DHCP request"""
        parsed = self._parse_dhcp_packet(packet)
        if not parsed or not parsed['message_type']:
            return
        
        message_type = parsed['message_type']
        client_mac = parsed['client_mac']
        
        if message_type == DHCPDISCOVER:
            # Offer an IP
            available_ip = self._get_available_ip()
            if available_ip:
                self.offers[client_mac] = available_ip
                response = self._build_dhcp_packet(
                    packet, DHCPOFFER, client_mac, available_ip
                )
                self._send_response(response, addr)
                print(f"DHCPDISCOVER from {client_mac.hex()}: offered {available_ip}")
        
        elif message_type == DHCPREQUEST:
            # Assign IP
            if client_mac in self.offers:
                ip = self.offers[client_mac]
                self.leases[client_mac] = ip
                del self.offers[client_mac]
                response = self._build_dhcp_packet(
                    packet, DHCPACK, client_mac, ip
                )
                self._send_response(response, addr)
                print(f"DHCPREQUEST from {client_mac.hex()}: assigned {ip}")
    
    def _send_response(self, response, addr):
        """Send DHCP response"""
        try:
            self.sock.sendto(response, (addr[0], PORT_DHCP_CLIENT))
        except OSError as e:
            print(f"Failed to send DHCP response: {e}")
    
    def stop(self):
        """Stop the DHCP server"""
        if self.sock:
            self.sock.close()
        print("DHCP Server stopped")


# Usage example
if __name__ == '__main__':
    server = DHCPServer(
        server_ip='192.168.172.1',
        subnet_mask='255.255.255.0',
        router_ip='192.168.172.1',
        dns_ip='8.8.8.8',
        pool_start='192.168.172.100',
        pool_end='192.168.172.150'
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
