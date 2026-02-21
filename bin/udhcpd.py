import sys

proc=None

def __main__(args):

    if len(args) == 1:

        import udhcpdserver
        
        dport=67
        
        if args[0]=="start":
            print(f"Starting udhcpd service on port {dport}")
            udhcpdserver.start(port=dport, verbose=0)
            
        elif args[0]=="stop":
            udhcpdserver.stop()
            del sys.modules["uftpdserver"]

        elif args[0]=="restart":
            udhcpdserver.restart()

        else:
            print("Invalid argument")
    else:
        print ("udhcpd, udhcpd <options>, start, stop, restart")


"""
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
"""
