import socket
import sys
import urllib.request

from labcontracts import network

try:
    socket.create_connection(("127.0.0.1", network.PORTS["proxy"]), timeout=3).close()
    url = f"http://{network.ADDR['gateway_observer']}:{network.PORTS['gateway_control']}/health"
    urllib.request.urlopen(url, timeout=3).read()
except OSError as exc:
    sys.exit(f"unhealthy: {exc}")
