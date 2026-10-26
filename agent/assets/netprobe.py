"""Reports whether the guest can open outbound connections."""
import json
import socket

result = {}
for host, port in (("1.1.1.1", 53), ("203.0.113.9", 80)):
    try:
        socket.create_connection((host, port), timeout=1.0).close()
        result["%s:%d" % (host, port)] = "connected"
    except OSError as exc:
        result["%s:%d" % (host, port)] = "%s(errno=%s)" % (type(exc).__name__, exc.errno)
print(json.dumps(result))
