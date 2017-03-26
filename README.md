# rawsockets
Project 4 - CS5700

Project link: http://david.choffnes.com/classes/cs4700sp17/project4.php

Responsibilities
----------------------
Michael:
Oladipupo:


Notes: Need to disable TCP checksum offloading to run in VM, configure iptables, etc.

-Currently doesn't deal with MTU for sending, but just attempts to send entire payload in one packet. This would
be fine for most "normal" inputs but a malicious input would cause issues. Note that the minimum MTU over IP is 68
bytes, but substracting the IP/TCP headers it is only 28 bytes, and our payload will be more than that.
----We can extract the MTU from the TCP packet received, if given.
-If we don't receive data from the server for 3 minutes, close the connection.
-For IPHeader, do flags and offset matter? Currently I just set them to 0
-We choose our sequence number between 0 and 65535, but it can go up to 4 billion or so. We should implement the
maximum sequence number with wrap around, otherwise if the server sends us a high sequence number we won't respond
appropriately.


-We do not use Connection: keep-alive in our HTTP header. This allows us to detect when the server is finished sending
the file simply by looking for a FIN packet.
-Our implementation ACKs every packet received (except duplicates). It could be more efficient sending cumulative ACKs.