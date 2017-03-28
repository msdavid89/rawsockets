# rawsockets
Project 4 - CS5700

Project link: http://david.choffnes.com/classes/cs4700sp17/project4.php


TO DO: Check the TCP flow for when duplicate packets arrive or are sent out of order.



Responsibilities
-----------------------------------
Michael: TCP and HTTP code

Oladipupo: IP code and checksums
-----------------------------------

To run the code
-----------------------------------
Need to disable TCP checksum offloading to run in VM, configure iptables, etc. This is addressed in the Makefile.

-------------------------------------

Architecture:

We attempted to separate each of the three relevant layers (Application/HTTP, TCP, and IP) into their own sections.

TCP and IP each have their own classes to manage their portion of the connection as well as a class for the
header. The idea was to make this "similar" to how an operating system might implement them. Alternatively, we
considered having a send-side class to handle outgoing traffic and a receiving class to handle incoming traffic,
but a layered approach is more intuitive.

-------------------------------------------


Challenges:

There were a couple major areas where we got stuck.

1. It took a while before we were even able to get the low-level networking right.

2. In particular, we spent a full day trying to figure out why our code was able to successfully complete
the handshake, send an HTTP GET message and receive the corresponding ACK, but then the server would continuously
retransmit their initial response despite us being up-to-date with our ACKs. It turned out that the problem was that
we weren't resetting the checksum of our TCP packets to 0 before calculating it for the next packet, so our ACKs
were getting dropped due to bad checksums at the other end.

3. There were similar issues with the FIN packets at the end, and not incrementing the sequence number properly. At
first, we were passing in the FIN packet received and updating that to send back, but this was problematic because
our "response" had the local and remote ports reversed.


-------------------------------------

Assorted:

-We choose our sequence number between 0 and 65535, but it can go up to 4 billion or so. We should implement the
maximum sequence number with wrap around, otherwise if the server sends us a particularly high sequence number we won't
respond appropriately. Also, we are more susceptible to attacks that might guess the sequence #.

-Our implementation ACKs every packet received (except duplicates). It would be more efficient sending cumulative ACKs.

------------------------------------------

MD5:

50 MB file: bf6a729296a1949057ef3fa984b88950
2 MB file: a6020a2bd05e9217f52bc1568cc28077
Project4 web page: d8d4d3d065d1ab59a7908775c39249c3