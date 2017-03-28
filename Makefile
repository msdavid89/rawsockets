all:
    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    sudo ethtool --offload eth0 rx off tx off
    sudo ethtool -K eth0 gso off
    sudo ethtool -K eth0 gro off
    chmod 755 rawhttpget.py
    chmod 755 rawhttpget