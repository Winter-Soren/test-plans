#!/bin/sh

set -ex

if [ -z "$DELAY_MS" ]; then
  echo "Error: DELAY_MS is not set!"
  exit 1
fi

ADDR_EXTERNAL=$(ip -json addr show eth0 | jq '.[0].addr_info[0].local' -r)
ADDR_INTERNAL=$(ip -json addr show eth1 | jq '.[0].addr_info[0].local' -r)
SUBNET_INTERNAL=$(ip -json addr show eth1 | jq '.[0].addr_info[0].local + "/" + (.[0].addr_info[0].prefixlen | tostring)' -r)

IFS=. read -r oct1 oct2 oct3 oct4 <<EOF
$ADDR_INTERNAL
EOF
# In the generated test LANs, `.2` is redis, `.4` is the client under test,
# and the router itself may vary depending on container creation order.
CLIENT_INTERNAL_IP="${oct1}.${oct2}.${oct3}.4"

# Set up NAT
nft add table ip nat
nft add chain ip nat prerouting { type nat hook prerouting priority -100 \; }
nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
nft add rule ip nat prerouting iifname "eth0" tcp dport 1-65535 dnat to "$CLIENT_INTERNAL_IP"
nft add rule ip nat prerouting iifname "eth0" udp dport 1-65535 dnat to "$CLIENT_INTERNAL_IP"
nft add rule ip nat postrouting ip saddr $SUBNET_INTERNAL oifname "eth0" snat $ADDR_EXTERNAL

# tc can only apply delays on egress traffic. By setting a delay for both eth0 and eth1, we achieve the active delay passed in as a parameter.
half_of_delay=$(expr "$DELAY_MS" / 2 )
param="${half_of_delay}ms"

tc qdisc add dev eth0 root netem delay $param
tc qdisc add dev eth1 root netem delay $param

echo "1" > /tmp/setup_done # This will be checked by our docker HEALTHCHECK

tail -f /dev/null # Keep it running forever.
