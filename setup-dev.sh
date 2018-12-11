set -x

# conntrack module is not loaded (and thus eBPF probe cannot be loaded)
# so iptables needs to have a conntrack rule if we don't want to call modprobe manually
sudo ip6tables -t filter -A OUTPUT -m conntrack --ctstate related,established -j ACCEPT
sudo iptables -t filter -A OUTPUT -m conntrack --ctstate related,established -j ACCEPT
