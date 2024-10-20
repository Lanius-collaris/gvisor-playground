
## Status
WIP
## How to run demo_cli
In the first terminal
```
unshare -U -r -n
$ ip link set lo up
$ ip tuntap add mode tun name tun0
$ ip link set tun0 mtu 1500
$ ip link set tun0 up
$ ip addr add 10.0.2.100/24 dev tun0
$ ip addr add fd00::100/64 dev tun0
$ ip route add 0.0.0.0/0 dev tun0
$ ip route add ::/0 dev tun0
$ echo $$
3000
```
In the second terminal
```
$ go build -trimpath ./linux_tool/demo_cli
$ ./demo_cli -mode main -tun tun0 -target 3000
#3000 is the pid of target process.
```
