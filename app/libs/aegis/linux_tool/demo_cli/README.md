## -config argument

path to a JSON file (e.g. config.json.sample)
\
Only `local.Arachne` uses the "mtu", `demo_cli` ignores it, if mtu = 0, `local.Arachne` will attempt to get the MTU of your primary interface.
\
Recognized strategies are "tlsfrag" and "overwrite".
\
"payload" should be base64-encoded.

## Warning
Haven't implemented DoH padding.
\
Two tools are both very buggy.
