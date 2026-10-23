# Zeek site config — Modbus logging for the solar farm lab.
#
# The CISA ICSNPP package adds modbus_detailed.log (addresses + request values)
# on top of Zeek's built-in modbus.log. The forwarder merges both per
# transaction. If ICSNPP is unavailable, the sensor entrypoint removes the
# @load line below so the built-in Modbus parser is used instead.
@load base/frameworks/notice
@load base/protocols/conn
@load policy/protocols/modbus/track-memmap
@load icsnpp-modbus

# Log all Modbus function codes (requests and responses).
redef Modbus::log_requests = T;
redef Modbus::log_responses = T;
