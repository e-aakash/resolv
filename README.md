# resolv

This is my try at implementing DNS reolution program, while trying to learn zig. 

## Current status

Supports IPV4 name resolution only, displays A and CNAME record correctly, using local nameserver (`127.0.0.53:53`) over TCP port

### Usage

- `zig build run -- www.example.com`
- `zig build run -- www.insti.app`

