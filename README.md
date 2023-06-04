# resolv

This is my try at implementing DNS reolution program, while trying to learn zig. 

## Current status

Supports IPV4 name resolution only, displays A and CNAME record correctly, using google nameserver (`8.8.8.8:53`) over TCP port

### Usage

- `zig build run -- www.example.com`
- `zig build run -- www.insti.app`

