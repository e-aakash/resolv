const std = @import("std");
const msg = @import("msg.zig");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    var mem_buffer: [8000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem_buffer);
    const allocator = fba.allocator();

    const args = try std.process.argsAlloc(allocator);

    if (args.len < 2) {
        printUsageAndExit(args);
    }

    // Server address
    var address = std.net.Address.initIp4([4]u8{ 8, 8, 8, 8 }, 53);
    var foundServer = false;

    // TODO: Parse arguments to take options also, like which ns to use, etc
    for (args, 0..) |value, i| {
        _ = i;
        // Use the first argument with @ as DNS server (similar to `dig`)
        if (!foundServer and std.mem.startsWith(u8, value, "@")) {
            const server = value[1..];
            address = try std.net.Address.parseIp4(server, 53);
            std.debug.print("Using server: {}\n", .{address});
            foundServer = true;
        }
    }

    // Generate message for DNS request
    const message = msg.message.forDomain(args[1], allocator) catch unreachable;

    var buffer: [512]u8 = undefined;
    const len = message.toBytesTCP(buffer[0..]);

    // USE TCP, no UDP yet in zig (std.net) :(
    const conn = try std.net.tcpConnectToAddress(address);
    defer conn.close();

    const sent = try conn.write(buffer[0..len]);
    _ = sent;

    var buf: [1024]u8 = undefined;
    const recv = @truncate(u32, try conn.read(buf[0..]));

    var resp_message: msg.message = undefined;
    const resp_content = buf[2..recv];

    // std.debug.print("Full resp:\n", .{});
    // msg.print_slice(resp_content);
    // std.debug.print("\n", .{});

    const read_count = try resp_message.fromBytes(resp_content[0..], allocator);
    _ = read_count;

    // Send output to stdio
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("{any}\n", .{resp_message});
    try bw.flush(); // don't forget to flush!
}

fn printUsageAndExit(args: [][:0]u8) void {
    std.debug.print("Usage: {s} [hostname]\n\n", .{args[0]});
    std.process.exit(1);
}

test "simple test" {
    std.testing.refAllDecls(@This());
}
