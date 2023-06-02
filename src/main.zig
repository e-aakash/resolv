const std = @import("std");
const msg = @import("msg.zig");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    var mem_buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem_buffer);
    const allocator = fba.allocator();

    const args = try std.process.argsAlloc(allocator);

    if (args.len != 2) {
        printUsageAndExit(args);
    }

    // Generate message for DNS request
    const message = msg.message.forDomain(args[1]);
    std.debug.print("argument: {}\n", .{message});

    var buffer: [512]u8 = undefined;
    // var len = message.toBytes(buffer[0..]);
    const len = message.toBytesTCP(buffer[0..]);

    for (0..len) |i| {
        std.debug.print("{x:0>2}", .{buffer[i]});
    }
    std.debug.print("\n\n", .{});

    // USE TCP, no UDP yet in zig :(
    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 53 }, 53);
    const conn = try std.net.tcpConnectToAddress(address);
    defer conn.close();

    const sent = try conn.write(buffer[0..len]);

    var buf: [1024]u8 = undefined;
    const recv = try conn.read(buf[0..]);
    std.debug.print("len: {d}\t\tsent: {d}\trecv: {d}\n\n", .{ len, sent, recv });

    for (0..recv) |i| {
        std.debug.print("{x:0>2} ", .{buf[i]});
    }
    std.debug.print("\n\n", .{});

    var resp_h: msg.header = msg.header{};
    const resp_content = buf[2..recv];
    resp_h.fromBytes(resp_content[0..]);
    std.debug.print("response header: {}, flags: {b:0>16}\n", .{ resp_h, resp_h.flags });

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // don't forget to flush!
}

fn printUsageAndExit(args: [][:0]u8) void {
    std.debug.print("Usage: {s} [hostname]\n\n", .{args[0]});
    std.process.exit(1);
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());

    std.testing.refAllDecls(@This());
}
