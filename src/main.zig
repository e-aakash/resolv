const std = @import("std");
const msg = @import("msg.zig");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});
    var mem_buffer: [8000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem_buffer);
    const allocator = fba.allocator();

    const args = try std.process.argsAlloc(allocator);

    if (args.len != 2) {
        printUsageAndExit(args);
    }

    // TODO: Parse arguments to take options also, like which ns to use, etc

    // Generate message for DNS request
    const message = msg.message.forDomain(args[1], allocator) catch unreachable;

    var buffer: [512]u8 = undefined;
    const len = message.toBytesTCP(buffer[0..]);

    // USE TCP, no UDP yet in zig :(
    const address = std.net.Address.initIp4([4]u8{ 8, 8, 8, 8 }, 53);
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

    const read_count = resp_message.fromBytes(resp_content[0..], allocator) catch unreachable;
    _ = read_count;

    // Send output to stdio
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    // TODO: Move print logic to respective structs?
    try stdout.print("Response header\n{any}\n", .{resp_message.header});
    if (resp_message.header.qdcount > 0)
        try stdout.print("\nResponse question\n{any}\n", .{resp_message.question});
    if (resp_message.header.ancount > 0) {
        try stdout.print("\nAnswer\n", .{});
        for (0..resp_message.header.ancount) |i| {
            const ans = resp_message.answers[i];
            try stdout.print("{s}\t{d}\t{d}\t{s}\t", .{
                ans.name,
                ans.ttl,
                ans.class,
                @tagName(ans.type),
            });
            switch (ans.rdata) {
                .raw => |val| {
                    try stdout.print("{any}", .{val});
                },
                .str => |val| {
                    try stdout.print("{s}", .{val});
                },
                .ipv4 => |ipv4| {
                    try ipv4.format("", undefined, stdout);
                },
            }
            try stdout.print("\n", .{});
        }
    }
    if (resp_message.header.nscount > 0)
        try stdout.print("\nResponse authority\n {any}\n", .{resp_message.authority});
    if (resp_message.header.arcount > 0)
        try stdout.print("\nResponse additional\n{any}\n", .{resp_message.additional});

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
