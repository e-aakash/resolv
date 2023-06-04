// Components of the flag section, which we don't need/use
// pub const qr = enum(bool) { query, response };
// pub const opcode = enum(u4) { query, iquery, status };
// pub const rcode = enum(u4) { no_error, format, server, name, not_implemented, refused };

const std = @import("std");

pub const header = struct {
    id: u16 = 0,
    flags: u16 = 0,
    qdcount: u16 = 0,
    ancount: u16 = 0,
    nscount: u16 = 0,
    arcount: u16 = 0,

    pub fn fromBytes(h: *header, buf: []const u8) u32 {
        // TODO: Use readIntForeign to remove bit manipulation?
        h.id = (@as(u16, buf[0]) << 8) + buf[1];
        h.flags = (@as(u16, buf[2]) << 8) + buf[3];
        h.qdcount = (@as(u16, buf[4]) << 8) + buf[5];
        h.ancount = (@as(u16, buf[6]) << 8) + buf[7];
        h.nscount = (@as(u16, buf[8]) << 8) + buf[9];
        h.arcount = (@as(u16, buf[10]) << 8) + buf[11];

        return 12;
    }

    pub fn toBytes(self: *const header, output: []u8) u32 {
        std.debug.assert(output.len >= 12);
        comptime var i: u32 = 0;

        // TODO: use comptime to cleanup this?
        std.mem.writeIntForeign(u16, output[i..(i + 2)], self.id);
        i += 2;
        std.mem.writeIntForeign(u16, output[i..(i + 2)], self.flags);
        i += 2;
        std.mem.writeIntForeign(u16, output[i..(i + 2)], self.qdcount);
        i += 2;
        std.mem.writeIntForeign(u16, output[i..(i + 2)], self.ancount);
        i += 2;
        std.mem.writeIntForeign(u16, output[i..(i + 2)], self.nscount);
        i += 2;
        std.mem.writeIntForeign(u16, output[i..(i + 2)], self.arcount);
        i += 2;
        return i;
    }
};

test "header from bytes" {
    var bytes = [_]u8{ 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1 };
    var h = header{ .id = 0, .flags = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 };

    _ = h.fromBytes(bytes[0..]);
    try std.testing.expectEqual(@as(u16, 1), h.id);
    try std.testing.expectEqual(@as(u16, 0), h.flags);
    try std.testing.expectEqual(@as(u16, 1), h.qdcount);
    try std.testing.expectEqual(@as(u16, 1), h.ancount);
    try std.testing.expectEqual(@as(u16, 1), h.nscount);
    try std.testing.expectEqual(@as(u16, 257), h.arcount);
}

test "header to bytes" {
    var bytes = [_]u8{0} ** 16;
    var h = header{ .id = 258, .arcount = 4, .ancount = 2 };

    try std.testing.expectEqual(@as(u32, 12), h.toBytes(bytes[0..]));
    try std.testing.expectEqual(@as(u8, 1), bytes[0]);
    try std.testing.expectEqual(@as(u8, 2), bytes[1]);

    try std.testing.expectEqual(@as(u8, 0), bytes[6]);
    try std.testing.expectEqual(@as(u8, 2), bytes[7]);

    try std.testing.expectEqual(@as(u8, 0), bytes[10]);
    try std.testing.expectEqual(@as(u8, 4), bytes[11]);
}

pub const question = struct {
    qname: []u8 = "",
    qtype: u16 = 0,
    qclass: u16 = 0,

    pub fn fromBytes(self: *question, input: []const u8, allocator: std.mem.Allocator) !u32 {
        var name: [:0]u8 = try allocator.allocSentinel(u8, 256, 0);
        var offset: u32 = 0;
        var parse_out = parse_name(input, offset, name);

        self.qname = name[0..(parse_out.output_written)];
        offset += parse_out.offset;

        self.qtype = slice_to_int(u16, input[0..], &offset);
        self.qclass = slice_to_int(u16, input[0..], &offset);

        return offset;
    }

    pub fn toBytes(self: *const question, output: []u8) u32 {
        std.debug.assert((self.qname.len + 4) <= output.len);

        var parts = std.mem.split(u8, self.qname, ".");

        var index: u32 = 0;
        while (parts.next()) |part| {
            output[index] = @truncate(u8, part.len);
            index += 1;
            for (part) |char| {
                output[index] = char;
                index += 1;
            }
        }
        output[index] = 0;
        index += 1;

        output[index] = @truncate(u8, self.qtype >> 8);
        index += 1;
        output[index] = @truncate(u8, self.qtype & 0b11111111);
        index += 1;
        output[index] = @truncate(u8, self.qclass >> 8);
        index += 1;
        output[index] = @truncate(u8, self.qclass & 0b11111111);
        index += 1;

        return index;
    }
};

test "question from bytes" {
    var input = [_]u8{ 3, 'e', 'a', 'a', 2, 'x', 'y', 0, 0, 1, 1, 1 };
    var q = question{ .qname = "", .qtype = 0, .qclass = 0 };

    var mem_buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem_buffer);
    const allocator = fba.allocator();

    var out = q.fromBytes(input[0..], allocator);

    try std.testing.expectEqual(@as(u32, 12), out catch unreachable);
    try std.testing.expectEqualStrings("eaa.xy", q.qname);
    try std.testing.expectEqual(@as(u32, 1), q.qtype);
    try std.testing.expectEqual(@as(u32, 257), q.qclass);
}

test "question to bytes" {
    var b = [_]u8{0} ** 10;
    var name = [_]u8{ 'a', 'b', '.', 'd' };

    const q = question{ .qname = &name, .qtype = 0, .qclass = 259 };

    try std.testing.expectEqual(@as(u32, 10), q.toBytes(b[0..]));

    try std.testing.expectEqual(b, [_]u8{ 2, 'a', 'b', 1, 'd', 0, 0, 0, 1, 3 });
}

pub const message = struct {
    header: header,
    question: []question = &[_]question{},
    answers: []resource_record = &[_]resource_record{},
    authority: []resource_record = &[_]resource_record{},
    additional: []resource_record = &[_]resource_record{},

    pub fn forDomain(domain: []u8, allocator: std.mem.Allocator) !message {
        const h = header{ .id = 1, .flags = 1 << 8, .qdcount = 1 };
        const q = question{ .qname = domain, .qtype = 1, .qclass = 1 };

        var qs = try allocator.alloc(question, 1);
        qs[0] = q;
        const m = message{ .header = h, .question = qs[0..] };
        return m;
    }

    pub fn toBytes(self: *const message, buffer: []u8) u32 {
        const header_len = self.header.toBytes(buffer[0..]);
        const question_len = self.question.toBytes(buffer[header_len..]);

        return header_len + question_len;
    }

    // TCP needs 2 bytes at start of the buffer (https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2)
    pub fn toBytesTCP(self: *const message, buffer: []u8) u32 {
        const header_len = self.header.toBytes(buffer[2..]);
        // FIXME: Update this to use allow variable questions
        const question_len = self.question[0].toBytes(buffer[(2 + header_len)..]);

        const msg_len = header_len + question_len;
        buffer[0] = @truncate(u8, msg_len >> 8);
        buffer[1] = @truncate(u8, msg_len & 0b11111111);
        return 2 + msg_len;
    }

    pub fn fromBytes(self: *message, msg: []const u8, allocator: std.mem.Allocator) !u32 {
        var offset: u32 = 0;

        var h = header{};
        offset += h.fromBytes(msg[0..]);
        self.header = h;

        if (self.header.qdcount != 0) {
            self.question = try allocator.alloc(question, self.header.qdcount);
            for (0..(h.qdcount)) |i| {
                offset += try self.question[i].fromBytes(msg[offset..], allocator);
            }
        }

        if (self.header.ancount != 0) {
            self.answers = try allocator.alloc(resource_record, self.header.ancount);
            for (0..(h.ancount)) |i| {
                offset += try self.answers[i].fromBytes(msg, offset, allocator);
            }
        }

        if (self.header.nscount != 0) {
            self.authority = try allocator.alloc(resource_record, self.header.nscount);
            for (0..(h.nscount)) |i| {
                offset += try self.authority[i].fromBytes(msg, offset, allocator);
            }
        }

        if (self.header.arcount != 0) {
            self.additional = try allocator.alloc(resource_record, self.header.arcount);
            for (0..(h.arcount)) |i| {
                offset += try self.additional[i].fromBytes(msg, offset, allocator);
            }
        }

        return offset;
    }
};

// TODO: Add basic tests for message

pub const rr_type = enum(u16) {
    A = 1,
    NS,
    CNAME = 5,
    SOA,
    PTR = 12,
    MX,
    TXT,
};

pub const rdata = union(enum) {
    raw: []const u8,
    str: []const u8,
    ipv4: std.net.Ip4Address,
};

pub const resource_record = struct {
    name: []u8 = "",
    type: rr_type = rr_type.A,
    class: u16 = 0,
    ttl: u32 = 0,
    rdlength: u16 = 0,
    rdata: rdata = rdata{ .raw = "" },

    // RR can have message compression, so we will need to pass full input buffer
    // Needs allocator?
    pub fn fromBytes(self: *resource_record, full_msg_bytes: []const u8, input_offset: u32, allocator: std.mem.Allocator) !u32 {
        // Domain name cannot be more than 255 octets
        var name = try allocator.alloc(u8, 256);
        var offset = input_offset;

        const name_out = parse_name(full_msg_bytes, offset, name);
        self.name = name[0..name_out.output_written];

        offset += name_out.offset;

        self.type = @intToEnum(rr_type, slice_to_int(u16, full_msg_bytes[0..], &offset));
        self.class = slice_to_int(u16, full_msg_bytes[0..], &offset);
        self.ttl = slice_to_int(u32, full_msg_bytes[0..], &offset);
        self.rdlength = slice_to_int(u16, full_msg_bytes[0..], &offset);

        self.rdata = rdata{ .raw = full_msg_bytes[offset..(offset + self.rdlength)] };

        switch (self.type) {
            .A => {
                self.rdata = rdata{
                    .ipv4 = std.net.Ip4Address.init(
                        [4]u8{ full_msg_bytes[offset + 0], full_msg_bytes[offset + 1], full_msg_bytes[offset + 2], full_msg_bytes[offset + 3] },
                        0,
                    ),
                };
            },
            .CNAME => {
                var cname = try allocator.allocSentinel(u8, 256, 0);
                var out = parse_name(full_msg_bytes[0..], offset, cname);
                self.rdata = rdata{ .str = cname[0..(out.output_written)] };
            },
            else => {
                self.rdata = rdata{ .raw = full_msg_bytes[offset..(offset + self.rdlength)] };
            },
        }

        offset += self.rdlength;

        // Return only the change in offset, not the absolute offset
        return offset - input_offset;
    }
};

test "rr from bytes" {
    const msg_bytes = [_]u8{ 3, 'a', 'b', 'c', 2, 'd', 'e', 0, 0, 1, 1, 1, 0, 0, 0, 2, 0, 3, 0, 0, 0, 0 };
    var output = [_]u8{0} ** 10;
    _ = output;
    var mem_buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&mem_buffer);
    const allocator = fba.allocator();

    var rr = resource_record{};
    const out = rr.fromBytes(msg_bytes[0..], 0, allocator);

    try std.testing.expectEqual(@as(u32, 21), out catch unreachable);
    try std.testing.expectEqual(rr_type.A, rr.type);
    try std.testing.expectEqual(@as(u16, 257), rr.class);
    try std.testing.expectEqual(@as(u32, 2), rr.ttl);
    try std.testing.expectEqual(@as(u16, 3), rr.rdlength);
}

const parse_name_out = struct { offset: u32, output_written: u32 };

fn parse_name(full_msg_bytes: []const u8, input_offset: u32, output: []u8) parse_name_out {
    var o_id: u32 = 0;
    var offset = input_offset;
    var offset_increase: u32 = 0;
    const compression_flag: u16 = 0b11 << 6;
    var compression_encountered: bool = false;
    var len: u8 = undefined;

    while (true) {
        len = full_msg_bytes[offset];
        offset += 1;
        if (!compression_encountered)
            offset_increase += 1;

        if (len == 0) break;
        if (o_id >= 256) {
            std.debug.print("Domain name cannot be more that 255 chars\n", .{});
            break;
        }

        if ((len & compression_flag) == compression_flag) {
            // Compressed msg offset is two octet, while normal label has one octet length
            var compressed_len: u16 = len;
            compressed_len = (compressed_len << 8) + full_msg_bytes[offset];
            offset += 1;
            offset_increase += 1;

            const msg_offset = compressed_len & (~(compression_flag << 8));
            len = full_msg_bytes[msg_offset];
            offset = msg_offset + 1;
            compression_encountered = true;
        }

        @memcpy(output[o_id..(o_id + len)], full_msg_bytes[offset..(offset + len)]);
        o_id += len;
        offset += len;

        if (!compression_encountered)
            offset_increase += len;

        // Add a . after each label in output
        output[o_id] = '.';
        o_id += 1;
    }

    // Add ending null char, remove last '.' char
    // TODO: Should we keep the ending `.` like `dig` command, or remove as in `nslookup`?
    output[o_id] = 0;
    o_id -= 1;

    return parse_name_out{ .offset = offset_increase, .output_written = o_id };
}

test "parse_name no compression" {
    const msg_bytes = [_]u8{ 3, 'a', 'b', 'c', 2, 'd', 'e', 0 };
    var output = [_]u8{0} ** 10;

    const out = parse_name(msg_bytes[0..], 0, output[0..]);

    try std.testing.expectEqual(@as(u32, 8), out.offset);
    try std.testing.expectEqual(@as(u32, 6), out.output_written);
    try std.testing.expectEqualStrings("abc.de", output[0..(out.output_written)]);
}

test "parse_name compression" {
    const msg_bytes = [_]u8{ 3, 'a', 'b', 'c', 2, 'd', 'e', 0, 0, 1, 3, 'e', 'a', 'a', 0b11000000, 0, 'r', 'a', 'n', 'd' };
    var output = [_]u8{0} ** 20;
    const offset = 10;

    const out = parse_name(msg_bytes[0..], offset, output[0..]);

    try std.testing.expectEqual(@as(u32, 6), out.offset);
    try std.testing.expectEqual(@as(u32, 10), out.output_written);
    try std.testing.expectEqualStrings("eaa.abc.de", output[0..(out.output_written)]);
}

fn slice_to_int(comptime T: type, slice: []const u8, input_offset: *u32) T {
    const it: u8 = @typeInfo(T).Int.bits / 8;
    var value: T = slice[input_offset.*];
    input_offset.* += 1;
    inline for (0..it - 1) |_| {
        value = (value << 8) + slice[input_offset.*];
        input_offset.* += 1;
    }

    return value;
}

// UTILITY Functions

pub fn print_slice(buf: []const u8) void {
    for (0..(buf.len)) |i| {
        std.debug.print("{x:0>2} ", .{buf[i]});
    }
    std.debug.print("\n", .{});
}
