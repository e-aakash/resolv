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

    pub fn fromBytes(buf: []u8, h: *header) void {
        h.id = (@as(u16, buf[0]) << 8) + buf[1];
        h.flags = (@as(u16, buf[2]) << 8) + buf[3];
        h.qdcount = (@as(u16, buf[4]) << 8) + buf[5];
        h.ancount = (@as(u16, buf[6]) << 8) + buf[7];
        h.nscount = (@as(u16, buf[8]) << 8) + buf[9];
        h.arcount = (@as(u16, buf[10]) << 8) + buf[11];
    }

    pub fn toBytes(self: *const header, output: []u8) u32 {
        std.debug.assert(output.len >= 12);
        comptime var i: u32 = 0;
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

    header.fromBytes(bytes[0..], &h);
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
    qname: []u8,
    qtype: u16,
    qclass: u16,

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

test "question to bytes" {
    var b = [_]u8{0} ** 10;
    var name = [_]u8{ 'a', 'b', '.', 'd' };

    const q = question{ .qname = &name, .qtype = 0, .qclass = 259 };

    try std.testing.expectEqual(@as(u32, 10), q.toBytes(b[0..]));

    try std.testing.expectEqual(b, [_]u8{ 2, 'a', 'b', 1, 'd', 0, 0, 0, 1, 3 });
}

pub const message = struct {
    header: header,
    question: question,

    pub fn forDomain(domain: []u8) message {
        const h = header{ .id = 33432, .flags = 1 << 8, .qdcount = 1 };
        const q = question{ .qname = domain, .qtype = 1, .qclass = 1 };

        const m = message{ .header = h, .question = q };
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
        const question_len = self.question.toBytes(buffer[(2 + header_len)..]);

        const msg_len = header_len + question_len;
        buffer[0] = @truncate(u8, msg_len >> 8);
        buffer[1] = @truncate(u8, msg_len & 0b11111111);
        return 2 + msg_len;
    }
};
