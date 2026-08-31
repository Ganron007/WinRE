// Minimal JSON writer and parser for MCP protocol.
// No allocations for writing (writes to a fixed buffer).
// Parsing uses std.json.

const std = @import("std");

pub const JsonWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) JsonWriter {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn raw(self: *JsonWriter, s: []const u8) void {
        if (self.pos + s.len > self.buf.len) return;
        @memcpy(self.buf[self.pos..][0..s.len], s);
        self.pos += s.len;
    }

    pub fn beginObject(self: *JsonWriter) void {
        self.raw("{");
    }
    pub fn endObject(self: *JsonWriter) void {
        // overwrite trailing comma if present
        if (self.pos > 0 and self.buf[self.pos - 1] == ',') self.pos -= 1;
        self.raw("}");
    }

    pub fn beginArray(self: *JsonWriter) void {
        self.raw("[");
    }
    pub fn endArray(self: *JsonWriter) void {
        if (self.pos > 0 and self.buf[self.pos - 1] == ',') self.pos -= 1;
        self.raw("]");
    }

    pub fn key(self: *JsonWriter, name: []const u8) void {
        self.writeString(name);
        self.raw(":");
    }

    pub fn fieldStr(self: *JsonWriter, name: []const u8, value: []const u8) void {
        self.key(name);
        self.writeString(value);
        self.raw(",");
    }

    pub fn fieldInt(self: *JsonWriter, name: []const u8, value: anytype) void {
        self.key(name);
        self.writeInt(value);
        self.raw(",");
    }

    pub fn fieldBool(self: *JsonWriter, name: []const u8, value: bool) void {
        self.key(name);
        self.raw(if (value) "true" else "false");
        self.raw(",");
    }

    pub fn fieldNull(self: *JsonWriter, name: []const u8) void {
        self.key(name);
        self.raw("null,");
    }

    pub fn fieldRaw(self: *JsonWriter, name: []const u8, value: []const u8) void {
        self.key(name);
        self.raw(value);
        self.raw(",");
    }

    pub fn writeString(self: *JsonWriter, s: []const u8) void {
        self.raw("\"");
        for (s) |c| {
            switch (c) {
                '"' => self.raw("\\\""),
                '\\' => self.raw("\\\\"),
                '\n' => self.raw("\\n"),
                '\r' => self.raw("\\r"),
                '\t' => self.raw("\\t"),
                else => {
                    if (self.pos < self.buf.len) {
                        self.buf[self.pos] = c;
                        self.pos += 1;
                    }
                },
            }
        }
        self.raw("\"");
    }

    pub fn writeInt(self: *JsonWriter, value: anytype) void {
        var tmp: [24]u8 = undefined;
        const T = @TypeOf(value);
        const s = switch (@typeInfo(T)) {
            .int => std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return,
            .comptime_int => std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return,
            else => std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return,
        };
        self.raw(s);
    }

    pub fn writeHex(self: *JsonWriter, value: usize) void {
        self.raw("\"0x");
        var tmp: [20]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, "{X}", .{value}) catch return;
        self.raw(s);
        self.raw("\"");
    }

    pub fn slice(self: *const JsonWriter) []const u8 {
        return self.buf[0..self.pos];
    }
};

// ── Minimal JSON value lookup (for parsing incoming requests) ───────

pub fn getStringField(parsed: std.json.Value, field: []const u8) ?[]const u8 {
    if (parsed != .object) return null;
    const obj = parsed.object;
    const val = obj.get(field) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

pub fn getIntField(parsed: std.json.Value, field: []const u8) ?i64 {
    if (parsed != .object) return null;
    const obj = parsed.object;
    const val = obj.get(field) orelse return null;
    return switch (val) {
        .integer => |i| i,
        else => null,
    };
}

pub fn getObjectField(parsed: std.json.Value, field: []const u8) ?std.json.Value {
    if (parsed != .object) return null;
    const obj = parsed.object;
    return obj.get(field);
}
