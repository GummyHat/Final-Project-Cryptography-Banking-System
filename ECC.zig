const std = @import("std");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

const prime: i257 = 0xfffffffdffffffffffffffffffffffff;
const a: i257 = 0xfffffffdfffffffffffffffffffffffc;
const b: i257 = 0xe87579c11079f43dd824993c2cee5ed3;
var G: Point = Point{
    .isInfinity = false,
    .x = 0x161ff7528b899b2d0c28607ca52c5b86,
    .y = 0xcf5ac8395bafeb13c02da292dded7a83,
};
const n: i257 = 0xfffffffe0000000075a30d1b9038a115;
const K: i257 = 40;
var privateKey: i257 = 0;
var publicKey: CPoint = CPoint{
    .isInfinity = true,
    .x = 0,
    .y = 0,
};
const bounds: u128 = prime / K;
const exponent: i257 = (prime - 1) / 2;
var points: std.ArrayList(CPoint) = std.ArrayList(CPoint).init(allocator);
var randomValues: std.ArrayList(usize) = std.ArrayList(usize).init(allocator);

pub export fn deinit() void {
    points.deinit();
    randomValues.deinit();
    _ = gpa.deinit();
}

pub fn extendedEuclidean(p: *const i257, q: *const i257, value: *i257, inverse: *i257) void {
    const mod: i257 = @mod(q.*, p.*);
    if (mod == 0) {
        value.* = 0;
        inverse.* = 1;
        return;
    }
    extendedEuclidean(&mod, p, value, inverse);
    const divisor: i257 = @divFloor(q.*, p.*);
    const tmp: i257 = inverse.*;
    inverse.* = value.* - inverse.* * divisor;
    value.* = tmp;
}

fn modPow(i: i257, exp: i257) i257 {
    var result: i257 = 1;
    var base: i257 = @mod(i, prime);
    var e = exp;
    while (e > 0) {
        if (e & 1 == 1) {
            result = @mod(result * base, prime);
        }
        e = e >> 1;
        base = @mod(base * base, prime);
    }
    return result;
}

fn checkResidue(i: i257) bool {
    return modPow(i, exponent) == 1;
}

pub export fn setPrivateKey(p: u128) callconv(.C) void {
    privateKey = p;
    var tmp: Point = Point{
        .isInfinity = G.isInfinity,
        .x = G.x,
        .y = G.y,
    };
    tmp.multiplyPoint(p);
    publicKey = CPoint{
        .isInfinity = tmp.isInfinity,
        .x = @intCast(tmp.x),
        .y = @intCast(tmp.y),
    };
}

pub export fn verifyPublicKey(p: *CPoint) callconv(.C) bool {
    if (p.isInfinity == true) {
        return true;
    }
    else {
        const xcoord: i257 = p.x;
        const ycoord: i257 = p.y;
        return @mod(@mod(@mod(xcoord * xcoord, prime) * xcoord, prime) +
                @mod(a * xcoord, prime) + b, prime) == @mod(ycoord * ycoord, prime);
    }
}

pub export fn setPublicKey(p: *CPoint) callconv(.C) void {
    publicKey = CPoint{
        .isInfinity = p.isInfinity,
        .x = p.x,
        .y = p.y,
    };
}

pub export fn getPublicKey() callconv(.C) CPoint {
    return publicKey;
}

pub export fn multPrivate(@"pub": *CPoint) callconv(.C) CPoint {
    var tmp: Point = Point{
        .isInfinity = @"pub".isInfinity,
        .x = @"pub".x,
        .y = @"pub".y,
    };
    tmp.multiplyPoint(privateKey);
    return CPoint{
        .isInfinity = tmp.isInfinity,
        .x = @intCast(tmp.x),
        .y = @intCast(tmp.y),
    };
}

pub export fn convertToMessage(arr: [*]CPoint, arrsize: usize, string: [*:0]u8) callconv(.C) void {
    for (0..arrsize) |i| {
        var num: i257 = @divFloor(@as(i257, arr[i].x), K);
        const mask: u257 = (1 << 8) - 1;
        for (0..4) |j| {
            string[i * 4 + j] = @intCast(num & mask);
            num = num >> 8;
        }
    }
}

pub export fn convertToPoint(arr: [*:0]u8, arrsize: usize, size: *u128) callconv(.C) *CPoint {
    points.clearRetainingCapacity();
    var i: usize = 0;
    while (i < arrsize) : (i += 4) {
        const slice: []u8 = arr[i..@min(i + 4, arrsize)];
        var num: i257 = slice[slice.len - 1];
        {
            var j: isize = @as(isize, @intCast(slice.len)) - 2;
            while (j >= 0) : (j -= 1) {
                num = num << 8;
                num += slice[@intCast(j)];
            }
        }
        //Tonelli Shanks
        const m: i257 = num * K;
        for (0..K) |j| {
            const xcoord: i257 = m + j;
            var ycoord: i257 = @mod(@mod(@mod(xcoord * xcoord, prime) * xcoord, prime) +
                @mod(a * xcoord, prime) + b, prime);
            if (checkResidue(ycoord)) {
                ycoord = modPow(ycoord, (prime + 1) / 4);
                points.append(CPoint{
                    .isInfinity = false,
                    .x = @intCast(@mod(xcoord, prime)),
                    .y = @intCast(@mod(ycoord, prime)),
                }) catch return @ptrCast(points.items);
                break;
            }
        }
    }
    size.* = points.items.len;
    return @ptrCast(points.items);
}

pub export fn setRandomEncryptValues(arr: [*]usize, size: usize) callconv(.C) void {
    randomValues.clearRetainingCapacity();
    for (0..size) |i| {
        randomValues.append(arr[i]) catch return;
    }
}

pub export fn eccEncrypt(arr: [*]CPoint, arrsize: usize, result: [*]CPoint) callconv(.C) void {
    for (0..arrsize) |i| {
        var cur: Point = Point{ .isInfinity = arr[i].isInfinity, .x = arr[i].x, .y = arr[i].y };
        const k: i257 = randomValues.items[i];
        var cx: Point = Point{
            .isInfinity = G.isInfinity,
            .x = G.x,
            .y = G.y,
        };
        cx.multiplyPoint(k);
        var cy: Point = Point{ .isInfinity = publicKey.isInfinity, .x = publicKey.x, .y = publicKey.y };
        cy.multiplyPoint(k);
        cy.addPoint(&cur);
        result[i * 2].x = @intCast(cx.x);
        result[i * 2].y = @intCast(cx.y);
        result[i * 2 + 1].x = @intCast(cy.x);
        result[i * 2 + 1].y = @intCast(cy.y);
    }
}

pub export fn eccDecrypt(arr: [*]CPoint, arrsize: usize, result: [*]CPoint) callconv(.C) void {
    for (0..arrsize) |i| {
        var curx: Point = Point{ .isInfinity = arr[i * 2].isInfinity, .x = arr[i * 2].x, .y = arr[i * 2].y };
        var cury: Point = Point{ .isInfinity = arr[i * 2 + 1].isInfinity, .x = arr[i * 2 + 1].x, .y = arr[i * 2 + 1].y };
        curx.multiplyPoint(privateKey);
        curx.y = @mod(-curx.y, prime);
        cury.addPoint(&curx);
        result[i] = CPoint{
            .isInfinity = cury.isInfinity,
            .x = @intCast(cury.x),
            .y = @intCast(cury.y),
        };
    }
}

pub const CPoint = extern struct {
    isInfinity: bool,
    x: u128,
    y: u128,
};

pub const Point = struct {
    isInfinity: bool,
    x: i257,
    y: i257,
    pub fn equals(self: *Point, other: *const Point) bool {
        if (self.isInfinity and other.isInfinity) {
            return true;
        } else if (self.isInfinity == other.isInfinity) {
            return self.x == other.x and self.y == other.y;
        }
        return false;
    }
    pub fn addPoint(self: *Point, other: *const Point) void {
        if (self.isInfinity) {
            self.x = other.x;
            self.y = other.y;
            self.isInfinity = other.isInfinity;
            return;
        }
        if (other.isInfinity) {
            return;
        }
        if (self.x == other.x and self.y != other.y) {
            self.isInfinity = true;
            return;
        }
        var slope: i257 = undefined;
        if (self.equals(other)) {
            slope = @mod(@mod(3 * @mod(self.x * self.x, prime), prime), prime) + a;
            var val: i257 = 0;
            var inverse: i257 = 0;
            var y = @mod((2 * self.y), prime);
            extendedEuclidean(&y, &prime, &val, &inverse);
            slope = @mod(slope * inverse, prime);
        } else {
            var val: i257 = 0;
            var inverse: i257 = 0;
            var x: i257 = @mod((other.x - self.x), prime);
            extendedEuclidean(&x, &prime, &val, &inverse);
            slope = @mod(((other.y - self.y) * inverse), prime);
        }
        const newX: i257 = @mod(((slope * slope) - self.x - other.x), prime);
        self.y = @mod(((slope * (self.x - newX)) - self.y), prime);
        self.x = newX;
    }
    pub fn multiplyPoint(self: *Point, mult: i257) void {
        var p = mult;
        var current: Point = Point{
            .isInfinity = self.isInfinity,
            .x = self.x,
            .y = self.y,
        };
        self.isInfinity = true;
        while (p > 0) {
            if (p & 1 == 1) {
                self.addPoint(&current);
            }
            current.addPoint(&current);
            p = p >> 1;
        }
    }
};
