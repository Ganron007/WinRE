// Configuration dialog and persistence for x64dbg-MCP Server.
// Uses raw Win32 API to create a modal config dialog.

const std = @import("std");
const bridge = @import("bridge.zig");
const mcp = @import("mcp_server.zig");

// ── Win32 types ────────────────────────────────────────────────────
const HWND = ?*anyopaque;
const HMENU = ?*anyopaque;
const HINSTANCE = ?*anyopaque;
const HFONT = ?*anyopaque;
const HBRUSH = ?*anyopaque;
const HICON = ?*anyopaque;
const HCURSOR = ?*anyopaque;
const HDC = ?*anyopaque;
const HANDLE = ?*anyopaque;
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;
const BOOL = i32;
const RECT = extern struct { left: i32, top: i32, right: i32, bottom: i32 };

const WNDCLASSEXA = extern struct {
    cbSize: u32 = @sizeOf(WNDCLASSEXA),
    style: u32 = 0,
    lpfnWndProc: *const fn (HWND, u32, WPARAM, LPARAM) callconv(.winapi) LRESULT,
    cbClsExtra: c_int = 0,
    cbWndExtra: c_int = 0,
    hInstance: HINSTANCE = null,
    hIcon: HICON = null,
    hCursor: HCURSOR = null,
    hbrBackground: HBRUSH = null,
    lpszMenuName: ?[*:0]const u8 = null,
    lpszClassName: [*:0]const u8,
    hIconSm: HICON = null,
};

// ── Win32 imports ──────────────────────────────────────────────────
extern "user32" fn RegisterClassExA(lpWndClass: *const WNDCLASSEXA) callconv(.winapi) u16;
extern "user32" fn CreateWindowExA(dwExStyle: u32, lpClassName: [*:0]const u8, lpWindowName: ?[*:0]const u8, dwStyle: u32, x: c_int, y: c_int, nWidth: c_int, nHeight: c_int, hWndParent: HWND, hMenu: HMENU, hInstance: HINSTANCE, lpParam: ?*anyopaque) callconv(.winapi) HWND;
extern "user32" fn DestroyWindow(hWnd: HWND) callconv(.winapi) BOOL;
extern "user32" fn ShowWindow(hWnd: HWND, nCmdShow: c_int) callconv(.winapi) BOOL;
extern "user32" fn UpdateWindow(hWnd: HWND) callconv(.winapi) BOOL;
extern "user32" fn GetMessageA(lpMsg: *MSG, hWnd: HWND, wMsgFilterMin: u32, wMsgFilterMax: u32) callconv(.winapi) BOOL;
extern "user32" fn TranslateMessage(lpMsg: *const MSG) callconv(.winapi) BOOL;
extern "user32" fn DispatchMessageA(lpMsg: *const MSG) callconv(.winapi) LRESULT;
extern "user32" fn PostQuitMessage(nExitCode: c_int) callconv(.winapi) void;
extern "user32" fn SendMessageA(hWnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT;
extern "user32" fn GetWindowTextA(hWnd: HWND, lpString: [*]u8, nMaxCount: c_int) callconv(.winapi) c_int;
extern "user32" fn SetFocus(hWnd: HWND) callconv(.winapi) HWND;
extern "user32" fn SetForegroundWindow(hWnd: HWND) callconv(.winapi) BOOL;
extern "user32" fn EnableWindow(hWnd: HWND, bEnable: BOOL) callconv(.winapi) BOOL;
extern "user32" fn IsDialogMessageA(hDlg: HWND, lpMsg: *MSG) callconv(.winapi) BOOL;
extern "user32" fn GetSystemMetrics(nIndex: c_int) callconv(.winapi) c_int;
extern "user32" fn SetWindowPos(hWnd: HWND, hWndInsertAfter: HWND, x: c_int, y: c_int, cx: c_int, cy: c_int, uFlags: u32) callconv(.winapi) BOOL;
extern "user32" fn MessageBoxA(hWnd: HWND, lpText: [*:0]const u8, lpCaption: [*:0]const u8, uType: u32) callconv(.winapi) c_int;
extern "gdi32" fn CreateFontA(cHeight: c_int, cWidth: c_int, cEscapement: c_int, cOrientation: c_int, cWeight: c_int, bItalic: u32, bUnderline: u32, bStrikeOut: u32, iCharSet: u32, iOutPrecision: u32, iClipPrecision: u32, iQuality: u32, iPitchAndFamily: u32, pszFaceName: [*:0]const u8) callconv(.winapi) HFONT;
extern "gdi32" fn DeleteObject(ho: ?*anyopaque) callconv(.winapi) BOOL;
extern "user32" fn DefWindowProcA(hWnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT;

extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.winapi) HINSTANCE;
extern "kernel32" fn CreateFileA(name: [*:0]const u8, access: u32, share: u32, sa: ?*anyopaque, disp: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) HANDLE;
extern "kernel32" fn ReadFile(h: ?*anyopaque, buf: [*]u8, len: u32, read: *u32, ov: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn WriteFile(h: ?*anyopaque, buf: [*]const u8, len: u32, written: *u32, ov: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn CloseHandle(h: ?*anyopaque) callconv(.winapi) BOOL;
extern "kernel32" fn GetModuleFileNameA(hModule: HINSTANCE, lpFilename: [*]u8, nSize: u32) callconv(.winapi) u32;
extern "kernel32" fn CreateThread(sa: ?*anyopaque, stackSize: usize, startAddr: *const fn (?*anyopaque) callconv(.winapi) u32, param: ?*anyopaque, flags: u32, id: ?*u32) callconv(.winapi) HANDLE;

const MSG = extern struct {
    hwnd: HWND,
    message: u32,
    wParam: WPARAM,
    lParam: LPARAM,
    time: u32,
    pt_x: i32,
    pt_y: i32,
};

// ── Win32 constants ────────────────────────────────────────────────
const WS_OVERLAPPED: u32 = 0x00000000;
const WS_CAPTION: u32 = 0x00C00000;
const WS_SYSMENU: u32 = 0x00080000;
const WS_CHILD: u32 = 0x40000000;
const WS_VISIBLE: u32 = 0x10000000;
const WS_TABSTOP: u32 = 0x00010000;
const WS_GROUP: u32 = 0x00020000;
const WS_BORDER: u32 = 0x00800000;
const WS_EX_DLGMODALFRAME: u32 = 0x00000001;
const WS_EX_CLIENTEDGE: u32 = 0x00000200;
const ES_AUTOHSCROLL: u32 = 0x0080;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const BS_AUTOCHECKBOX: u32 = 0x0003;
const BM_SETCHECK: u32 = 0x00F1;
const BM_GETCHECK: u32 = 0x00F0;
const BST_CHECKED: u32 = 1;
const WM_CREATE: u32 = 0x0001;
const WM_DESTROY: u32 = 0x0002;
const WM_CLOSE: u32 = 0x0010;
const WM_COMMAND: u32 = 0x0111;
const WM_SETFONT: u32 = 0x0030;
const WM_SETTEXT: u32 = 0x000C;
const SM_CXSCREEN: c_int = 0;
const SM_CYSCREEN: c_int = 1;
const SWP_NOZORDER: u32 = 0x0004;
const SWP_NOSIZE: u32 = 0x0001;
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_SHARE_READ: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE: HANDLE = @ptrFromInt(@as(usize, @truncate(@as(u128, 0xFFFFFFFFFFFFFFFF))));
const IDC_IP: c_int = 101;
const IDC_PORT: c_int = 102;
const IDC_URL: c_int = 103;
const IDC_AUTOSTART: c_int = 104;
const IDC_SAVE: c_int = 1;
const IDC_CANCEL: c_int = 2;
const BN_CLICKED: u32 = 0;

// ── Config data ────────────────────────────────────────────────────
pub const Config = struct {
    ip: [64]u8 = undefined,
    ip_len: usize = 0,
    port: u16 = 0,
    auto_start: bool = true,

    pub fn ipSlice(self: *const Config) []const u8 {
        return self.ip[0..self.ip_len];
    }
};

var config_path: [512]u8 = undefined;
var config_path_len: usize = 0;

fn getConfigPath() [*:0]const u8 {
    if (config_path_len > 0) return @ptrCast(&config_path);

    var module_path: [512]u8 = undefined;
    const len = GetModuleFileNameA(null, &module_path, 512);
    if (len == 0) {
        const fallback = "mcp_config.json";
        @memcpy(config_path[0..fallback.len], fallback);
        config_path[fallback.len] = 0;
        config_path_len = fallback.len;
        return @ptrCast(&config_path);
    }

    // Find last backslash
    var last_sep: usize = 0;
    for (0..len) |i| {
        if (module_path[i] == '\\') last_sep = i;
    }

    const filename = "mcp_config.json";
    @memcpy(config_path[0 .. last_sep + 1], module_path[0 .. last_sep + 1]);
    @memcpy(config_path[last_sep + 1 .. last_sep + 1 + filename.len], filename);
    config_path[last_sep + 1 + filename.len] = 0;
    config_path_len = last_sep + 1 + filename.len;
    return @ptrCast(&config_path);
}

pub fn load() Config {
    const default_port: u16 = if (@sizeOf(usize) == 8) 9094 else 9095;
    var cfg = Config{ .port = default_port };
    const default_ip = "0.0.0.0";
    @memcpy(cfg.ip[0..default_ip.len], default_ip);
    cfg.ip_len = default_ip.len;

    const path = getConfigPath();
    const h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (h == INVALID_HANDLE or h == null) return cfg;
    defer _ = CloseHandle(h);

    var buf: [512]u8 = undefined;
    var bytes_read: u32 = 0;
    if (ReadFile(h, &buf, 512, &bytes_read, null) == 0) return cfg;

    const json_data = buf[0..bytes_read];

    // Parse "IpAddress":"<value>"
    if (findJsonString(json_data, "IpAddress")) |ip_val| {
        if (ip_val.len > 0 and ip_val.len < 64) {
            @memcpy(cfg.ip[0..ip_val.len], ip_val);
            cfg.ip_len = ip_val.len;
        }
    }

    // Parse "Port":<number>
    if (findJsonNumber(json_data, "Port")) |port_val| {
        cfg.port = port_val;
    }

    // Parse "AutoStart":true/false
    if (findJsonBool(json_data, "AutoStart")) |val| {
        cfg.auto_start = val;
    }

    return cfg;
}

fn findJsonString(data: []const u8, key: []const u8) ?[]const u8 {
    // Search for "key":"value"
    var i: usize = 0;
    while (i + key.len + 4 < data.len) : (i += 1) {
        if (data[i] == '"' and i + 1 + key.len < data.len and
            std.mem.eql(u8, data[i + 1 .. i + 1 + key.len], key) and
            data[i + 1 + key.len] == '"')
        {
            var j = i + 2 + key.len;
            while (j < data.len and (data[j] == ':' or data[j] == ' ')) j += 1;
            if (j < data.len and data[j] == '"') {
                j += 1;
                const val_start = j;
                while (j < data.len and data[j] != '"') j += 1;
                return data[val_start..j];
            }
        }
    }
    return null;
}

fn findJsonNumber(data: []const u8, key: []const u8) ?u16 {
    // Search for "key":<number>
    var i: usize = 0;
    while (i + key.len + 3 < data.len) : (i += 1) {
        if (data[i] == '"' and i + 1 + key.len < data.len and
            std.mem.eql(u8, data[i + 1 .. i + 1 + key.len], key) and
            data[i + 1 + key.len] == '"')
        {
            var j = i + 2 + key.len;
            while (j < data.len and (data[j] == ':' or data[j] == ' ')) j += 1;
            const num_start = j;
            while (j < data.len and data[j] >= '0' and data[j] <= '9') j += 1;
            if (j > num_start) {
                return parsePort(data[num_start..j]);
            }
        }
    }
    return null;
}

fn findJsonBool(data: []const u8, key: []const u8) ?bool {
    var i: usize = 0;
    while (i + key.len + 3 < data.len) : (i += 1) {
        if (data[i] == '"' and i + 1 + key.len < data.len and
            std.mem.eql(u8, data[i + 1 .. i + 1 + key.len], key) and
            data[i + 1 + key.len] == '"')
        {
            var j = i + 2 + key.len;
            while (j < data.len and (data[j] == ':' or data[j] == ' ')) j += 1;
            if (j + 4 <= data.len and std.mem.eql(u8, data[j .. j + 4], "true")) return true;
            if (j + 5 <= data.len and std.mem.eql(u8, data[j .. j + 5], "false")) return false;
        }
    }
    return null;
}

fn parsePort(s: []const u8) ?u16 {
    var val: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        val = val * 10 + (c - '0');
        if (val > 65535) return null;
    }
    if (val == 0) return null;
    return @intCast(val);
}

pub fn save(cfg: *const Config) void {
    const path = getConfigPath();
    const h = CreateFileA(path, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
    if (h == INVALID_HANDLE or h == null) return;
    defer _ = CloseHandle(h);

    var buf: [192]u8 = undefined;
    const prefix = "{\"IpAddress\":\"";
    @memcpy(buf[0..prefix.len], prefix);
    var pos: usize = prefix.len;
    @memcpy(buf[pos .. pos + cfg.ip_len], cfg.ip[0..cfg.ip_len]);
    pos += cfg.ip_len;
    const mid = "\",\"Port\":";
    @memcpy(buf[pos .. pos + mid.len], mid);
    pos += mid.len;
    var port_buf: [6]u8 = undefined;
    const port_len = fmtU16(cfg.port, &port_buf);
    @memcpy(buf[pos .. pos + port_len], port_buf[0..port_len]);
    pos += port_len;
    const auto_str = if (cfg.auto_start) ",\"AutoStart\":true}" else ",\"AutoStart\":false}";
    @memcpy(buf[pos .. pos + auto_str.len], auto_str);
    pos += auto_str.len;

    var written: u32 = 0;
    _ = WriteFile(h, &buf, @intCast(pos), &written, null);
}

fn fmtU16(val: u16, buf: *[6]u8) usize {
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    var v = val;
    var i: usize = 0;
    while (v > 0) : (i += 1) {
        buf[5 - i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    // Shift to start
    var j: usize = 0;
    while (j < i) : (j += 1) {
        buf[j] = buf[6 - i + j];
    }
    return i;
}

// ── Dialog ─────────────────────────────────────────────────────────

var dlg_hwnd: HWND = null;
var edit_ip: HWND = null;
var edit_port: HWND = null;
var lbl_url: HWND = null;
var chk_autostart: HWND = null;
var ui_font: HFONT = null;
var ui_font_bold: HFONT = null;
var ui_font_small: HFONT = null;
var class_registered: bool = false;
var parent_hwnd: HWND = null;

const DLG_W = 450;
const DLG_H = 300;
const CLASS_NAME = "MCPServerConfig\x00";

pub fn showDialog(parentHwnd: usize) void {
    parent_hwnd = @ptrFromInt(parentHwnd);
    _ = CreateThread(null, 0, dialogThread, null, 0, null);
}

fn dialogThread(_: ?*anyopaque) callconv(.winapi) u32 {
    const hInst = GetModuleHandleA(null);

    if (!class_registered) {
        const wc = WNDCLASSEXA{
            .lpfnWndProc = wndProc,
            .hInstance = hInst,
            .hbrBackground = @ptrFromInt(@as(usize, @intCast(1 + @as(c_int, 15)))),
            .lpszClassName = CLASS_NAME,
            .hCursor = null,
        };
        _ = RegisterClassExA(&wc);
        class_registered = true;
    }

    ui_font = CreateFontA(-14, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI\x00");
    ui_font_bold = CreateFontA(-14, 0, 0, 0, 700, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI\x00");
    ui_font_small = CreateFontA(-12, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 5, 0, "Segoe UI\x00");

    dlg_hwnd = CreateWindowExA(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        "MCP Server Configuration\x00",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        100,
        100,
        DLG_W,
        DLG_H,
        parent_hwnd,
        null,
        hInst,
        null,
    );

    if (dlg_hwnd == null) return 1;

    // Disable parent
    if (parent_hwnd != null) _ = EnableWindow(parent_hwnd, 0);

    // Center on screen
    const sw = GetSystemMetrics(SM_CXSCREEN);
    const sh = GetSystemMetrics(SM_CYSCREEN);
    _ = SetWindowPos(dlg_hwnd, null, @divTrunc(sw - DLG_W, 2), @divTrunc(sh - DLG_H, 2), 0, 0, SWP_NOZORDER | SWP_NOSIZE);

    _ = ShowWindow(dlg_hwnd, 5);
    _ = UpdateWindow(dlg_hwnd);

    var msg: MSG = undefined;
    while (GetMessageA(&msg, null, 0, 0) > 0) {
        if (IsDialogMessageA(dlg_hwnd, &msg) == 0) {
            _ = TranslateMessage(&msg);
            _ = DispatchMessageA(&msg);
        }
    }

    if (ui_font != null) { _ = DeleteObject(ui_font); ui_font = null; }
    if (ui_font_bold != null) { _ = DeleteObject(ui_font_bold); ui_font_bold = null; }
    if (ui_font_small != null) { _ = DeleteObject(ui_font_small); ui_font_small = null; }

    return 0;
}

fn createCtrl(class: [*:0]const u8, text: ?[*:0]const u8, style: u32, x: c_int, y: c_int, w: c_int, h: c_int, id: c_int) HWND {
    const hInst = GetModuleHandleA(null);
    const hwnd = CreateWindowExA(
        if (std.mem.eql(u8, std.mem.span(class), "EDIT")) WS_EX_CLIENTEDGE else 0,
        class,
        text,
        WS_CHILD | WS_VISIBLE | style,
        x,
        y,
        w,
        h,
        dlg_hwnd,
        @ptrFromInt(@as(usize, @intCast(id))),
        hInst,
        null,
    );
    if (hwnd != null and ui_font != null) {
        _ = SendMessageA(hwnd, WM_SETFONT, @intFromPtr(ui_font.?), 1);
    }
    return hwnd;
}

fn wndProc(hwnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT {
    switch (msg) {
        WM_CREATE => {
            dlg_hwnd = hwnd;
            const cfg = load();

            // Row 1: IP Address
            _ = createCtrl("STATIC\x00", "IP Address:\x00", 0, 20, 24, 85, 20, 0);
            edit_ip = createCtrl("EDIT\x00", null, WS_TABSTOP | ES_AUTOHSCROLL, 112, 20, 190, 24, IDC_IP);
            const ip_hint = createCtrl("STATIC\x00", "(0.0.0.0, 127.0.0.1, etc.)\x00", 0, 310, 24, 120, 20, 0);
            if (ip_hint != null and ui_font_small != null)
                _ = SendMessageA(ip_hint, WM_SETFONT, @intFromPtr(ui_font_small.?), 1);

            // Row 2: Port
            _ = createCtrl("STATIC\x00", "Port:\x00", 0, 20, 60, 85, 20, 0);
            edit_port = createCtrl("EDIT\x00", null, WS_TABSTOP | ES_AUTOHSCROLL, 112, 56, 100, 24, IDC_PORT);
            const port_hint = createCtrl("STATIC\x00", "(1 - 65535)\x00", 0, 220, 60, 80, 20, 0);
            if (port_hint != null and ui_font_small != null)
                _ = SendMessageA(port_hint, WM_SETFONT, @intFromPtr(ui_font_small.?), 1);

            // Row 3: Auto Start checkbox
            chk_autostart = createCtrl("BUTTON\x00", "Auto start server on plugin load\x00", WS_TABSTOP | BS_AUTOCHECKBOX, 20, 96, 250, 20, IDC_AUTOSTART);
            if (chk_autostart != null and cfg.auto_start)
                _ = SendMessageA(chk_autostart, BM_SETCHECK, BST_CHECKED, 0);

            // Row 4: URL preview
            _ = createCtrl("STATIC\x00", "Server URL:\x00", 0, 20, 130, 85, 20, 0);
            lbl_url = createCtrl("STATIC\x00", null, 0, 112, 130, 310, 20, IDC_URL);
            if (lbl_url != null and ui_font_bold != null)
                _ = SendMessageA(lbl_url, WM_SETFONT, @intFromPtr(ui_font_bold.?), 1);

            // Help notes
            const notes = createCtrl("STATIC\x00",
                "Use 0.0.0.0 to listen on all interfaces (for WSL/remote access).\r\nUse 127.0.0.1 for local-only access.\r\nSave will automatically restart the MCP server.\x00",
                0, 20, 158, 400, 52, 0);
            if (notes != null and ui_font_small != null)
                _ = SendMessageA(notes, WM_SETFONT, @intFromPtr(ui_font_small.?), 1);

            // Buttons
            _ = createCtrl("BUTTON\x00", "Save\x00", WS_TABSTOP | BS_DEFPUSHBUTTON, 240, 215, 90, 30, IDC_SAVE);
            _ = createCtrl("BUTTON\x00", "Cancel\x00", WS_TABSTOP, 340, 215, 90, 30, IDC_CANCEL);

            // Set initial values
            if (edit_ip != null) {
                var ip_z: [65]u8 = undefined;
                @memcpy(ip_z[0..cfg.ip_len], cfg.ip[0..cfg.ip_len]);
                ip_z[cfg.ip_len] = 0;
                _ = SendMessageA(edit_ip, WM_SETTEXT, 0, @bitCast(@intFromPtr(&ip_z)));
            }
            if (edit_port != null) {
                var port_buf: [6]u8 = undefined;
                const port_len = fmtU16(cfg.port, &port_buf);
                port_buf[port_len] = 0;
                _ = SendMessageA(edit_port, WM_SETTEXT, 0, @bitCast(@intFromPtr(&port_buf)));
            }
            updateUrlPreview();

            if (edit_ip != null) _ = SetFocus(edit_ip);
            return 0;
        },
        WM_COMMAND => {
            const id: c_int = @intCast(wParam & 0xFFFF);
            const notify: u32 = @intCast((wParam >> 16) & 0xFFFF);

            if (id == IDC_SAVE and notify == BN_CLICKED) {
                onSave(hwnd);
                return 0;
            }
            if (id == IDC_CANCEL and notify == BN_CLICKED) {
                restoreParent();
                _ = DestroyWindow(hwnd);
                return 0;
            }
            // Update URL preview on text change (EN_CHANGE = 0x0300)
            if (notify == 0x0300 and (id == IDC_IP or id == IDC_PORT)) {
                updateUrlPreview();
            }
            return 0;
        },
        WM_CLOSE => {
            restoreParent();
            _ = DestroyWindow(hwnd);
            return 0;
        },
        WM_DESTROY => {
            dlg_hwnd = null;
            PostQuitMessage(0);
            return 0;
        },
        else => return DefWindowProcA(hwnd, msg, wParam, lParam),
    }
}

fn restoreParent() void {
    if (parent_hwnd != null) {
        _ = EnableWindow(parent_hwnd, 1);
        _ = SetForegroundWindow(parent_hwnd);
    }
}

fn updateUrlPreview() void {
    if (lbl_url == null or edit_ip == null or edit_port == null) return;

    var ip_buf: [64]u8 = undefined;
    const ip_len: usize = @intCast(GetWindowTextA(edit_ip, &ip_buf, 64));

    var port_buf: [8]u8 = undefined;
    const port_len: usize = @intCast(GetWindowTextA(edit_port, &port_buf, 8));

    var url: [128]u8 = undefined;
    const prefix = "http://";
    @memcpy(url[0..prefix.len], prefix);
    var pos: usize = prefix.len;

    if (ip_len == 0) {
        @memcpy(url[pos .. pos + 7], "0.0.0.0");
        pos += 7;
    } else {
        @memcpy(url[pos .. pos + ip_len], ip_buf[0..ip_len]);
        pos += ip_len;
    }

    url[pos] = ':';
    pos += 1;

    if (port_len == 0) {
        url[pos] = '0';
        pos += 1;
    } else {
        @memcpy(url[pos .. pos + port_len], port_buf[0..port_len]);
        pos += port_len;
    }

    url[pos] = '/';
    pos += 1;
    url[pos] = 0;

    _ = SendMessageA(lbl_url, WM_SETTEXT, 0, @bitCast(@intFromPtr(&url)));
}

fn onSave(hwnd: HWND) void {
    var ip_buf: [64]u8 = undefined;
    const ip_len: usize = @intCast(GetWindowTextA(edit_ip, &ip_buf, 64));

    if (ip_len == 0) {
        _ = MessageBoxA(hwnd, "IP address cannot be empty.\x00", "Validation Error\x00", 0x30);
        return;
    }

    var port_buf: [8]u8 = undefined;
    const port_len: usize = @intCast(GetWindowTextA(edit_port, &port_buf, 8));
    const port = parsePort(port_buf[0..port_len]) orelse {
        _ = MessageBoxA(hwnd, "Port must be a number between 1 and 65535.\x00", "Validation Error\x00", 0x30);
        return;
    };

    const auto_start = if (chk_autostart != null)
        SendMessageA(chk_autostart, BM_GETCHECK, 0, 0) == BST_CHECKED
    else
        true;

    var cfg = Config{ .port = port, .auto_start = auto_start };
    @memcpy(cfg.ip[0..ip_len], ip_buf[0..ip_len]);
    cfg.ip_len = ip_len;
    save(&cfg);

    mcp.stop();
    mcp.setConfig(cfg.ip[0..cfg.ip_len], cfg.port);
    if (cfg.auto_start) mcp.start();

    bridge.logPuts("[x64dbg-MCP Server] Configuration saved.\x00");
    restoreParent();
    _ = DestroyWindow(hwnd);
}
