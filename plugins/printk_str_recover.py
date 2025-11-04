# coding: utf-8

"""
Changes:
- 2025-11-04: Initial version
"""

import idaapi
import idautils
import idc

PLUGIN_NAME = "PrintkStrRecover"
PLUGIN_HELP = "Identify printk strings in .rodata (0x01+'0'..'7' prefix) and convert to string with comment"


def is_printable_ascii(byte_value):
    return 0x20 <= byte_value <= 0x7E


def looks_like_printk_prefixed(ea):
    b0 = idc.get_wide_byte(ea)
    b1 = idc.get_wide_byte(ea + 1)
    if b0 != 0x01:
        return False
    if b1 < ord("0") or b1 > ord("7"):
        return False
    b2 = idc.get_wide_byte(ea + 2)
    return b2 in (0x09, 0x0A ,0x0D, 0x20) or is_printable_ascii(b2)


def read_c_string(ea, maxlen=0x10000):
    bytes_list = []
    cur = ea
    for _ in range(maxlen):
        b = idc.get_wide_byte(cur)
        if b == 0xFF:
            break
        if b == 0:
            break
        bytes_list.append(b)
        cur += 1
    return bytes(bytes_list), cur


def to_ascii_safe(bs):
    try:
        return bs.decode("ascii", errors="replace")
    except Exception:
        # Use Python-compatible Unicode escape form, e.g., "\\u00xx"
        return "".join(chr(b) if 32 <= b <= 126 else ("\\u%04x" % b) for b in bs)


def strip_printk_prefix(s):
    if len(s) >= 2 and s[0] == "\x01" and s[1] in "01234567":
        return s[2:]
    return s


def make_strlit(ea, size):
    # Define data item as NUL-terminated string
    idc.del_items(ea, 0, size)
    idaapi.create_strlit(ea, size, idaapi.STRTYPE_C)


def iter_rodata_segments():
    for seg_ea in idautils.Segments():
        s = idaapi.getseg(seg_ea)
        if not s:
            continue
        name = idaapi.get_segm_name(s)
        if not name:
            continue
        if (
            name.startswith(".rodata")
            or name.startswith("__const")
            or name.lower().startswith(".rdata")
        ):
            yield s


def recover_printk_strings_in_segment(seg):
    ea = seg.start_ea
    end_ea = seg.end_ea
    recovered = 0
    while ea < end_ea:
        if looks_like_printk_prefixed(ea):
            raw_bs, last = read_c_string(ea)
            if raw_bs:
                s_full = to_ascii_safe(raw_bs)
                s_clean = strip_printk_prefix(s_full)
                # +1 includes the trailing NUL
                make_strlit(ea, len(raw_bs) + 1)
                # Add repeatable comment showing content after prefix removal
                idaapi.set_cmt(ea, s_clean, True)
                recovered += 1
                ea = last + 1
                continue
        ea += 1
    return recovered


class PrintkStrRecoverAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        total = 0
        for seg in iter_rodata_segments():
            total += recover_printk_strings_in_segment(seg)
        idaapi.info(
            "[{}] Done, identified and converted {} printk strings".format(
                PLUGIN_NAME, total
            )
        )
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


ACTION_NAME = "printk_str_recover:run"
ACTION_LABEL = "Recover printk strings (.rodata)"


def register_action():
    desc = idaapi.action_desc_t(
        ACTION_NAME,
        ACTION_LABEL,
        PrintkStrRecoverAction(),
        "",
        PLUGIN_HELP,
        0,
    )
    try:
        idaapi.register_action(desc)
    except Exception:
        pass
    idaapi.attach_action_to_menu("Edit/", ACTION_NAME, idaapi.SETMENU_APP)


class plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = PLUGIN_HELP
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        register_action()
        return idaapi.PLUGIN_OK

    def run(self, arg):
        act = PrintkStrRecoverAction()
        act.activate(None)

    def term(self):
        try:
            idaapi.detach_action_from_menu("Edit/", ACTION_NAME)
            idaapi.unregister_action(ACTION_NAME)
        except Exception:
            pass


def PLUGIN_ENTRY():
    return plugin_t()
