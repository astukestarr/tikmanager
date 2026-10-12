"""What kind of MikroTik a device is - access point, switch or router - for the Devices sections of the sidebar.

Worked out from the model code and board name (RouterOS /system routerboard and /system resource); a technician can
override it per device (router page > Settings > Tags & notes). Anything not recognised as a switch or an access point
counts as a router - hAP / Chateau style all-in-ones included, since they route.
"""
import re

KINDS = ("router", "switch", "ap")
SWITCH = re.compile(r"^(CRS|CSS|NETPOWER|NETFIBER|FIBERBOX|RB260|RB250)")
AP = re.compile(r"^(RBCAP|CAP|RBWAP|WAP|RBSXT|SXT|RBLHG|LHG|RBLDF|LDF|RBDISC|DISC|RBD22|RBD23|RBD25|MANTBOX|NETMETAL|BASEBOX|RB91[12]|RB92[12]|"
                r"RBMETAL|METAL|RBGROOVE|GROOVE|CUBE|RBWAPG|AUDIENCE|RBMAP|MAP|QRT|RBQRT|NETBOX|RBNETBOX)")


def kind(model, board, override=None) -> str:
    if override in KINDS:
        return override
    for s in (model, board):
        s = re.sub(r"[^A-Z0-9]", "", str(s or "").upper())
        if not s:
            continue
        if SWITCH.match(s):
            return "switch"
        if AP.match(s):
            return "ap"
    return "router"
