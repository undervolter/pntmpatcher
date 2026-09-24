import os
"""
phantom_patchkit.py - unified crack + brand patcher for phantom2.exe.

Stages (single in-memory pass, one write at the end):
  crack : 8 patches - RET on neckHurt9 (wiper), NOPs on NeckHurtE/F/C/D/A
          + license call, JNE->JMP on the valid branch (from patch_phantom.py)
  brand : redirect the red log prefix "\x1b[91m[%s] Phantom\x1b[0m\n" to a
          longer credit line stored in .rdata slack (from brand_phantom.py)
  osd   : in-place rebrand of the 4 hardcoded OSD overlay texts
          (SetPhantomOverlayCGI, 22 bytes each - no LEA/len changes needed)

Usage:
  python phantom_patchkit.py [--src PATH] [--dst PATH]
                             [--no-crack] [--no-brand] [--no-osd] [--dry-run]
                             [--decrypt] [--decrypt-and-patch]

Defaults: src=phantom2.exe (Telegram Desktop), dst=phantom2_branded.exe.
Idempotent: already-applied patches are detected and skipped.
"""
import argparse
import hashlib
import struct
import sys
import time

from rich.console import Console, Group
from rich.align import Align
from rich.text import Text
from rich.live import Live

console = Console()

T = {
    # ---- interactive menu ----
    "menu.title": "Phantom v3 patcher",
    "menu.what": "           what you wanna do?",
    "menu.item_decrypt": "decrypt phantom bin",
    "menu.item_patch": "patch phantom",
    "menu.item_decrypt_patch": "decrypt + patch",
    "menu.item_exit": "exit",

    # ---- CLI flags ----
    "cli.desc": "phantom2.exe crack + brand + osd + decrypt toolkit",
    "cli.src": "Path to source exe (if omitted, opens file picker)",
    "cli.dst": "Path to output exe",
    "cli.decrypt": "Run decrypt directly",
    "cli.patch": "Run patch directly",
    "cli.decrypt_patch": "Decrypt and patch in one pass",
    "cli.no_crack": "Skip crack stage",
    "cli.no_brand": "Skip brand stage",
    "cli.no_osd": "Skip osd stage",

    # ---- generic byte patch ----
    "bytes.fail_section": "  [red][FAIL][/red] {desc}: VA {va:#x} not in any section",
    "bytes.skip_applied": "  [yellow][SKIP][/yellow] {desc}: already applied",
    "bytes.fail_mismatch": "  [red][FAIL][/red] {desc}: expected {exp} at offset {off:#x}, got {got}",
    "bytes.ok": "  [green][OK][/green]   {desc}: {exp} -> {rep} @ VA {va:#x}",

    # ---- crack stage ----
    "crack.header": "\n[bold]--- stage: crack ---[/bold]",
    "crack.d_wiper": "RET at ghost/core.neckHurt9 (self-destruct off)",
    "crack.d_unhook": "NOP CALL NeckHurtE (unhooking)",
    "crack.d_integrity": "NOP JE after NeckHurtF (integrity bypass)",
    "crack.d_parent": "NOP JE after NeckHurtC (parent check bypass)",
    "crack.d_frida": "NOP JNE after NeckHurtD (frida/dll bypass)",
    "crack.d_watchdog": "NOP CALL NeckHurtA (watchdogs)",
    "crack.d_license": "NOP CALL NeckHurt (license check)",
    "crack.d_jmp": "JNE->JMP after NeckHurt (license bypass)",

    # ---- brand stage ----
    "brand.header": "\n[bold]--- stage: brand ---[/bold]",
    "brand.fail_nobanner": "  [red][FAIL][/red] old banner bytes not found",
    "brand.found_old": "  [green][+][/green] old banner @ file 0x{hit:X}, VA 0x{old_va:X}",
    "brand.skip_slack": "  [yellow][SKIP][/yellow] banner payload already in slack",
    "brand.fail_size": "  [red][FAIL][/red] banner ({new_len}) > slack ({gap})",
    "brand.ok_banner": "  [green][OK][/green]   banner -> VA 0x{new_va:X}",
    "brand.fail_nolea": "  [red][FAIL][/red] no LEA refs to old banner",
    "brand.skip_lea": "  [yellow][SKIP][/yellow] lea @ 0x{iva:X} already redirected",
    "brand.ok_lea": "  [green][OK][/green]   lea @ 0x{iva:X} -> 0x{new_va:X}",
    "brand.ok_len": "  [green][OK][/green]   len imm @ 0x{imm_off:X}: {old_len} -> {new_len}",
    "brand.warn_nolen": "  [yellow][WARN][/yellow] no len immediate near 0x{iva:X}",

    # ---- osd stage ----
    "osd.header": "\n[bold]--- stage: osd ---[/bold]",
    "osd.fail_section": "  [red][FAIL][/red] VA {va:#x} not in any section",
    "osd.skip_applied": "  [yellow][SKIP][/yellow] OSD @ VA {va:#x}: already applied",
    "osd.fail_mismatch": "  [red][FAIL][/red] OSD @ VA {va:#x}: expected {exp!r}, got {got!r}",
    "osd.ok": "  [green][OK][/green]   OSD @ VA {va:#x}: {exp!r} -> {rep!r}",

    # ---- image loading ----
    "image.err_phenc": "{path} starts with PHENC magic - this copy was already wiped by neckHurt9. Use the .bak / .cracked copy instead.",
    "image.err_notpe": "{path} is not a PE file (magic {magic!r}).",

    # ---- decrypt ----
    "dec.err_magic": "[red][-] Error: Invalid magic header. File is not encrypted with PHENC\x01 magic.[/red]",
    "dec.info_salt": "[cyan][*][/cyan] Extracted Salt (32 bytes): {salt}",
    "dec.info_nonce": "[cyan][*][/cyan] Extracted Nonce (12 bytes): {nonce}",
    "dec.info_deriving": "[cyan][*][/cyan] Deriving AES-256 key (100,000 SHA256 iterations)...",
    "dec.info_key": "[cyan][*][/cyan] Derived AES Key: {key}",
    "dec.info_decrypting": "[cyan][*][/cyan] Decrypting payload with AES-256-GCM...",
    "dec.ok_saved": "[green][+] Success! Decrypted binary saved to:[/green] {dst}",
    "dec.err_fail": "[red][-] Decryption failed:[/red] {err}",

    # ---- file picker ----
    "pick.title_default": "Choose EXE file",

    # ---- patch flow ----
    "flow.pick_src": "[yellow][?][/yellow] choose phantom's exe file",
    "flow.pick_title": "choose phantom binary for patching",
    "flow.pick_cancel": "[red][!][/red] file not choosed - canceling",
    "flow.header": "\n[bold]=== PHANTOM PATCHKIT ===[/bold]",
    "flow.src": "src: {src}",
    "flow.info": "({size} bytes, sha256 {digest}...)",
    "flow.summary": "\npatched={patched} skipped={skipped}{dry}",
    "flow.dry_suffix": " (dry run, nothing written)",
    "flow.fail_not_saved": "[red][!][/red] failures above - binary NOT saved",
    "flow.saved": "[green][+][/green] saved: {dst} ({size} bytes)",

    # ---- decrypt flow ----
    "decflow.pick_prompt": "[yellow][?][/yellow] choose encrypted phantom's binary",
    "decflow.pick_title": "choose encrypted file by PHENC!",

    # ---- decrypt + patch flow ----
    "dpflow.pick_title": "choose encrypted phantom's binary",
    "dpflow.step1": "\n[bold][=== decrypting ===][/bold]",
    "dpflow.step1_fail": "[red][!][/red] decrypt failed :(",
    "dpflow.step2": "\n[bold][=== patching ===][/bold]",
    "dpflow.cleaned": "[dim][*] file deleted: {f}[/dim]",
    "dpflow.clean_fail": "[yellow][!] file not deleted: {err}[/yellow]",
    "dpflow.done": "\n[green][+] PATCHED! results: {res}[/green]",

    # ---- misc UI ----
    "ui.wait_key": "\n[press any key]",
    "ui.h_decrypt": "[bold cyan]>>> decrypt phantom bin[/bold cyan]\n",
    "ui.h_patch": "[bold cyan]>>> patch phantom bin[/bold cyan]\n",
    "ui.h_all": "[bold cyan]>>> decrypt+patch phantom bin[/bold cyan]\n",
    "ui.bye": "[bold green]bb[/bold green]",
}

if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        mode = ctypes.c_ulong()
        hOut = kernel32.GetStdHandle(-11)
        kernel32.GetConsoleMode(hOut, ctypes.byref(mode))
        kernel32.SetConsoleMode(hOut, mode.value | 0x0004)
    except Exception:
        pass

OLD_BANNER = b"\x1b[91m[%s] Phantom\x1b[0m\n"
NEW_BANNER = (b"\x1b[91m[%s] Phantom cracked by undervolter"
              b" | github.com/undervolter | t.me/kronaphasia | ascade.li"
              b"\x1b[0m\n")

OSD_PATCHES = [
    (0x1403DB5E2, b"=======PHANTOM========", b"== phantom cracked == "),
    (0x1403DB5F8, b"this cam is vulnerable", b"cracked by undervolter"),
    (0x1403DB60E, b"discord.gg/SGsPCqDgGB ", b"t.me/ppatch1 .gg/dahua"),
    (0x1403DB624, b"--- phantom on top ---", b"phantom=piece of shit "),
]

IMG_BASE = 0x140000000
NOP = b"\x90"

MENU_ITEMS = [
    ("1", T["menu.item_decrypt"]),
    ("2", T["menu.item_patch"]),
    ("3", T["menu.item_decrypt_patch"]),
    ("0", T["menu.item_exit"]),
]


class PEImage:
    def __init__(self, data: bytearray):
        self.data = data
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        self.sec_tbl = pe_off + 24 + opt_size
        self.sections = []
        for i in range(nsec):
            s = data[self.sec_tbl + i*40: self.sec_tbl + (i+1)*40]
            name = s[:8].rstrip(b"\x00").decode("latin1")
            vsize, va, rsize, roff = struct.unpack_from("<IIII", s, 8)
            self.sections.append({"i": i, "name": name, "vsize": vsize,
                                  "va": va, "rsize": rsize, "roff": roff})

    def section(self, name):
        return next(s for s in self.sections if s["name"] == name)

    def va_of(self, off):
        for s in self.sections:
            if s["roff"] <= off < s["roff"] + s["rsize"]:
                return IMG_BASE + s["va"] + (off - s["roff"])
        return None

    def off_of(self, va):
        rva = va - IMG_BASE
        for s in self.sections:
            if s["va"] <= rva < s["va"] + s["vsize"]:
                return s["roff"] + (rva - s["va"])
        return None


def patch_bytes(img, va, expected, replacement, desc, stats, dry):
    off = img.off_of(va)
    if off is None:
        console.print(T["bytes.fail_section"].format(desc=desc, va=va))
        return False
    actual = bytes(img.data[off:off + len(expected)])
    if actual == replacement:
        console.print(T["bytes.skip_applied"].format(desc=desc))
        stats["skipped"] += 1
        return True
    if actual != expected:
        console.print(T["bytes.fail_mismatch"].format(desc=desc, exp=expected.hex(), off=off, got=actual.hex()))
        return False
    if not dry:
        img.data[off:off + len(replacement)] = replacement
    console.print(T["bytes.ok"].format(desc=desc, exp=expected.hex(), rep=replacement.hex(), va=va))
    stats["patched"] += 1
    return True


CRACK_PATCHES = [
    (0x1402c9ec0, b"\x4c\x8d\xa4\x24", b"\xc3\x90\x90\x90",
     T["crack.d_wiper"]),
    (0x1402d3da2, b"\xe8\xb9\x74\xff\xff", NOP * 5,
     T["crack.d_unhook"]),
    (0x1402d3dae, b"\x0f\x84\x1c\x0a\x00\x00", NOP * 6,
     T["crack.d_integrity"]),
    (0x1402d3dc2, b"\x0f\x84\xbd\x09\x00\x00", NOP * 6,
     T["crack.d_parent"]),
    (0x1402d3dcf, b"\x0f\x85\x62\x09\x00\x00", NOP * 6,
     T["crack.d_frida"]),
    (0x1402d3dd5, b"\xe8\xc6\xcc\xfe\xff", NOP * 5,
     T["crack.d_watchdog"]),
    (0x1402d3dda, b"\xe8\x81\x4d\xff\xff", NOP * 5,
     T["crack.d_license"]),
    (0x1402d3de2, b"\x75\x4b", b"\xeb\x4b",
     T["crack.d_jmp"]),
]


def stage_crack(img, stats, dry):
    console.print(T["crack.header"])
    ok = True
    for va, exp, rep, desc in CRACK_PATCHES:
        if not patch_bytes(img, va, exp, rep, desc, stats, dry):
            ok = False
    return ok


def stage_brand(img, stats, dry):
    console.print(T["brand.header"])
    rdata = img.section(".rdata")
    text = img.section(".text")

    hit = img.data.find(OLD_BANNER)
    while hit >= 0:
        tail = bytes(img.data[hit + len(OLD_BANNER):hit + len(OLD_BANNER) + 8])
        if not tail.startswith(b" cracked"):
            break
        hit = img.data.find(OLD_BANNER, hit + len(OLD_BANNER))
    if hit < 0:
        console.print(T["brand.fail_nobanner"])
        return False
    old_va = img.va_of(hit)
    console.print(T["brand.found_old"].format(hit=hit, old_va=old_va))

    slack_file = rdata["roff"] + rdata["vsize"]
    slack_va = IMG_BASE + rdata["va"] + rdata["vsize"]
    gap = rdata["rsize"] - rdata["vsize"]
    existing = bytes(img.data[slack_file:slack_file + len(NEW_BANNER)])
    if existing == NEW_BANNER:
        console.print(T["brand.skip_slack"])
    else:
        if len(NEW_BANNER) > gap:
            console.print(T["brand.fail_size"].format(new_len=len(NEW_BANNER), gap=gap))
            return False
        if not dry:
            img.data[slack_file:slack_file + len(NEW_BANNER)] = NEW_BANNER
            struct.pack_into("<I", img.data,
                             img.sec_tbl + rdata["i"] * 40 + 8,
                             rdata["vsize"] + len(NEW_BANNER))
        console.print(T["brand.ok_banner"].format(new_va=slack_va))
        rdata["vsize"] += len(NEW_BANNER)
    new_va = slack_va

    t0, t1 = text["roff"], text["roff"] + text["rsize"]
    leas = []
    i = t0
    while i < t1 - 7:
        b0 = img.data[i]
        if b0 in (0x48, 0x4C) and img.data[i + 1] == 0x8D:
            if (img.data[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", img.data, i + 3)[0]
                iva = img.va_of(i)
                if iva + 7 + disp == old_va:
                    leas.append((i, iva))
                i += 7
                continue
        i += 1
    if not leas:
        console.print(T["brand.fail_nolea"])
        return False

    ok = True
    for off, iva in leas:
        nd = new_va - (iva + 7)
        cur = struct.unpack_from("<i", img.data, off + 3)[0]
        if cur == nd:
            console.print(T["brand.skip_lea"].format(iva=iva))
            stats["skipped"] += 1
            continue
        if not dry:
            struct.pack_into("<i", img.data, off + 3, nd)
        console.print(T["brand.ok_lea"].format(iva=iva, new_va=new_va))
        stats["patched"] += 1
        found = False
        for j in range(off + 7, min(off + 7 + 32, t1 - 5)):
            b = img.data[j]
            imm = imm_off = None
            if 0xB8 <= b <= 0xBF:
                imm = struct.unpack_from("<I", img.data, j + 1)[0]
                imm_off = j + 1
            elif (b == 0x41 and j + 5 < t1
                    and 0xB8 <= img.data[j + 1] <= 0xBF):
                imm = struct.unpack_from("<I", img.data, j + 2)[0]
                imm_off = j + 2
            elif (b == 0x48 and j + 6 < t1 and img.data[j + 1] == 0xC7
                    and (img.data[j + 2] & 0xF8) == 0xC0):
                imm = struct.unpack_from("<I", img.data, j + 3)[0]
                imm_off = j + 3
            if imm == len(OLD_BANNER):
                if not dry:
                    struct.pack_into("<I", img.data, imm_off,
                                     len(NEW_BANNER))
                console.print(T["brand.ok_len"].format(imm_off=imm_off, old_len=len(OLD_BANNER), new_len=len(NEW_BANNER)))
                stats["patched"] += 1
                found = True
                break
        if not found:
            console.print(T["brand.warn_nolen"].format(iva=iva))
            ok = False
    return ok


def stage_osd(img, stats, dry):
    console.print(T["osd.header"])
    ok = True
    for va, exp, rep in OSD_PATCHES:
        assert len(exp) == len(rep), f"OSD pair length mismatch @ VA {va:#x}"
        off = img.off_of(va)
        if off is None:
            console.print(T["osd.fail_section"].format(va=va))
            ok = False
            continue
        actual = bytes(img.data[off:off + len(exp)])
        if actual == rep:
            console.print(T["osd.skip_applied"].format(va=va))
            stats["skipped"] += 1
            continue
        if actual != exp:
            console.print(T["osd.fail_mismatch"].format(va=va, exp=exp, got=actual))
            ok = False
            continue
        if not dry:
            img.data[off:off + len(rep)] = rep
        console.print(T["osd.ok"].format(va=va, exp=exp, rep=rep))
        stats["patched"] += 1
    return ok


def load_image(path):
    raw = open(path, "rb").read()
    if bytes(raw[:5]) == b"PHENC":
        return None, T["image.err_phenc"].format(path=path)
    if bytes(raw[:2]) != b"MZ":
        return None, T["image.err_notpe"].format(path=path, magic=bytes(raw[:4]))
    return PEImage(bytearray(raw)), None


STATIC_KEY_STR = b"HWID&%dec63E0472_=d===215!35261Y"


def decrypt_ghost_file(src_path, dst_path=None):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    with open(src_path, "rb") as f:
        data = f.read()

    if data[:6] != b"\x50\x48\x45\x4E\x43\x01":
        console.print(T["dec.err_magic"])
        return None

    salt = data[6:38]
    nonce = data[38:50]
    ciphertext = data[50:]

    console.print(T["dec.info_salt"].format(salt=salt.hex()))
    console.print(T["dec.info_nonce"].format(nonce=nonce.hex()))
    console.print(T["dec.info_deriving"])

    current_hash = hashlib.sha256(STATIC_KEY_STR + salt).digest()
    for _ in range(100000):
        current_hash = hashlib.sha256(current_hash + salt).digest()

    aes_key = current_hash
    console.print(T["dec.info_key"].format(key=aes_key.hex()))
    console.print(T["dec.info_decrypting"])

    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        if not dst_path:
            base, ext = os.path.splitext(src_path)
            dst_path = f"{base}_decrypted{ext}"
        with open(dst_path, "wb") as f:
            f.write(plaintext)
        console.print(T["dec.ok_saved"].format(dst=dst_path))
        return dst_path
    except Exception as e:
        console.print(T["dec.err_fail"].format(err=e))
        return None


def pick_file(title=None):
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askopenfilename(
        title=title or T["pick.title_default"],
        filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
    )
    root.destroy()
    return path


def run_patch_flow(a, src_file=None):
    src_path = src_file or a.src
    if not src_path:
        console.print(T["flow.pick_src"])
        src_path = pick_file(T["flow.pick_title"])
        if not src_path:
            console.print(T["flow.pick_cancel"])
            return None

    dst_path = a.dst
    if not dst_path:
        base, ext = os.path.splitext(src_path)
        dst_path = f"{base}_branded{ext}"

    img, err = load_image(src_path)
    console.print(T["flow.header"])
    console.print(T["flow.src"].format(src=src_path))
    if err:
        console.print(f"[red][!][/red] {err}")
        return None
    console.print(T["flow.info"].format(size=f"{len(img.data):,}",
                                        digest=hashlib.sha256(img.data).hexdigest()[:16]))
    stats = {"patched": 0, "skipped": 0}
    ok = True
    if not a.no_crack:
        ok = stage_crack(img, stats, a.dry_run) and ok
    if not a.no_brand:
        ok = stage_brand(img, stats, a.dry_run) and ok
    if not a.no_osd:
        ok = stage_osd(img, stats, a.dry_run) and ok

    console.print(T["flow.summary"].format(patched=stats["patched"], skipped=stats["skipped"],
                                                  dry=T["flow.dry_suffix"] if a.dry_run else ""))
    if a.dry_run:
        return dst_path
    if not ok:
        console.print(T["flow.fail_not_saved"])
        return None
    with open(dst_path, "wb") as f:
        f.write(img.data)
    console.print(T["flow.saved"].format(dst=dst_path, size=f"{len(img.data):,}"))
    return dst_path


def run_decrypt_flow():
    console.print(T["decflow.pick_prompt"])
    src = pick_file(T["decflow.pick_title"])
    if not src:
        console.print(T["flow.pick_cancel"])
        return None
    return decrypt_ghost_file(src)


def run_decrypt_and_patch_flow(a):
    console.print(T["decflow.pick_prompt"])
    src = pick_file(T["dpflow.pick_title"])
    if not src:
        console.print(T["flow.pick_cancel"])
        return

    console.print(T["dpflow.step1"])
    decrypted_file = decrypt_ghost_file(src)
    if not decrypted_file:
        console.print(T["dpflow.step1_fail"])
        return

    console.print(T["dpflow.step2"])
    base, ext = os.path.splitext(decrypted_file)
    final_dst = f"{base}_cracked{ext}"
    a.dst = final_dst
    res = run_patch_flow(a, src_file=decrypted_file)
    if res:
        try:
            if os.path.exists(decrypted_file) and decrypted_file != res:
                os.remove(decrypted_file)
                console.print(T["dpflow.cleaned"].format(f=decrypted_file))
        except Exception as e:
            console.print(T["dpflow.clean_fail"].format(err=e))
        console.print(T["dpflow.done"].format(res=res))


def render_menu(selected_idx):
    """Renders the entire menu UI perfectly centered horizontally and vertically."""
    art_str = r"""               __         __________         __         .__                  
______   _____/  |_  _____\______   \_____ _/  |_  ____ |  |__   ___________ 
\____ \ /    \   __\/     \|     ___/\__  \\   __\/ ___\|  |  \_/ __ \_  __ \
|  |_> >   |  \  | |  Y Y  \    |     / __ \|  | \  \___|   Y  \  ___/|  | \/
|   __/|___|  /__| |__|_|  /____|    (____  /__|  \___  >___|  /\___  >__|   
|__|        \/           \/               \/          \/     \/     \/       """

    art = Text(art_str, style="bold red")

    sub_group = Group(
        Text(T["menu.title"], style="bold white", justify="center"),
        Text("made by ascade.li | t.me/kronaphasia | github.com/undervolter", style="dim cyan", justify="center")
    )

    menu_lines = [
        Text("========================================", style="bold cyan"),
        Text(T["menu.what"], style="bold white"),
        Text(""),
    ]

    for i, (key, title) in enumerate(MENU_ITEMS):
        if i == selected_idx:
            menu_lines.append(Text.assemble(
                (" > ", "bold red"),
                (f"{key}) ", "bold yellow"),
                (f"{title}", "bold white")
            ))
        else:
            menu_lines.append(Text.assemble(
                ("   ", "white"),
                (f"{key}) ", "yellow"),
                (f"{title}", "white")
            ))

    menu_lines.append(Text("========================================", style="bold cyan"))
    menu_group = Group(*menu_lines)

    full_ui = Group(
        art,
        Text(""),
        sub_group,
        Text(""),
        Align.center(menu_group, width=40)
    )

    h = console.height
    if h > 20:
        return Align(full_ui, align="center", vertical="middle", height=h)
    return Align(full_ui, align="center")


def read_input_nonblocking():
    """Non-blocking keyboard read supporting Arrow keys, Enter, and hotkeys."""
    if os.name == "nt":
        import msvcrt
        if not msvcrt.kbhit():
            return None
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):
            code = msvcrt.getch()
            if code in (b"H",):
                return "UP"
            elif code in (b"P",):
                return "DOWN"
            return None
        if ch in (b"\r", b"\n", b" "):
            return "ENTER"
        if ch in (b"\x1b",):
            return "ESC"
        if ch in (b"\x03",):
            return "CTRL_C"
        try:
            char = ch.decode("utf-8", errors="ignore").lower()
            if char in ("w", "k"):
                return "UP"
            if char in ("s", "j"):
                return "DOWN"
            if char in ("1", "2", "3", "0", "q"):
                return char
        except Exception:
            pass
    else:
        import select
        dr, _, _ = select.select([sys.stdin], [], [], 0)
        if not dr:
            return None
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            dr2, _, _ = select.select([sys.stdin], [], [], 0.05)
            if dr2:
                seq = sys.stdin.read(2)
                if seq == "[A":
                    return "UP"
                elif seq == "[B":
                    return "DOWN"
            return "ESC"
        if ch in ("\r", "\n", " "):
            return "ENTER"
        if ch in ("w", "k"):
            return "UP"
        if ch in ("s", "j"):
            return "DOWN"
        if ch in ("1", "2", "3", "0", "q"):
            return ch
    return None


def select_menu_item():
    """Interactive loop with dynamic live-resize centering and arrow key navigation."""
    if not sys.stdin.isatty():
        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return "0"

    selected_idx = 0
    with Live(render_menu(selected_idx), console=console, screen=True, auto_refresh=False) as live:
        last_size = console.size
        while True:
            current_size = console.size
            if current_size != last_size:
                last_size = current_size
                live.update(render_menu(selected_idx), refresh=True)

            key = read_input_nonblocking()
            if key == "UP":
                selected_idx = (selected_idx - 1) % len(MENU_ITEMS)
                live.update(render_menu(selected_idx), refresh=True)
            elif key == "DOWN":
                selected_idx = (selected_idx + 1) % len(MENU_ITEMS)
                live.update(render_menu(selected_idx), refresh=True)
            elif key == "ENTER":
                return MENU_ITEMS[selected_idx][0]
            elif key in ("1", "2", "3", "0"):
                return key
            elif key in ("q", "ESC", "CTRL_C"):
                return "0"

            time.sleep(0.02)


def wait_any_key():
    """Wait for any keypress before returning to menu."""
    console.print(Align.center(Text(T["ui.wait_key"], style="dim yellow")))
    if sys.stdin.isatty():
        if os.name == "nt":
            import msvcrt
            msvcrt.getch()
            return
        else:
            try:
                import termios, tty
                fd = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    sys.stdin.read(1)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                return
            except Exception:
                pass
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


def main():
    ap = argparse.ArgumentParser(description=T["cli.desc"])
    ap.add_argument("--src", default=None, help=T["cli.src"])
    ap.add_argument("--dst", default=None, help=T["cli.dst"])
    ap.add_argument("--decrypt", action="store_true", help=T["cli.decrypt"])
    ap.add_argument("--patch", action="store_true", help=T["cli.patch"])
    ap.add_argument("--decrypt-and-patch", action="store_true", help=T["cli.decrypt_patch"])
    ap.add_argument("--no-crack", action="store_true", help=T["cli.no_crack"])
    ap.add_argument("--no-brand", action="store_true", help=T["cli.no_brand"])
    ap.add_argument("--no-osd", action="store_true", help=T["cli.no_osd"])
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if a.decrypt_and_patch:
        if a.src:
            dec = decrypt_ghost_file(a.src)
            if dec:
                run_patch_flow(a, src_file=dec)
        else:
            run_decrypt_and_patch_flow(a)
        return

    if a.decrypt:
        if a.src:
            decrypt_ghost_file(a.src, a.dst)
        else:
            run_decrypt_flow()
        return

    if a.patch or a.src:
        run_patch_flow(a)
        return

    while True:
        choice = select_menu_item()

        if choice == "1":
            console.clear()
            console.print(T["ui.h_decrypt"])
            run_decrypt_flow()
            wait_any_key()
        elif choice == "2":
            console.clear()
            console.print(T["ui.h_patch"])
            run_patch_flow(a)
            wait_any_key()
        elif choice == "3":
            console.clear()
            console.print(T["ui.h_all"])
            run_decrypt_and_patch_flow(a)
            wait_any_key()
        elif choice in ("0", "q", "Q"):
            console.clear()
            console.print(T["ui.bye"])
            return


if __name__ == "__main__":
    main()
