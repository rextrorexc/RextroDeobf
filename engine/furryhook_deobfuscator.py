"""
furryhook_deobfuscator.py - Single-Command End-to-End Java / Fabric Mod Deobfuscator & Auditor

Capabilities:
  1. JVM Bytecode Metadata Parser (SourceFile, InnerClasses, BootstrapMethods)
  2. CFR Anti-Obfuscation Decompiler Orchestration
  3. Dynamic Cipher Discovery & String/Indy Deobfuscation
  4. Java Lexer & Precedence-Aware Constant Folder
  5. Symbolic Opaque Predicate & Watermark Eliminator
  6. Constant Inliner, Static Block Lifter & Code Polish
  7. Collision-Free Class, Package & Config Remapper
  8. Security & Domain Reverse-Engineering Auditor

Usage:
  python3 furryhook_deobfuscator.py furryhook-obf.jar -o furryhook_deobf
  python3 furryhook_deobfuscator.py furryhook_src -o furryhook_clean --no-cfr
"""

from __future__ import annotations

import argparse
import ast
import base64
import concurrent.futures
import json
import operator
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import unicodedata
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ==============================================================================
# Constants & Configuration Tables
# ==============================================================================

DEFAULT_CFR_CANDIDATES: Tuple[str, ...] = (
    os.path.expanduser("~/.local/share/cfr.jar"),
    os.path.expanduser("~/cfr.jar"),
    "/usr/share/java/cfr.jar",
    "/opt/cfr/cfr.jar",
    "cfr.jar",
)

DEFAULT_JAVA_CANDIDATES: Tuple[str, ...] = (
    os.path.expanduser("~/.local/share/PrismLauncher/java/java-runtime-delta/bin/java"),
    os.path.expanduser("~/.local/share/PrismLauncher/java/java-runtime-gamma/bin/java"),
    "/usr/lib/jvm/default/bin/java",
    "/usr/lib/jvm/java-21-openjdk/bin/java",
    "/usr/bin/java",
)

# Semantic package mapping inferred from FurryHook's module/subsystem responsibilities
SEMANTIC_PACKAGE_MAP: Dict[str, str] = {
    "ad": "com.furryhook.alts",
    "bc": "com.furryhook.features.impl.pve.mining",
    "caf": "com.furryhook.ui.hud",
    "cf": "com.furryhook.obf.dec1",
    "cq": "com.furryhook.obf.dec2",
    "cr": "com.furryhook.navigation",
    "crt": "com.furryhook.mixin",
    "did": "com.furryhook.render.chams",
    "dif": "com.furryhook.features",
    "dz": "com.furryhook.obf.decoy1",
    "ed": "com.furryhook.events.player",
    "ej": "com.furryhook",
    "fk": "com.furryhook.events.network",
    "fuh": "com.furryhook.features.impl.combat.aura",
    "fxw": "com.furryhook.render.util",
    "gce": "com.furryhook.eventbus",
    "gld": "com.furryhook.emotes",
    "hb": "com.furryhook.ui.menu",
    "hy": "com.furryhook.events.render",
    "ic": "com.furryhook.server",
    "id": "com.furryhook.util.math",
    "ie": "com.furryhook.features.impl.player",
    "kp": "com.furryhook.obf.decoy2",
    "lh": "com.furryhook.obf.decoy3",
    "mh": "com.furryhook.features.impl.pve",
    "mpk": "com.furryhook.util.text",
    "nje": "com.furryhook.combat.neuro",
    "nq": "com.furryhook.features.impl.pve.warden",
    "ou": "com.furryhook.features.settings",
    "pft": "com.furryhook.events.screen",
    "qhh": "com.furryhook.ui.lang",
    "qm": "com.furryhook.features.impl.movement",
    "qmf": "com.furryhook.render.target",
    "qx": "com.furryhook.obf.decoy4",
    "qxd": "com.furryhook.util.inventory",
    "rj": "com.furryhook.obf.decoy5",
    "rn": "com.furryhook.obf.dec3",
    "rq": "com.furryhook.render.post",
    "rwa": "com.furryhook.events.input",
    "szf": "com.furryhook.sync",
    "tg": "com.furryhook.ui.render",
    "tp": "com.furryhook.core",
    "ua": "com.furryhook.obf.concat",
    "ubl": "com.furryhook.features.impl.render",
    "uj": "com.furryhook.features.impl.pve.core",
    "ur": "com.furryhook.commands.impl",
    "vb": "com.furryhook.obf.decoy6",
    "vk": "com.furryhook.context",
    "vy": "com.furryhook.features.impl.combat",
    "wce": "com.furryhook.commands",
    "wwr": "com.furryhook.render.world",
    "xv": "com.furryhook.ui.handlers",
    "xvk": "com.furryhook.render.jump",
    "xx": "com.furryhook.ui.screens",
    "ybc": "com.furryhook.combat.rotations",
    "yox": "com.furryhook.features.impl.misc",
    "yvf": "com.furryhook.render.particles",
    "yx": "com.furryhook.events.client",
}

JAVA_KEYWORDS: Set[str] = {
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char",
    "class", "const", "continue", "default", "do", "double", "else", "enum",
    "extends", "final", "finally", "float", "for", "goto", "if", "implements",
    "import", "instanceof", "int", "interface", "long", "native", "new",
    "package", "private", "protected", "public", "return", "short", "static",
    "strictfp", "super", "switch", "synchronized", "this", "throw", "throws",
    "transient", "try", "void", "volatile", "while", "yield", "record", "sealed",
    "permits", "var", "true", "false", "null",
}

JAVA_PRIM_TYPES: Set[str] = {
    "boolean", "byte", "short", "char", "int", "long", "float", "double", "void"
}

SAFE_URL_HOSTS: Tuple[str, ...] = (
    "fabricmc.net", "mojang.com", "minecraft.net", "github.com/Vineflower",
    "maven.org", "lucide.dev", "w3.org", "apache.org", "oracle.com",
    "schema.org", "json-schema.org", "benf.org",
)

BINARY_MAGICS: Dict[bytes, str] = {
    b"MZ": "Windows PE Executable / DLL",
    b"\x7fELF": "Linux ELF Binary",
    b"\xca\xfe\xba\xbe": "Java Classfile",
    b"\xcf\xfa\xed\xfe": "macOS Mach-O (64-bit)",
    b"\xfe\xed\xfa\xcf": "macOS Mach-O (BE)",
}

SCRIPT_EXTENSIONS: Set[str] = {
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py", ".jse", ".hta"
}

SCRIPT_NET_RE = re.compile(
    r"(Invoke-WebRequest|\biwr\b|Invoke-Expression|\biex\b|DownloadString|"
    r"DownloadFile|WebClient|Net\.Sockets|FromBase64String|curl\s|wget\s|"
    r"Start-BitsTransfer|certutil|bitsadmin|https?://)",
    re.I,
)

DANGEROUS_API_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    ("Process Execution", "CRITICAL",
     r"new\s+ProcessBuilder\s*\(|Runtime\.getRuntime\(\)\s*\.exec\s*\("),
    ("Raw Socket / IPC", "HIGH",
     r"new\s+(?:SSL)?Socket\s*\(|DatagramSocket|ServerSocket|"
     r"InetSocketAddress\s*\(|SocketChannel\.open|NioSocketChannel|UnixDomainSocketAddress"),
    ("HTTP Client / Request", "HIGH",
     r"HttpClient\.new|HttpURLConnection|\.openConnection\s*\(|"
     r"new\s+URL\s*\(|URI\.create\s*\(\s*\"https?"),
    ("Dynamic Class Loading", "CRITICAL",
     r"defineClass\s*\(|new\s+URLClassLoader|MethodHandles\.Lookup.*defineClass|"
     r"Unsafe\.(?:defineClass|defineAnonymousClass)"),
    ("Native Library Loading", "HIGH",
     r"System\.load(?:Library)?\s*\("),
    ("Dynamic Reflection", "MEDIUM",
     r"Class\.forName\s*\(\s*[^\"\s)]"),
    ("Sensitive Path Access", "CRITICAL",
     r"\"[^\"]*(?:Local Storage|leveldb|Login Data|Cookies|"
     r"\.minecraft[/\\\\]launcher_accounts|discord[/\\\\]|Telegram Desktop|"
     r"\.ssh|\.aws|Exodus|Electrum|wallet)[^\"]*\""),
    ("Persistence Mechanism", "CRITICAL",
     r"\"[^\"]*(?:\\\\Run\b|schtasks|Startup\\\\|autostart|crontab|"
     r"systemd/user)[^\"]*\""),
    ("Hidden PowerShell", "HIGH",
     r"\"powershell(?:\.exe)?\"[\s\S]{0,300}?\"-(?:WindowStyle|EncodedCommand|enc)\""),
    ("Cryptographic Cipher", "INFO",
     r"Cipher\.getInstance\s*\(|SecretKeySpec\s*\(|GCMParameterSpec\s*\("),
)

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
IP_RE = re.compile(
    r"\b(?!(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d+|\d+\.\d+\.\d+\.0)\b)"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)
B64_RE = re.compile(r'"([A-Za-z0-9+/]{24,}={0,2})"')
ARR_RE = re.compile(r"new\s+(byte|char|int)\s*\[\s*\]\s*\{([^{}]{8,4000})\}")


# ==============================================================================
# Integer Width & Java Semantics Helpers
# ==============================================================================

def to_int32(val: int) -> int:
    val &= 0xFFFFFFFF
    return val - 0x100000000 if val >= 0x80000000 else val


def to_int64(val: int) -> int:
    val &= 0xFFFFFFFFFFFFFFFF
    return val - 0x10000000000000000 if val >= 0x8000000000000000 else val


def java_rshift32(val: int, shift: int) -> int:
    shift &= 0x1F
    return to_int32(to_int32(val) >> shift)


def java_urshift32(val: int, shift: int) -> int:
    shift &= 0x1F
    return to_int32((val & 0xFFFFFFFF) >> shift)


def java_lshift32(val: int, shift: int) -> int:
    shift &= 0x1F
    return to_int32((val & 0xFFFFFFFF) << shift)


def java_rshift64(val: int, shift: int) -> int:
    shift &= 0x3F
    return to_int64(to_int64(val) >> shift)


def java_urshift64(val: int, shift: int) -> int:
    shift &= 0x3F
    return to_int64((val & 0xFFFFFFFFFFFFFFFF) >> shift)


def java_lshift64(val: int, shift: int) -> int:
    shift &= 0x3F
    return to_int64((val & 0xFFFFFFFFFFFFFFFF) << shift)


def java_string_escape(text: str, unescape_utf8: bool = True) -> str:
    """Format a Python string as a safe Java string literal."""
    out: List[str] = ['"']
    for ch in text:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif 0x20 <= code <= 0x7E:
            out.append(ch)
        elif unescape_utf8 and code >= 0xA0 and not unicodedata.category(ch).startswith("C"):
            # Keep visible international UTF-8 characters (Cyrillic, Turkish, symbols),
            # while keeping format/control/bidi characters (like Cf, Cc, Cs) escaped.
            out.append(ch)
        else:
            out.append(f"\\u{code:04x}")
    out.append('"')
    return "".join(out)


def unescape_java_string_content(raw: str) -> str:
    """Decode Java escape sequences inside a string literal (without quotes)."""
    out: List[str] = []
    i = 0
    n = len(raw)
    simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "\\": "\\", '"': '"', "'": "'"}
    while i < n:
        ch = raw[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = raw[i + 1]
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
        elif nxt == "u":
            j = i + 2
            while j < n and raw[j] == "u":
                j += 1
            if j + 4 <= n:
                try:
                    cp = int(raw[j:j + 4], 16)
                    out.append(chr(cp))
                    i = j + 4
                    continue
                except ValueError:
                    pass
            out.append(ch)
            i += 1
        elif "0" <= nxt <= "7":
            j = i + 1
            limit = 3 if nxt <= "3" else 2
            while j < n and (j - (i + 1)) < limit and "0" <= raw[j] <= "7":
                j += 1
            out.append(chr(int(raw[i + 1:j], 8)))
            i = j
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# ==============================================================================
# Stage 1: JVM ClassFile Binary Parser & Bytecode Metadata Extraction
# ==============================================================================

@dataclass
class ClassMetadata:
    internal_name: str               # e.g. "ad/bzgn"
    package: str                     # e.g. "ad"
    simple_name: str                 # e.g. "bzgn"
    super_name: str = ""
    interfaces: List[str] = field(default_factory=list)
    access_flags: int = 0
    source_file: Optional[str] = None
    is_inner: bool = False
    outer_class: Optional[str] = None
    field_names: List[str] = field(default_factory=list)
    method_names: List[str] = field(default_factory=list)
    has_indy_concat: bool = False
    utf8_strings: List[str] = field(default_factory=list)


class JVMClassFileParser:
    """Zero-dependency binary parser adhering to the JVM ClassFile specification."""

    ACC_PUBLIC = 0x0001
    ACC_INTERFACE = 0x0200
    ACC_ABSTRACT = 0x0400
    ACC_SYNTHETIC = 0x1000
    ACC_ENUM = 0x4000

    @classmethod
    def parse_bytes(cls, data: bytes) -> Optional[ClassMetadata]:
        if len(data) < 12 or data[:4] != b"\xCA\xFE\xBA\xBE":
            return None
        try:
            pos = 8
            cp_count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            cp: List[Any] = [None] * cp_count
            i = 1
            while i < cp_count:
                tag = data[pos]
                pos += 1
                if tag == 1:  # CONSTANT_Utf8
                    ln = struct.unpack_from(">H", data, pos)[0]
                    pos += 2
                    cp[i] = ("Utf8", data[pos:pos + ln].decode("utf-8", errors="replace"))
                    pos += ln
                elif tag in (3, 4):  # Integer / Float
                    val = struct.unpack_from(">i", data, pos)[0] if tag == 3 else struct.unpack_from(">f", data, pos)[0]
                    cp[i] = ("Num", val)
                    pos += 4
                elif tag in (5, 6):  # Long / Double (occupies 2 CP slots)
                    val = struct.unpack_from(">q", data, pos)[0] if tag == 5 else struct.unpack_from(">d", data, pos)[0]
                    cp[i] = ("Num64", val)
                    pos += 8
                    i += 1
                elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
                    idx = struct.unpack_from(">H", data, pos)[0]
                    cp[i] = (tag, idx)
                    pos += 2
                elif tag in (9, 10, 11, 12, 17, 18):  # Fieldref, Methodref, NameAndType, Dynamic, InvokeDynamic
                    idx1, idx2 = struct.unpack_from(">HH", data, pos)
                    cp[i] = (tag, idx1, idx2)
                    pos += 4
                elif tag == 15:  # MethodHandle
                    kind, idx = struct.unpack_from(">BH", data, pos)
                    cp[i] = (15, kind, idx)
                    pos += 3
                else:
                    return None
                i += 1

            def cp_utf8(idx: int) -> str:
                if 0 < idx < cp_count and isinstance(cp[idx], tuple) and cp[idx][0] == "Utf8":
                    return cp[idx][1]
                return ""

            def cp_class_name(idx: int) -> str:
                if 0 < idx < cp_count and isinstance(cp[idx], tuple) and cp[idx][0] == 7:
                    return cp_utf8(cp[idx][1])
                return ""

            access_flags, this_idx, super_idx = struct.unpack_from(">HHH", data, pos)
            pos += 6
            this_name = cp_class_name(this_idx)
            super_name = cp_class_name(super_idx)

            iface_count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            interfaces = []
            for _ in range(iface_count):
                if_idx = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                interfaces.append(cp_class_name(if_idx))

            def skip_attributes(p: int) -> Tuple[int, List[Tuple[str, bytes]]]:
                attr_count = struct.unpack_from(">H", data, p)[0]
                p += 2
                attrs: List[Tuple[str, bytes]] = []
                for _ in range(attr_count):
                    name_idx, attr_len = struct.unpack_from(">HI", data, p)
                    p += 6
                    attr_name = cp_utf8(name_idx)
                    attrs.append((attr_name, data[p:p + attr_len]))
                    p += attr_len
                return p, attrs

            # Fields
            fields_count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            field_names: List[str] = []
            for _ in range(fields_count):
                _, fname_idx, _ = struct.unpack_from(">HHH", data, pos)
                pos += 6
                field_names.append(cp_utf8(fname_idx))
                pos, _ = skip_attributes(pos)

            # Methods
            methods_count = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            method_names: List[str] = []
            for _ in range(methods_count):
                _, mname_idx, _ = struct.unpack_from(">HHH", data, pos)
                pos += 6
                method_names.append(cp_utf8(mname_idx))
                pos, _ = skip_attributes(pos)

            # Class attributes
            _, class_attrs = skip_attributes(pos)
            source_file: Optional[str] = None
            has_indy_concat = False
            for aname, abody in class_attrs:
                if aname == "SourceFile" and len(abody) >= 2:
                    src_idx = struct.unpack_from(">H", abody, 0)[0]
                    source_file = cp_utf8(src_idx)
                elif aname == "BootstrapMethods":
                    has_indy_concat = True

            pkg = this_name.rsplit("/", 1)[0] if "/" in this_name else ""
            simple = this_name.rsplit("/", 1)[-1]
            is_inner = "$" in simple
            outer = this_name.split("$", 1)[0] if is_inner else None

            utf8_strings = [
                ent[1] for ent in cp
                if isinstance(ent, tuple) and ent[0] == "Utf8"
            ]

            return ClassMetadata(
                internal_name=this_name,
                package=pkg,
                simple_name=simple,
                super_name=super_name,
                interfaces=interfaces,
                access_flags=access_flags,
                source_file=source_file,
                is_inner=is_inner,
                outer_class=outer,
                field_names=field_names,
                method_names=method_names,
                has_indy_concat=has_indy_concat,
                utf8_strings=utf8_strings,
            )
        except (struct.error, IndexError):
            return None

    @classmethod
    def inspect_jar(cls, jar_path: Path) -> Dict[str, ClassMetadata]:
        metadata: Dict[str, ClassMetadata] = {}
        with zipfile.ZipFile(jar_path, "r") as zf:
            for entry in zf.namelist():
                if entry.endswith(".class"):
                    meta = cls.parse_bytes(zf.read(entry))
                    if meta:
                        metadata[meta.internal_name] = meta
        return metadata


# ==============================================================================
# Stage 2: Java Source Lexer & Token Stream Engine
# ==============================================================================

@dataclass
class Token:
    kind: str    # WS, NL, COMMENT, STRING, CHAR, TEXTBLOCK, NUMBER, IDENT, OP, SEP
    text: str
    start: int
    end: int


class JavaLexer:
    """Fast, accurate Java 21+ lexer preserving strings, char literals, and comments."""

    MULTI_OPS: Tuple[str, ...] = (
        ">>>=", ">>>", ">>=", "<<=", "::", "->", "==", "!=", "<=", ">=",
        "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
        "<<", ">>",
    )
    SINGLE_OPS: Set[str] = set("+-*/%&|^~!<>?:=")
    SEPS: Set[str] = set("(){}[];,.")

    @classmethod
    def tokenize(cls, text: str) -> List[Token]:
        tokens: List[Token] = []
        n = len(text)
        i = 0
        while i < n:
            ch = text[i]

            # Newlines
            if ch == "\n" or ch == "\r":
                j = i + 1
                if ch == "\r" and j < n and text[j] == "\n":
                    j += 1
                tokens.append(Token("NL", text[i:j], i, j))
                i = j
                continue

            # Horizontal whitespace
            if ch in " \t\v\f":
                j = i + 1
                while j < n and text[j] in " \t\v\f":
                    j += 1
                tokens.append(Token("WS", text[i:j], i, j))
                i = j
                continue

            # Line comment
            if ch == "/" and i + 1 < n and text[i + 1] == "/":
                j = text.find("\n", i + 2)
                if j == -1:
                    j = n
                tokens.append(Token("COMMENT", text[i:j], i, j))
                i = j
                continue

            # Block / Javadoc comment
            if ch == "/" and i + 1 < n and text[i + 1] == "*":
                j = text.find("*/", i + 2)
                j = n if j == -1 else j + 2
                tokens.append(Token("COMMENT", text[i:j], i, j))
                i = j
                continue

            # Text block """..."""
            if text.startswith('"""', i):
                j = i + 3
                while j < n:
                    if text[j] == "\\":
                        j += 2
                    elif text.startswith('"""', j):
                        j += 3
                        break
                    else:
                        j += 1
                tokens.append(Token("TEXTBLOCK", text[i:j], i, j))
                i = j
                continue

            # String literal
            if ch == '"':
                j = i + 1
                while j < n:
                    if text[j] == "\\":
                        j += 2
                    elif text[j] == '"':
                        j += 1
                        break
                    elif text[j] == "\n":
                        break
                    else:
                        j += 1
                tokens.append(Token("STRING", text[i:j], i, j))
                i = j
                continue

            # Char literal
            if ch == "'":
                j = i + 1
                while j < n:
                    if text[j] == "\\":
                        j += 2
                    elif text[j] == "'":
                        j += 1
                        break
                    elif text[j] == "\n":
                        break
                    else:
                        j += 1
                tokens.append(Token("CHAR", text[i:j], i, j))
                i = j
                continue

            # Number literal (hex, binary, decimal, float/double)
            if ch.isdigit() or (ch == "." and i + 1 < n and text[i + 1].isdigit()):
                j = i
                if text[j:j + 2].lower() in ("0x", "0b"):
                    j += 2
                    while j < n and (text[j] in "0123456789abcdefABCDEF_"):
                        j += 1
                    # Hex float exponent (0x1.0p-2)
                    if j < n and text[j] == ".":
                        j += 1
                        while j < n and text[j] in "0123456789abcdefABCDEF_":
                            j += 1
                    if j < n and text[j] in "pP":
                        j += 1
                        if j < n and text[j] in "+-":
                            j += 1
                        while j < n and (text[j].isdigit() or text[j] == "_"):
                            j += 1
                else:
                    while j < n and (text[j].isdigit() or text[j] == "_"):
                        j += 1
                    if j < n and text[j] == "." and not (j + 1 < n and text[j + 1] == "."):
                        j += 1
                        while j < n and (text[j].isdigit() or text[j] == "_"):
                            j += 1
                    if j < n and text[j] in "eE":
                        j += 1
                        if j < n and text[j] in "+-":
                            j += 1
                        while j < n and (text[j].isdigit() or text[j] == "_"):
                            j += 1
                if j < n and text[j] in "lLfFdD":
                    j += 1
                tokens.append(Token("NUMBER", text[i:j], i, j))
                i = j
                continue

            # Identifier / keyword
            if ch.isalpha() or ch in "_$":
                j = i + 1
                while j < n and (text[j].isalnum() or text[j] in "_$"):
                    j += 1
                tokens.append(Token("IDENT", text[i:j], i, j))
                i = j
                continue

            # Multi-char operators
            matched_op = None
            for mop in cls.MULTI_OPS:
                if text.startswith(mop, i):
                    matched_op = mop
                    break
            if matched_op:
                tokens.append(Token("OP", matched_op, i, i + len(matched_op)))
                i += len(matched_op)
                continue

            # Separators & annotations
            if ch in cls.SEPS or ch == "@":
                tokens.append(Token("SEP", ch, i, i + 1))
                i += 1
                continue

            if ch in cls.SINGLE_OPS:
                tokens.append(Token("OP", ch, i, i + 1))
                i += 1
                continue

            tokens.append(Token("OTHER", ch, i, i + 1))
            i += 1
        return tokens


# ==============================================================================
# Stage 3: Dynamic Cipher Discovery, String & Indy Deobfuscation
# ==============================================================================

@dataclass
class StrDecProfile:
    class_fqn: str           # e.g. "cf.rp"
    simple_name: str         # e.g. "rp"
    package: str             # e.g. "cf"
    method_name: str         # e.g. "d"
    default_mul: int
    seed_xor: int
    step1_add: int = -1640531527
    step3_add: int = 12345
    mix1: int = 2146121005
    mix2: int = -2073254261


@dataclass
class StrCatProfile:
    class_fqn: str           # e.g. "ua.ptr"
    simple_name: str         # e.g. "ptr"
    package: str             # e.g. "ua"
    method_name: str         # e.g. "b"
    lcg_mul: int = 1103515245
    lcg_add: int = 12345


class StringCipherRegistry:
    """Discovers and executes string cipher and invokedynamic concatenation kernels."""

    STRDEC_SIGNATURE_RE = re.compile(
        r"DEFAULT_MUL\s*=\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*;.*?"
        r"Base64\.getDecoder\(\)\.decode\(.*?\).*?"
        r"\^\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*;",
        re.DOTALL,
    )

    STRCAT_SIGNATURE_RE = re.compile(
        r"public\s+static\s+CallSite\s+(\w+)\s*\([^)]*MethodHandles\.Lookup.*?"
        r"n2\s*\*\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*\+\s*(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*;.*?"
        r"StringConcatFactory\.makeConcatWithConstants",
        re.DOTALL,
    )

    def __init__(self) -> None:
        self.strdecs: Dict[str, StrDecProfile] = {}
        self.strcats: Dict[str, StrCatProfile] = {}
        self.decryptor_files: Set[Path] = set()
        # Fallback profiles in case decryptor source files were already stripped
        self.add_strdec(StrDecProfile("cf.rp", "rp", "cf", "d", 1411743317, 0x54257E55))
        self.add_strdec(StrDecProfile("rn.ms", "ms", "rn", "d", -354801545, 0xEADA2877))
        self.add_strdec(StrDecProfile("cq.mr", "mr", "cq", "d", 253498949, 0xF1C1645))
        self.add_strcat(StrCatProfile("ua.ptr", "ptr", "ua", "b", 1103515245, 12345))

    def add_strdec(self, prof: StrDecProfile) -> None:
        self.strdecs[f"{prof.simple_name}.{prof.method_name}"] = prof
        self.strdecs[f"{prof.class_fqn}.{prof.method_name}"] = prof

    def add_strcat(self, prof: StrCatProfile) -> None:
        self.strcats[f"{prof.simple_name}.{prof.method_name}"] = prof
        self.strcats[f"{prof.class_fqn}.{prof.method_name}"] = prof

    def discover_from_sources(self, java_files: Sequence[Path]) -> None:
        """Scan decompiled Java classes to dynamically learn StrDec and StrCat parameters."""
        for path in java_files:
            try:
                text = path.read_text("utf-8", errors="replace")
            except OSError:
                continue
            pkg_m = re.search(r"^\s*package\s+([\w.]+)\s*;", text, re.MULTILINE)
            cls_m = re.search(r"\bclass\s+([A-Za-z_$][\w$]*)\b", text)
            if not cls_m:
                continue
            pkg = pkg_m.group(1) if pkg_m else ""
            cls_name = cls_m.group(1)
            fqn = f"{pkg}.{cls_name}" if pkg else cls_name

            m_dec = self.STRDEC_SIGNATURE_RE.search(text)
            if m_dec and "Base64.getDecoder().decode" in text:
                mul = to_int32(int(m_dec.group(1), 0))
                sxor = to_int32(int(m_dec.group(2), 0))
                meth_m = re.search(
                    r"public\s+static\s+String\s+(\w+)\s*\(\s*String\s+\w+\s*,\s*int\s+\w+\s*,\s*int\s+\w+\s*\)",
                    text,
                )
                meth = meth_m.group(1) if meth_m else "d"
                self.add_strdec(StrDecProfile(fqn, cls_name, pkg, meth, mul, sxor))
                self.decryptor_files.add(path)
                continue

            m_cat = self.STRCAT_SIGNATURE_RE.search(text)
            if m_cat:
                meth = m_cat.group(1)
                lmul = to_int32(int(m_cat.group(2), 0))
                ladd = to_int32(int(m_cat.group(3), 0))
                self.add_strcat(StrCatProfile(fqn, cls_name, pkg, meth, lmul, ladd))
                self.decryptor_files.add(path)

    @staticmethod
    def decrypt_strdec(b64: str, k1: int, k2: int, prof: StrDecProfile) -> str:
        buf = bytearray(base64.b64decode(b64))
        n = len(buf)
        if n == 0:
            return ""
        n7 = to_int32(k1 * 31 + k2)
        n8 = to_int32(n7 ^ prof.seed_xor)
        for i in range(n - 1, -1, -1):
            n8 = to_int32(n8 * prof.default_mul + prof.step1_add)
            buf[i] = (buf[i] - ((n8 & 0xFFFFFFFF) >> 19)) & 0xFF

        idx = n - 2 - (n & 1)
        while idx >= 0:
            swap_idx = (idx + 1 ^ ((n7 & 0xFFFFFFFF) >> 8)) % n
            buf[idx], buf[swap_idx] = buf[swap_idx], buf[idx]
            idx -= 2

        state = n7
        for i in range(n):
            state = to_int32(state * prof.default_mul + prof.step3_add)
            h = state ^ ((state & 0xFFFFFFFF) >> 16)
            h = to_int32(h * prof.mix1)
            h ^= (h & 0xFFFFFFFF) >> 15
            h = to_int32(h * prof.mix2)
            h ^= (h & 0xFFFFFFFF) >> 16
            key_byte = (h ^ ((n7 & 0xFFFFFFFF) >> ((i & 3) << 3))) & 0xFF
            buf[i] ^= key_byte

        return buf.decode("utf-8")

    @staticmethod
    def decrypt_strcat(b64: str, seed: int, prof: StrCatProfile) -> str:
        buf = bytearray(base64.b64decode(b64))
        state = to_int32(seed)
        seed_u = seed & 0xFFFFFFFF
        for i in range(len(buf)):
            state = to_int32(state * prof.lcg_mul + prof.lcg_add)
            mask = ((state & 0xFFFFFFFF) >> 16) ^ ((seed_u >> ((i & 3) << 3)) & 0xFF)
            buf[i] ^= mask & 0xFF
        return buf.decode("utf-8")


# ==============================================================================
# Stage 4: Java Constant Expression Evaluator & Precedence-Safe Folder
# ==============================================================================

class JavaIntEvaluator:
    """Evaluates constant 32-bit int / 64-bit long Java expressions accurately."""

    AST_OPS = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.BitXor: operator.xor,
        ast.BitAnd: operator.and_,
        ast.BitOr: operator.or_,
        ast.LShift: operator.lshift,
        ast.RShift: operator.rshift,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
        ast.Invert: operator.invert,
    }

    @classmethod
    def eval_seed_expr(cls, expr_str: str) -> Optional[int]:
        """Evaluate integer seed expressions used in decryptor calls (32-bit signed)."""
        try:
            s = expr_str.strip()
            # Strip integer L/l suffix ONLY — never touch hex digits F/D!
            s = re.sub(r"\b(0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)[Ll]\b", r"\1", s)
            # Support Java unsigned right shift >>> by rewriting to custom helper if present
            if ">>>" in s:
                res = cls.eval_token_expr(JavaLexer.tokenize(expr_str))
                return res[0] if res is not None else None
            tree = ast.parse(s, mode="eval")

            def _eval(node: ast.AST) -> int:
                if isinstance(node, ast.Expression):
                    return _eval(node.body)
                if isinstance(node, ast.Constant) and isinstance(node.value, int):
                    return node.value
                if isinstance(node, ast.UnaryOp) and type(node.op) in cls.AST_OPS:
                    return to_int32(cls.AST_OPS[type(node.op)](_eval(node.operand)))
                if isinstance(node, ast.BinOp) and type(node.op) in cls.AST_OPS:
                    left = _eval(node.left)
                    right = _eval(node.right)
                    if isinstance(node.op, ast.LShift):
                        return java_lshift32(left, right)
                    if isinstance(node.op, ast.RShift):
                        return java_rshift32(left, right)
                    return to_int32(cls.AST_OPS[type(node.op)](left, right))
                raise ValueError(f"Unsupported AST node: {node}")

            return to_int32(_eval(tree))
        except Exception:
            return None

    @classmethod
    def eval_token_expr(cls, toks: Sequence[Token]) -> Optional[Tuple[int, bool]]:
        """
        Recursive-descent parser for Java constant integer/long expressions.
        Returns (value, is_long) or None if non-constant / floating-point / invalid.
        """
        stream = [t for t in toks if t.kind not in ("WS", "NL", "COMMENT")]
        if not stream:
            return None
        pos = 0
        n = len(stream)

        def peek() -> Optional[Token]:
            return stream[pos] if pos < n else None

        def consume() -> Token:
            nonlocal pos
            t = stream[pos]
            pos += 1
            return t

        def cast_width(val: int, is_long: bool) -> int:
            return to_int64(val) if is_long else to_int32(val)

        def parse_bitor() -> Tuple[int, bool]:
            v, l = parse_bitxor()
            while peek() and peek().kind == "OP" and peek().text == "|":
                consume()
                rv, rl = parse_bitxor()
                l = l or rl
                v = cast_width(v | rv, l)
            return v, l

        def parse_bitxor() -> Tuple[int, bool]:
            v, l = parse_bitand()
            while peek() and peek().kind == "OP" and peek().text == "^":
                consume()
                rv, rl = parse_bitand()
                l = l or rl
                v = cast_width(v ^ rv, l)
            return v, l

        def parse_bitand() -> Tuple[int, bool]:
            v, l = parse_shift()
            while peek() and peek().kind == "OP" and peek().text == "&":
                consume()
                rv, rl = parse_shift()
                l = l or rl
                v = cast_width(v & rv, l)
            return v, l

        def parse_shift() -> Tuple[int, bool]:
            v, l = parse_add()
            while peek() and peek().kind == "OP" and peek().text in ("<<", ">>", ">>>"):
                op = consume().text
                rv, _ = parse_add()
                if op == "<<":
                    v = java_lshift64(v, rv) if l else java_lshift32(v, rv)
                elif op == ">>":
                    v = java_rshift64(v, rv) if l else java_rshift32(v, rv)
                else:
                    v = java_urshift64(v, rv) if l else java_urshift32(v, rv)
            return v, l

        def parse_add() -> Tuple[int, bool]:
            v, l = parse_mul()
            while peek() and peek().kind == "OP" and peek().text in ("+", "-"):
                op = consume().text
                rv, rl = parse_mul()
                l = l or rl
                v = cast_width(v + rv if op == "+" else v - rv, l)
            return v, l

        def parse_mul() -> Tuple[int, bool]:
            v, l = parse_unary()
            while peek() and peek().kind == "OP" and peek().text == "*":
                consume()
                rv, rl = parse_unary()
                l = l or rl
                v = cast_width(v * rv, l)
            return v, l

        def parse_unary() -> Tuple[int, bool]:
            t = peek()
            if t and t.kind == "OP" and t.text in ("+", "-", "~"):
                op = consume().text
                v, l = parse_unary()
                if op == "-":
                    return cast_width(-v, l), l
                if op == "~":
                    return cast_width(~v, l), l
                return v, l
            return parse_primary()

        def parse_primary() -> Tuple[int, bool]:
            t = peek()
            if not t:
                raise ValueError("Unexpected EOF")
            if t.kind == "SEP" and t.text == "(":
                consume()
                v, l = parse_bitor()
                ct = peek()
                if not ct or ct.kind != "SEP" or ct.text != ")":
                    raise ValueError("Unbalanced paren")
                consume()
                return v, l
            if t.kind == "NUMBER":
                consume()
                raw = t.text.replace("_", "")
                if "." in raw or raw[-1] in "fFdD" or (
                    not raw.lower().startswith("0x") and ("e" in raw or "E" in raw)
                ):
                    raise ValueError("Non-integer literal")
                is_long = raw.endswith(("L", "l"))
                num_s = raw[:-1] if is_long else raw
                if num_s.lower().startswith("0x"):
                    val = int(num_s, 16)
                elif num_s.lower().startswith("0b"):
                    val = int(num_s, 2)
                elif len(num_s) > 1 and num_s.startswith("0") and all("0" <= c <= "7" for c in num_s):
                    val = int(num_s, 8)
                else:
                    val = int(num_s, 10)
                return cast_width(val, is_long), is_long
            raise ValueError(f"Non-constant token: {t}")

        try:
            res_val, res_long = parse_bitor()
            if pos != n:
                return None
            return res_val, res_long
        except ValueError:
            return None


class ConstantExpressionFolder:
    """
    Replaces obfuscated constant arithmetic/bitwise expressions with folded literals
    while strictly respecting Java operator precedence and associativity boundaries.
    """

    LOW_PRECEDENCE_PREV: Set[str] = {
        "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=",
        "==", "!=", "<", "<=", ">", ">=", "&&", "||", "?", ":", "->",
    }
    LOW_PRECEDENCE_NEXT: Set[str] = {
        "==", "!=", "<", "<=", ">", ">=", "&&", "||", "?", ":",
    }
    EXPR_SEPS_PREV: Set[str] = {"(", "[", "{", ",", ";", ":"}
    EXPR_SEPS_NEXT: Set[str] = {")", "]", "}", ",", ";", ":"}
    ALLOWED_KINDS: Set[str] = {"NUMBER"}
    ALLOWED_OPS: Set[str] = {"+", "-", "*", "&", "|", "^", "<<", ">>", ">>>", "~"}

    @staticmethod
    def format_folded(val: int, is_long: bool, had_hex: bool) -> str:
        if is_long:
            if had_hex and (val < -100000 or val > 1000000):
                return f"0x{val & 0xFFFFFFFFFFFFFFFF:X}L"
            return f"{val}L"
        if had_hex and (val < -65536 or val >= 0x01000000):
            return f"0x{val & 0xFFFFFFFF:08X}"
        return str(val)

    @classmethod
    def _is_safe_left_boundary(cls, prev_tok: Optional[Token]) -> bool:
        if prev_tok is None:
            return True
        if prev_tok.kind == "SEP":
            return prev_tok.text in cls.EXPR_SEPS_PREV
        if prev_tok.kind == "OP":
            return prev_tok.text in cls.LOW_PRECEDENCE_PREV
        if prev_tok.kind == "IDENT":
            return prev_tok.text in ("return", "yield", "case", "throw")
        return False

    @classmethod
    def _is_safe_right_boundary(cls, next_tok: Optional[Token]) -> bool:
        if next_tok is None:
            return True
        if next_tok.kind == "SEP":
            return next_tok.text in cls.EXPR_SEPS_NEXT
        if next_tok.kind == "OP":
            return next_tok.text in cls.LOW_PRECEDENCE_NEXT
        return False

    @classmethod
    def _looks_obfuscated(cls, span_tokens: Sequence[Token]) -> bool:
        num_count = sum(1 for t in span_tokens if t.kind == "NUMBER")
        if num_count < 2:
            return False
        has_xor = any(t.kind == "OP" and t.text == "^" for t in span_tokens)
        if has_xor:
            return True
        for t in span_tokens:
            if t.kind == "NUMBER":
                raw = t.text.rstrip("lL")
                if raw.lower().startswith("0x") and len(raw) >= 6:
                    return True
                if raw.isdigit() and len(raw) >= 6:
                    return True
        return False

    @classmethod
    def fold_source(cls, text: str) -> Tuple[str, int]:
        tokens = JavaLexer.tokenize(text)
        sig_indices = [i for i, t in enumerate(tokens) if t.kind not in ("WS", "NL", "COMMENT")]
        if not sig_indices:
            return text, 0

        replacements: List[Tuple[int, int, str]] = []
        idx = 0
        m = len(sig_indices)
        while idx < m:
            tok = tokens[sig_indices[idx]]
            prev_tok = tokens[sig_indices[idx - 1]] if idx > 0 else None

            can_start = (
                tok.kind == "NUMBER"
                or (tok.kind == "OP" and tok.text in ("-", "+", "~"))
                or (tok.kind == "SEP" and tok.text == "(")
            )
            if not can_start or not cls._is_safe_left_boundary(prev_tok):
                idx += 1
                continue

            # Greedily consume maximal balanced candidate expression span
            j = idx
            depth = 0
            saw_number = False
            valid_span = True
            while j < m:
                ct = tokens[sig_indices[j]]
                if ct.kind == "NUMBER":
                    saw_number = True
                elif ct.kind == "SEP" and ct.text == "(":
                    depth += 1
                elif ct.kind == "SEP" and ct.text == ")":
                    if depth == 0:
                        break
                    depth -= 1
                elif ct.kind == "OP" and ct.text in cls.ALLOWED_OPS:
                    pass
                else:
                    if depth > 0:
                        valid_span = False
                    break
                j += 1

            if valid_span and depth == 0 and saw_number and j > idx + 1:
                next_tok = tokens[sig_indices[j]] if j < m else None
                if cls._is_safe_right_boundary(next_tok):
                    span_toks = [tokens[sig_indices[k]] for k in range(idx, j)]
                    # Avoid folding clean intentional hex/RGBA bitmasks like 0xFF << 24 | 0x00
                    if cls._looks_obfuscated(span_toks):
                        evaluated = JavaIntEvaluator.eval_token_expr(span_toks)
                        if evaluated is not None:
                            val, is_long = evaluated
                            had_hex = any(
                                t.kind == "NUMBER" and t.text.lower().startswith("0x")
                                for t in span_toks
                            )
                            folded = cls.format_folded(val, is_long, had_hex)
                            char_start = tokens[sig_indices[idx]].start
                            char_end = tokens[sig_indices[j - 1]].end
                            replacements.append((char_start, char_end, folded))
                            idx = j
                            continue
            idx += 1

        if not replacements:
            return text, 0

        out: List[str] = []
        cursor = 0
        for s, e, rep in replacements:
            out.append(text[cursor:s])
            out.append(rep)
            cursor = e
        out.append(text[cursor:])
        return "".join(out), len(replacements)


# ==============================================================================
# Stage 5: String & Invokedynamic Deobfuscator
# ==============================================================================

class StringAndIndyDeobfuscator:
    """Decrypts StrDec calls and resolves invokedynamic StringConcatFactory calls."""

    OBJ_ARRAY_RE = re.compile(
        r'new\s+Object\s*\[\s*\]\s*\{\s*"((?:\\.|[^"\\])*)"\s*,\s*(.+?)\s*\}\s*$',
        re.DOTALL,
    )

    def __init__(self, registry: StringCipherRegistry, unescape_utf8: bool = True) -> None:
        self.registry = registry
        self.unescape_utf8 = unescape_utf8
        # Build regex matching any discovered decryptor call: e.g. \b(rp|ms|mr)\.d\(
        cipher_names = sorted({p.split(".")[0] for p in registry.strdecs if "." in p})
        # Also support qualified package.Class.method(
        fqn_calls = sorted({p for p in registry.strdecs if p.count(".") >= 2})
        parts = [rf"\b{re.escape(c)}\.\w+\(" for c in cipher_names] + [
            rf"\b{re.escape(f)}\(" for f in fqn_calls
        ]
        self.cipher_call_re = re.compile("|".join(parts))

        cat_names = sorted({p.split(".")[0] for p in registry.strcats if "." in p})
        cat_fqns = sorted({p for p in registry.strcats if p.count(".") >= 2})
        cparts = [rf"(?:\(String\)\s*\(\s*Object\s*\)\s*)?\b{re.escape(c)}\.\w+\(" for c in cat_names] + [
            rf"(?:\(String\)\s*\(\s*Object\s*\)\s*)?\b{re.escape(f)}\(" for f in cat_fqns
        ]
        self.concat_call_re = re.compile("|".join(cparts))

    @staticmethod
    def parse_top_level_args(call_inside: str) -> List[str]:
        args: List[str] = []
        cur: List[str] = []
        depth = 0
        in_str = False
        in_chr = False
        esc = False
        for ch in call_inside:
            if in_str:
                cur.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif in_chr:
                cur.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == "'":
                    in_chr = False
            else:
                if ch == '"':
                    in_str = True
                    cur.append(ch)
                elif ch == "'":
                    in_chr = True
                    cur.append(ch)
                elif ch in "({[":
                    depth += 1
                    cur.append(ch)
                elif ch in ")}]":
                    depth -= 1
                    cur.append(ch)
                elif ch == "," and depth == 0:
                    args.append("".join(cur).strip())
                    cur = []
                else:
                    cur.append(ch)
        tail = "".join(cur).strip()
        if tail:
            args.append(tail)
        return args

    @staticmethod
    def find_matching_paren(text: str, open_paren_idx: int) -> Optional[int]:
        """Given index immediately after '(', find index immediately after matching ')'."""
        pos = open_paren_idx
        n = len(text)
        depth = 1
        in_str = False
        in_chr = False
        esc = False
        while pos < n and depth > 0:
            ch = text[pos]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif in_chr:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == "'":
                    in_chr = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "'":
                    in_chr = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            pos += 1
        return pos if depth == 0 else None

    def _build_concat_expr(self, recipe: str, vars_list: Sequence[str]) -> str:
        parts = recipe.split("\x01")
        expr_parts: List[str] = []
        for idx, lit in enumerate(parts):
            if lit:
                expr_parts.append(java_string_escape(lit, self.unescape_utf8))
            if idx < len(vars_list):
                v = vars_list[idx].strip()
                # Strip redundant cast prefixes like (String)(...) when unambiguous or wrap complex ops
                if any(op in v for op in ("?", "+", "-", "<<", ">>", "&", "|", "^")):
                    if not (v.startswith("(") and v.endswith(")")):
                        v = f"({v})"
                expr_parts.append(v)
        if not expr_parts:
            return '""'
        if len(expr_parts) == 1:
            # Ensure String type if single arg isn't already a string literal
            if not expr_parts[0].startswith('"'):
                return f'String.valueOf({expr_parts[0]})'
            return expr_parts[0]
        # In Java, '+' is string concat only if one of the first two operands is a String.
        if not expr_parts[0].startswith('"') and not expr_parts[1].startswith('"'):
            expr_parts[0] = f'"" + {expr_parts[0]}'
        return " + ".join(expr_parts)

    def deobfuscate_source(self, text: str, filepath: Optional[Path] = None) -> Tuple[str, int, int]:
        if filepath and filepath in self.registry.decryptor_files:
            return text, 0, 0

        cipher_count = 0
        concat_count = 0

        # Pass A: Decrypt StrDec calls (rp.d / ms.d / mr.d / discovered profiles)
        out: List[str] = []
        cursor = 0
        while True:
            m = self.cipher_call_re.search(text, cursor)
            if not m:
                out.append(text[cursor:])
                break
            out.append(text[cursor:m.start()])
            call_hdr = m.group(0)[:-1]  # strip '('
            end_pos = self.find_matching_paren(text, m.end())
            if end_pos is None:
                out.append(text[m.start():m.end()])
                cursor = m.end()
                continue

            prof = self.registry.strdecs.get(call_hdr)
            if not prof and "." in call_hdr:
                short_key = ".".join(call_hdr.split(".")[-2:])
                prof = self.registry.strdecs.get(short_key)

            replaced = False
            if prof:
                inside = text[m.end():end_pos - 1]
                args = self.parse_top_level_args(inside)
                if len(args) >= 2 and args[0].startswith('"') and args[0].endswith('"'):
                    b64_str = unescape_java_string_content(args[0][1:-1])
                    k1 = JavaIntEvaluator.eval_seed_expr(args[1])
                    k2 = JavaIntEvaluator.eval_seed_expr(args[2]) if len(args) > 2 else 0
                    if k1 is not None and k2 is not None:
                        try:
                            plain = self.registry.decrypt_strdec(b64_str, k1, k2, prof)
                            out.append(java_string_escape(plain, self.unescape_utf8))
                            cipher_count += 1
                            replaced = True
                        except Exception:
                            pass
            if not replaced:
                out.append(text[m.start():end_pos])
            cursor = end_pos

        text = "".join(out)

        # Pass B: Resolve invokedynamic StringConcatFactory calls (innermost-first)
        while True:
            matches = list(self.concat_call_re.finditer(text))
            if not matches:
                break
            chosen_match = None
            chosen_end = None
            for m in reversed(matches):
                end_pos = self.find_matching_paren(text, m.end())
                if end_pos is None:
                    continue
                has_nested = any(m.start() < om.start() < end_pos for om in matches if om is not m)
                if not has_nested:
                    chosen_match = m
                    chosen_end = end_pos
                    break
            if chosen_match is None or chosen_end is None:
                break

            raw_hdr = chosen_match.group(0)[:-1]
            # Strip optional (String)(Object) prefix to get method key
            hdr = re.sub(r"^\(String\)\s*\(\s*Object\s*\)\s*", "", raw_hdr).strip()
            cat_prof = self.registry.strcats.get(hdr)
            if not cat_prof and "." in hdr:
                cat_prof = self.registry.strcats.get(".".join(hdr.split(".")[-2:]))

            inside = text[chosen_match.end():chosen_end - 1]
            args = self.parse_top_level_args(inside)
            replaced = False
            if cat_prof and len(args) >= 2 and "makeConcatWithConstants" in args[0]:
                arr_m = self.OBJ_ARRAY_RE.match(args[1].strip())
                if arr_m:
                    b64_str = unescape_java_string_content(arr_m.group(1))
                    seed = JavaIntEvaluator.eval_seed_expr(arr_m.group(2))
                    if seed is not None:
                        try:
                            recipe = self.registry.decrypt_strcat(b64_str, seed, cat_prof)
                            concat_expr = self._build_concat_expr(recipe, args[2:])
                            text = text[:chosen_match.start()] + f"({concat_expr})" + text[chosen_end:]
                            concat_count += 1
                            replaced = True
                        except Exception:
                            pass
            if not replaced:
                break

        # Pass C: Clean up CFR CallSite artifacts left by invokedynamic decompilation
        if concat_count > 0:
            text = re.sub(r"\bOptional<CallSite>\b", "Optional<String>", text)
            text = re.sub(r"\bCallSite\s+([A-Za-z_$][\w$]*)\b", r"String \1", text)
            text = re.sub(r"\(String\)\s*\(\s*Object\s*\)\s*([A-Za-z_$][\w$]*)", r"\1", text)

        return text, cipher_count, concat_count


# ==============================================================================
# Stage 6: Symbolic Opaque Predicate & Watermark Eliminator
# ==============================================================================

class OpaquePredicateEliminator:
    """
    Symbolically verifies and eliminates dead `if (<always_false>) { throw null; }`
    opaque predicates, unused local seed copies, `_xxxx` seed fields, and 40-hex
    synthetic obfuscator watermark strings.
    """

    SEED_FIELD_RE = re.compile(
        r"^[ \t]*private\s+static\s+int\s+(_[0-9a-fA-F]{1,4})\s*;[ \t]*\r?\n?",
        re.MULTILINE,
    )
    WATERMARK_FIELD_RE = re.compile(
        r'^[ \t]*(?:(?:private|public|protected)\s+)?static\s+final\s+/\*\s*synthetic\s*\*/\s+'
        r'String\s+[A-Za-z_$][\w$]*\s*=\s*"[0-9a-fA-F]{40}"\s*;[ \t]*\r?\n?',
        re.MULTILINE,
    )
    ALIAS_DECL_RE = re.compile(
        r"^[ \t]*int\s+([A-Za-z_$][\w$]*)\s*=\s*(_[0-9a-fA-F]{1,4})\s*;[ \t]*\r?\n?",
        re.MULTILINE,
    )
    THROW_NULL_BLOCK_RE = re.compile(
        r"(?P<indent>[ \t]*)if\s*\((?P<cond>[^;{}\n]+)\)\s*\{\s*throw\s+null\s*;\s*\}[ \t]*\r?\n?"
    )

    TEST_SEED_VALUES: Tuple[int, ...] = (
        0, 1, -1, 2, -2, 7, -8, 0x7FFFFFFF, -0x80000000, 0x5A5A5A5A
    )

    @classmethod
    def _eval_opaque_condition(cls, cond_str: str, allowed_vars: Set[str]) -> Optional[bool]:
        """
        Verify a boolean condition is ALWAYS FALSE across all signed 32-bit values
        of the opaque seed variable(s). Returns False if proven always-false, else None.
        """
        toks = [t for t in JavaLexer.tokenize(cond_str) if t.kind not in ("WS", "NL", "COMMENT")]
        if not toks:
            return None
        for t in toks:
            if t.kind == "IDENT" and t.text not in allowed_vars:
                return None
            if t.kind in ("STRING", "CHAR", "TEXTBLOCK"):
                return None

        # Translate Java operators to Python integer-width expressions
        py_expr = cond_str.strip()
        # Reject complex constructs we don't model directly
        if any(bad in py_expr for bad in ("?", ":", "&&", "||", ".", "[")):
            return None

        # Parse and evaluate using Python AST with exact 32-bit int32 wrapping
        try:
            # Handle >>> via custom rewrite or reject if needed
            if ">>>" in py_expr:
                return None
            tree = ast.parse(py_expr, mode="eval")
        except SyntaxError:
            return None

        def eval_node(node: ast.AST, env: Dict[str, int]) -> Any:
            if isinstance(node, ast.Expression):
                return eval_node(node.body, env)
            if isinstance(node, ast.Name):
                return env[node.id]
            if isinstance(node, ast.Constant) and isinstance(node.value, int):
                return to_int32(node.value)
            if isinstance(node, ast.UnaryOp):
                v = eval_node(node.operand, env)
                if isinstance(node.op, ast.USub):
                    return to_int32(-v)
                if isinstance(node.op, ast.UAdd):
                    return to_int32(v)
                if isinstance(node.op, ast.Invert):
                    return to_int32(~v)
                raise ValueError("Unsupported unary op")
            if isinstance(node, ast.BinOp):
                lv = eval_node(node.left, env)
                rv = eval_node(node.right, env)
                if isinstance(node.op, ast.Add): return to_int32(lv + rv)
                if isinstance(node.op, ast.Sub): return to_int32(lv - rv)
                if isinstance(node.op, ast.Mult): return to_int32(lv * rv)
                if isinstance(node.op, ast.BitXor): return to_int32(lv ^ rv)
                if isinstance(node.op, ast.BitAnd): return to_int32(lv & rv)
                if isinstance(node.op, ast.BitOr): return to_int32(lv | rv)
                if isinstance(node.op, ast.LShift): return java_lshift32(lv, rv)
                if isinstance(node.op, ast.RShift): return java_rshift32(lv, rv)
                raise ValueError("Unsupported bin op")
            if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
                lv = eval_node(node.left, env)
                rv = eval_node(node.comparators[0], env)
                op = node.ops[0]
                if isinstance(op, ast.Gt): return lv > rv
                if isinstance(op, ast.Lt): return lv < rv
                if isinstance(op, ast.GtE): return lv >= rv
                if isinstance(op, ast.LtE): return lv <= rv
                if isinstance(op, ast.Eq): return lv == rv
                if isinstance(op, ast.NotEq): return lv != rv
                raise ValueError("Unsupported compare op")
            raise ValueError("Unsupported AST node")

        try:
            for val in cls.TEST_SEED_VALUES:
                env = {v: val for v in allowed_vars}
                res = eval_node(tree, env)
                if not isinstance(res, bool) or res is True:
                    return None
            return False
        except Exception:
            return None

    @classmethod
    def clean_source(cls, text: str) -> Tuple[str, int, int]:
        """Eliminate opaque predicates and synthetic watermark/seed fields."""
        seed_vars = set(cls.SEED_FIELD_RE.findall(text))
        alias_vars = {m.group(1) for m in cls.ALIAS_DECL_RE.finditer(text) if m.group(2) in seed_vars}
        allowed_vars = seed_vars | alias_vars

        removed_guards = 0
        removed_meta = 0

        if allowed_vars:
            # Find balanced `if (<cond>) { throw null; }` blocks.
            # Standard regex fails when `<cond>` has nested parentheses, so scan cleanly.
            out: List[str] = []
            pos = 0
            n = len(text)
            if_pat = re.compile(r"(?m)^(?P<indent>[ \t]*)if\s*\(")
            while True:
                m = if_pat.search(text, pos)
                if not m:
                    out.append(text[pos:])
                    break
                cond_end = StringAndIndyDeobfuscator.find_matching_paren(text, m.end())
                if cond_end is None:
                    out.append(text[pos:m.end()])
                    pos = m.end()
                    continue
                cond_str = text[m.end():cond_end - 1]
                tail_m = re.match(r"\s*\{\s*throw\s+null\s*;\s*\}[ \t]*\r?\n?", text[cond_end:])
                if tail_m and cls._eval_opaque_condition(cond_str, allowed_vars) is False:
                    out.append(text[pos:m.start()])
                    pos = cond_end + tail_m.end()
                    removed_guards += 1
                    continue
                out.append(text[pos:m.end()])
                pos = m.end()
            text = "".join(out)

            # Remove orphan `int n = _xxxx;` lines if the alias variable is no longer referenced
            def maybe_drop_alias(m: re.Match[str]) -> str:
                nonlocal removed_guards
                var_name, seed_name = m.group(1), m.group(2)
                if seed_name not in seed_vars:
                    return m.group(0)
                # Count occurrences outside this declaration
                without_decl = text[:m.start()] + text[m.end():]
                if not re.search(rf"\b{re.escape(var_name)}\b", without_decl):
                    removed_guards += 1
                    return ""
                return m.group(0)

            text = cls.ALIAS_DECL_RE.sub(maybe_drop_alias, text)

            # Remove `_xxxx` seed fields if zero references remain outside declaration
            def maybe_drop_seed(m: re.Match[str]) -> str:
                nonlocal removed_meta
                seed_name = m.group(1)
                without_decl = text[:m.start()] + text[m.end():]
                if not re.search(rf"\b{re.escape(seed_name)}\b", without_decl):
                    removed_meta += 1
                    return ""
                return m.group(0)

            text = cls.SEED_FIELD_RE.sub(maybe_drop_seed, text)

        # Remove 40-hex synthetic obfuscator watermark fields
        text, wm_count = cls.WATERMARK_FIELD_RE.subn("", text)
        removed_meta += wm_count

        return text, removed_guards, removed_meta


# ==============================================================================
# Stage 7: Static Constant Lifter, Cross-Class Inliner & Code Polish
# ==============================================================================

class ConstantInlinerAndCleaner:
    """Lifts static-block literals, inlines static final constants, and strips CFR junk."""

    STR_LIT = r'"(?:\\.|[^"\\\n])*"'
    CHR_LIT = r"'(?:\\.|[^'\\\n])+'"
    NUM_LIT = r"-?(?:0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)[LlFfDd]?"
    BOOL_LIT = r"(?:true|false)"
    LITERAL = rf"(?:{STR_LIT}|{CHR_LIT}|{NUM_LIT}|{BOOL_LIT})"
    QUAL_REF = r"(?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*"

    DECL_RE = re.compile(
        r"^[ \t]*(?:(?:private|public|protected)\s+)?static\s+final\s+"
        r"(String|int|long|float|double|boolean|char|short|byte)\s+"
        rf"([A-Za-z_$][\w$]*)\s*=\s*({LITERAL}|{QUAL_REF})\s*;[ \t]*\r?\n?",
        re.MULTILINE,
    )

    SKIP_RE = re.compile(rf"{STR_LIT}|{CHR_LIT}|//[^\n]*|/\*.*?\*/", re.DOTALL)

    JUNK_PATTERNS: Tuple[re.Pattern[str], ...] = (
        re.compile(r"^[ \t]*\*\s*Could not load the following classes:\s*\r?\n(?:[ \t]*\*\s*[^\n]*\r?\n)+", re.M),
        re.compile(r"^[ \t]*//\s*Please report this to the Vineflower.*\r?\n", re.M),
        re.compile(r"^[ \t]*//\s*\$VF:.*\r?\n", re.M),
        re.compile(r"^[ \t]*//\s*src by @.*\r?\n", re.M),
        re.compile(r"^[ \t]*//\s*@pointdlc.*\r?\n", re.M),
        re.compile(r"^[ \t]*Object var\d+\s*=\s*null;\r?\n", re.M),
        re.compile(r"^[ \t]*var\d+\s*=\s*null;\r?\n", re.M),
        re.compile(r"^[ \t]*/\*\s*\r?\n[ \t]*\*\s*WARNING - Removed try catching itself.*\r?\n[ \t]*\*/\s*\r?\n", re.M),
    )
    EMPTY_STATIC_RE = re.compile(r"\n[ \t]*static\s*\{\s*\}[ \t]*\r?\n")

    @classmethod
    def split_code(cls, text: str) -> Iterable[Tuple[bool, str]]:
        pos = 0
        for m in cls.SKIP_RE.finditer(text):
            if m.start() > pos:
                yield True, text[pos:m.start()]
            yield False, m.group(0)
            pos = m.end()
        if pos < len(text):
            yield True, text[pos:]

    @classmethod
    def map_code(cls, text: str, fn: Callable[[str], str]) -> str:
        return "".join(fn(chunk) if is_code else chunk for is_code, chunk in cls.split_code(text))

    @classmethod
    def lift_static_literals(cls, text: str) -> Tuple[str, int]:
        """
        Lift `private static final Type FIELD;` + `static { FIELD = <literal>; }`
        into `private static final Type FIELD = <literal>;` when unambiguous.
        """
        uninit_re = re.compile(
            r"^(?P<indent>[ \t]*)(?P<mods>(?:(?:private|public|protected)\s+)?static\s+final\s+"
            r"(?:String|int|long|float|double|boolean|char|short|byte))\s+"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*;[ \t]*\r?\n",
            re.MULTILINE,
        )
        uninit_fields = {m.group("name"): m for m in uninit_re.finditer(text)}
        if not uninit_fields:
            return text, 0

        static_block_re = re.compile(r"(?m)^([ \t]*)static\s*\{")
        m_sb = static_block_re.search(text)
        if not m_sb:
            return text, 0

        # Find matching brace of static {} block
        open_idx = m_sb.end() - 1
        pos = open_idx + 1
        depth = 1
        in_str = False
        esc = False
        while pos < len(text) and depth > 0:
            ch = text[pos]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
            pos += 1
        if depth != 0:
            return text, 0

        block_body = text[open_idx + 1:pos - 1]
        assign_re = re.compile(
            rf"^[ \t]*([A-Za-z_$][\w$]*)\s*=\s*({cls.LITERAL})\s*;[ \t]*\r?\n?",
            re.MULTILINE,
        )
        lifted_vals: Dict[str, str] = {}

        def strip_assign(m: re.Match[str]) -> str:
            fname, lit = m.group(1), m.group(2)
            if fname in uninit_fields and fname not in lifted_vals:
                lifted_vals[fname] = lit
                return ""
            return m.group(0)

        new_block_body = assign_re.sub(strip_assign, block_body)
        if not lifted_vals:
            return text, 0

        text = text[:open_idx + 1] + new_block_body + text[pos - 1:]
        # Insert literal initializers into field declarations
        def fill_decl(m: re.Match[str]) -> str:
            name = m.group("name")
            if name in lifted_vals:
                return f"{m.group('indent')}{m.group('mods')} {name} = {lifted_vals[name]};\n"
            return m.group(0)

        text = uninit_re.sub(fill_decl, text)
        return text, len(lifted_vals)

    @classmethod
    def clean_junk_and_imports(cls, text: str, decryptor_fqns: Set[str]) -> Tuple[str, int]:
        removed = 0
        for pat in cls.JUNK_PATTERNS:
            text, k = pat.subn("", text)
            removed += k
        text, k = cls.EMPTY_STATIC_RE.subn("\n", text)
        removed += k

        # Remove unused decryptor imports (e.g. import cf.rp;, import ua.ptr;, import java.lang.invoke.CallSite;)
        for fqn in decryptor_fqns:
            simple = fqn.split(".")[-1]
            imp_re = re.compile(rf"^[ \t]*import\s+{re.escape(fqn)}\s*;\s*\r?\n", re.MULTILINE)
            if imp_re.search(text):
                without_imp = imp_re.sub("", text)
                if not re.search(rf"\b{re.escape(simple)}\b", without_imp):
                    text = without_imp
                    removed += 1

        if "import java.lang.invoke.CallSite;" in text:
            without_cs = re.sub(r"^[ \t]*import\s+java\.lang\.invoke\.CallSite\s*;\s*\r?\n", "", text, flags=re.M)
            if not re.search(r"\bCallSite\b", without_cs):
                text = without_cs
                removed += 1

        # Unescape remaining unicode escapes in string literals (outside decryptor calls)
        def unesc_str_match(m: re.Match[str]) -> str:
            raw_lit = m.group(0)
            if "\\u" not in raw_lit:
                return raw_lit
            inner = unescape_java_string_content(raw_lit[1:-1])
            return java_string_escape(inner, unescape_utf8=True)

        text = re.sub(cls.STR_LIT, unesc_str_match, text)
        # Collapse excessive blank lines
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text, removed

    def __init__(self) -> None:
        self.local: Dict[Path, Dict[str, str]] = {}
        self.raw: Dict[Path, Dict[str, Tuple[str, str]]] = {}
        self.global_defs: Dict[str, List[Tuple[Path, str]]] = defaultdict(list)
        self.inlined_count = 0
        self.dropped_count = 0

    def collect_constants(self, texts: Dict[Path, str]) -> None:
        for path, text in texts.items():
            raw_map: Dict[str, Tuple[str, str]] = {}
            for m in self.DECL_RE.finditer(text):
                raw_map[m.group(2)] = (m.group(1), m.group(3).strip())
            self.raw[path] = raw_map

        name_to_raw: Dict[str, List[Tuple[Path, str, str]]] = defaultdict(list)
        for path, raw_map in self.raw.items():
            for name, (typ, rhs) in raw_map.items():
                name_to_raw[name].append((path, typ, rhs))

        lit_re = re.compile(rf"^{self.LITERAL}$", re.DOTALL)

        def resolve(path: Path, name: str, depth: int = 0) -> Optional[str]:
            if depth > 12:
                return None
            ent = self.raw.get(path, {}).get(name)
            if ent is None:
                defs = name_to_raw.get(name, [])
                if len(defs) != 1:
                    return None
                path, _, rhs = defs[0]
            else:
                _, rhs = ent
            if lit_re.match(rhs):
                return rhs
            ref = rhs.split(".")[-1]
            return resolve(path, ref, depth + 1)

        for path, raw_map in self.raw.items():
            loc: Dict[str, str] = {}
            for name in raw_map:
                val = resolve(path, name)
                if val is not None:
                    if val.startswith("-"):
                        val = f"({val})"
                    loc[name] = val
                    self.global_defs[name].append((path, val))
            self.local[path] = loc

    def inline_constants(self, path: Path, text: str) -> str:
        loc = self.local.get(path, {})
        glob = {name: defs[0][1] for name, defs in self.global_defs.items() if len(defs) == 1}
        names = set(loc) | set(glob)
        if not names:
            return text

        decls: List[str] = []

        def hide_decl(m: re.Match[str]) -> str:
            decls.append(m.group(0))
            return f"\x00DECL{len(decls) - 1}\x00"

        text = self.DECL_RE.sub(hide_decl, text)
        ref_re = re.compile(
            r"(?<![\w$.])((?:[A-Za-z_$][\w$]*\.)*)([A-Za-z_$][\w$]*)\b(?!\s*\()"
        )

        def repl_chunk(chunk: str) -> str:
            def sub_ref(m: re.Match[str]) -> str:
                prefix, name = m.group(1), m.group(2)
                if name not in names:
                    return m.group(0)
                if prefix:
                    last = prefix.rstrip(".").split(".")[-1]
                    if last == "this" or not last[:1].isupper():
                        return m.group(0)
                    val = glob.get(name) or loc.get(name)
                else:
                    val = loc.get(name) or glob.get(name)
                if val is None:
                    return m.group(0)
                self.inlined_count += 1
                return val

            return ref_re.sub(sub_ref, chunk)

        text = self.map_code(text, repl_chunk)
        return re.sub(r"\x00DECL(\d+)\x00", lambda m: decls[int(m.group(1))], text)

    def drop_unused_constants(self, texts: Dict[Path, str]) -> Dict[Path, str]:
        token_counts: Dict[str, int] = defaultdict(int)
        tok_re = re.compile(r"[A-Za-z_$][\w$]*")
        for text in texts.values():
            for is_code, chunk in self.split_code(text):
                if is_code:
                    for word in tok_re.findall(chunk):
                        token_counts[word] += 1

        out: Dict[Path, str] = {}
        for path, text in texts.items():
            loc = self.local.get(path, {})

            def maybe_drop(m: re.Match[str]) -> str:
                name = m.group(2)
                if name in loc and token_counts.get(name, 0) <= 1:
                    self.dropped_count += 1
                    return ""
                return m.group(0)

            out[path] = self.DECL_RE.sub(maybe_drop, text)
        return out


# ==============================================================================
# Stage 8: SourceFile-Based Class, Package & Mod Config Remapper
# ==============================================================================

@dataclass
class RemapEntry:
    old_internal: str       # e.g. "ad/bzgn"
    old_pkg: str            # e.g. "ad"
    old_simple: str         # e.g. "bzgn"
    new_pkg: str            # e.g. "com.furryhook.alts"
    new_simple: str         # e.g. "Alt"
    is_dead: bool = False
    reason: str = ""

    @property
    def old_fqn(self) -> str:
        return f"{self.old_pkg}.{self.old_simple}" if self.old_pkg else self.old_simple

    @property
    def new_fqn(self) -> str:
        return f"{self.new_pkg}.{self.new_simple}" if self.new_pkg else self.new_simple


class ClassAndPackageRemapper:
    """
    Maps obfuscated classes to their original SourceFile names & semantic packages,
    eliminates dead decoy/decryptor classes, rewrites Java tokens safely, and updates
    fabric.mod.json and furryhook.mixins.json.
    """

    DECOY_FIELD_RE = re.compile(r"^\s*private\s+(?:int|String)\s+a\d+\s*;\s*$", re.M)

    def __init__(self, use_semantic_packages: bool = True) -> None:
        self.use_semantic_packages = use_semantic_packages
        self.entries: Dict[str, RemapEntry] = {}  # old_internal -> RemapEntry

    @staticmethod
    def is_decoy_class(text: str, meta: Optional[ClassMetadata]) -> bool:
        if meta and meta.source_file == "a.java":
            return True
        # Check if class body after stripping watermarks/synthetic fields is trivial decoy
        stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        stripped = re.sub(r"package\s+[\w.]+\s*;", "", stripped)
        stripped = re.sub(r"public\s+class\s+\w+\s*\{", "", stripped)
        stripped = re.sub(r"private\s+void\s+b\d+\s*\(\s*\)\s*\{\s*\}", "", stripped)
        stripped = re.sub(r"private\s+(?:int|String)\s+a\d+\s*;", "", stripped)
        stripped = stripped.strip().rstrip("}").strip()
        return stripped == ""

    def build_mapping(
        self,
        java_texts: Dict[Path, str],
        src_root: Path,
        jar_meta: Dict[str, ClassMetadata],
        decryptor_files: Set[Path],
    ) -> None:
        # First pass: determine candidate simple names from SourceFile
        by_target_pkg_name: Dict[Tuple[str, str], List[Tuple[Path, str, str]]] = defaultdict(list)

        for path, text in sorted(java_texts.items()):
            rel = path.relative_to(src_root).as_posix()
            old_internal = rel[:-5]
            old_pkg = old_internal.rsplit("/", 1)[0] if "/" in old_internal else ""
            old_simple = old_internal.rsplit("/", 1)[-1]
            meta = jar_meta.get(old_internal)

            new_pkg = (
                SEMANTIC_PACKAGE_MAP.get(old_pkg, f"com.furryhook.{old_pkg}" if old_pkg else "com.furryhook")
                if self.use_semantic_packages
                else old_pkg
            )

            if path in decryptor_files:
                self.entries[old_internal] = RemapEntry(
                    old_internal, old_pkg, old_simple, new_pkg, old_simple,
                    is_dead=True, reason="Obfuscator string/concat runtime",
                )
                continue

            if self.is_decoy_class(text, meta):
                # Double check no other class references this simple name
                referenced = any(
                    other_p != path and re.search(rf"\b{re.escape(old_simple)}\b", other_t)
                    for other_p, other_t in java_texts.items()
                )
                if not referenced:
                    self.entries[old_internal] = RemapEntry(
                        old_internal, old_pkg, old_simple, new_pkg, old_simple,
                        is_dead=True, reason="Obfuscator decoy class (a.java)",
                    )
                    continue

            candidate = old_simple
            if meta and meta.source_file and meta.source_file.endswith(".java"):
                sf_base = meta.source_file[:-5]
                if sf_base and sf_base != "a" and sf_base not in JAVA_KEYWORDS:
                    candidate = sf_base

            by_target_pkg_name[(new_pkg, candidate)].append((path, old_internal, text))

        # Second pass: resolve collisions cleanly (e.g., mh/qfia + mh/rfsn -> AntiAfkFeature.java)
        for (new_pkg, candidate), group in by_target_pkg_name.items():
            if len(group) == 1:
                _, old_internal, _ = group[0]
                old_pkg = old_internal.rsplit("/", 1)[0] if "/" in old_internal else ""
                old_simple = old_internal.rsplit("/", 1)[-1]
                self.entries[old_internal] = RemapEntry(old_internal, old_pkg, old_simple, new_pkg, candidate)
            else:
                # Prefer public class or Feature subclass for primary SourceFile name
                scored: List[Tuple[int, Path, str, str]] = []
                for path, old_internal, text in group:
                    old_simple = old_internal.rsplit("/", 1)[-1]
                    score = 0
                    if re.search(rf"\bpublic\s+(?:final\s+)?(?:class|interface|enum|record)\s+{re.escape(old_simple)}\b", text):
                        score += 10
                    if "extends " in text:
                        score += 5
                    scored.append((score, path, old_internal, text))
                scored.sort(key=lambda x: -x[0])

                used: Set[str] = set()
                for idx, (_, _, old_internal, text) in enumerate(scored):
                    old_pkg = old_internal.rsplit("/", 1)[0] if "/" in old_internal else ""
                    old_simple = old_internal.rsplit("/", 1)[-1]
                    if idx == 0:
                        chosen = candidate
                    elif candidate == "AntiAfkFeature" and "elapsedTicks" in text:
                        chosen = "AntiAfkTimer"
                    else:
                        chosen = f"{candidate}_{old_simple}"
                    while chosen in used:
                        chosen += "_alt"
                    used.add(chosen)
                    self.entries[old_internal] = RemapEntry(old_internal, old_pkg, old_simple, new_pkg, chosen)

    def remap_java_source(self, text: str, current_entry: RemapEntry) -> str:
        """Safely rewrite package, imports, declarations, and type identifiers via token stream."""
        active_entries = {e.old_fqn: e for e in self.entries.values() if not e.is_dead}
        by_old_pkg: Dict[str, Dict[str, RemapEntry]] = defaultdict(dict)
        for e in active_entries.values():
            by_old_pkg[e.old_pkg][e.old_simple] = e

        # Track which classes are in scope without qualification in this file:
        # 1) All classes from current package
        in_scope: Dict[str, RemapEntry] = dict(by_old_pkg.get(current_entry.old_pkg, {}))
        # 2) Explicitly imported classes (`import pkg.Cls;` or `import pkg.*;`)
        for m in re.finditer(r"^\s*import\s+(?:static\s+)?([\w.]+)(?:\.(\*)|\.([A-Za-z_$][\w$]*))\s*;", text, re.M):
            pkg_part, star, cls_part = m.group(1), m.group(2), m.group(3)
            if star == "*" and pkg_part in by_old_pkg:
                in_scope.update(by_old_pkg[pkg_part])
            elif cls_part and f"{pkg_part}.{cls_part}" in active_entries:
                in_scope[cls_part] = active_entries[f"{pkg_part}.{cls_part}"]
            elif pkg_part in active_entries:
                # import static pkg.Cls.MEMBER;
                ent = active_entries[pkg_part]
                in_scope[ent.old_simple] = ent

        # Rewrite package declaration and import statements first
        if current_entry.new_pkg:
            text = re.sub(
                rf"^(\s*package\s+){re.escape(current_entry.old_pkg)}(\s*;)",
                rf"\g<1>{current_entry.new_pkg}\2",
                text,
                count=1,
                flags=re.M,
            )

        def repl_import(m: re.Match[str]) -> str:
            prefix, fqn_body, tail = m.group(1), m.group(2), m.group(3)
            if fqn_body in active_entries:
                return f"{prefix}{active_entries[fqn_body].new_fqn}{tail}"
            # Handle static import: pkg.Cls.MEMBER
            parts = fqn_body.rsplit(".", 1)
            if len(parts) == 2 and parts[0] in active_entries:
                return f"{prefix}{active_entries[parts[0]].new_fqn}.{parts[1]}{tail}"
            # Handle wildcard import: pkg.*
            if fqn_body in by_old_pkg:
                first_ent = next(iter(by_old_pkg[fqn_body].values()))
                return f"{prefix}{first_ent.new_pkg}{tail}"
            return m.group(0)

        text = re.sub(
            r"^(\s*import\s+(?:static\s+)?)([\w.]+)((?:\.\*)?\s*;)",
            repl_import,
            text,
            flags=re.M,
        )

        # Token-level replacement for qualified `old_pkg.old_cls` and in-scope `old_cls`
        tokens = JavaLexer.tokenize(text)
        sig_indices = [i for i, t in enumerate(tokens) if t.kind not in ("WS", "NL", "COMMENT")]

        def sig_tok(offset: int) -> Optional[Token]:
            return tokens[sig_indices[offset]] if 0 <= offset < len(sig_indices) else None

        pos = 0
        m_sig = len(sig_indices)
        while pos < m_sig:
            ti = sig_indices[pos]
            tok = tokens[ti]

            # Skip package / import lines (already rewritten above)
            if tok.kind == "IDENT" and tok.text in ("package", "import"):
                while pos < m_sig and not (tokens[sig_indices[pos]].kind == "SEP" and tokens[sig_indices[pos]].text == ";"):
                    pos += 1
                pos += 1
                continue

            # Check qualified reference: old_pkg . old_simple
            if tok.kind == "IDENT" and tok.text in by_old_pkg:
                t1 = sig_tok(pos + 1)
                t2 = sig_tok(pos + 2)
                prev_t = sig_tok(pos - 1)
                if (
                    t1 and t1.kind == "SEP" and t1.text == "."
                    and t2 and t2.kind == "IDENT" and t2.text in by_old_pkg[tok.text]
                    and not (prev_t and prev_t.kind == "SEP" and prev_t.text == ".")
                ):
                    ent = by_old_pkg[tok.text][t2.text]
                    tokens[ti].text = ent.new_pkg
                    tokens[sig_indices[pos + 2]].text = ent.new_simple
                    pos += 3
                    continue

            # Check unqualified in-scope class reference: old_simple
            if tok.kind == "IDENT" and tok.text in in_scope:
                prev_t = sig_tok(pos - 1)
                next_t = sig_tok(pos + 1)
                # Never replace field/method access like obj.bzgn() unless it's `.new`
                is_after_dot = prev_t is not None and prev_t.kind == "SEP" and prev_t.text == "."
                # If it's a method invocation like foo(), do not replace unless it is a constructor definition
                is_constructor_decl = (
                    tok.text == current_entry.old_simple
                    and next_t is not None and next_t.kind == "SEP" and next_t.text == "("
                    and prev_t is not None and prev_t.text in ("public", "private", "protected", "}", ";")
                )
                is_method_call = (
                    next_t is not None and next_t.kind == "SEP" and next_t.text == "("
                    and not is_constructor_decl
                )
                if not is_after_dot and not is_method_call:
                    tokens[ti].text = in_scope[tok.text].new_simple

            pos += 1

        return "".join(t.text for t in tokens)

    def remap_resources(self, res_dir: Path) -> int:
        updated = 0
        # Update fabric.mod.json
        fmod = res_dir / "fabric.mod.json"
        if fmod.is_file():
            try:
                data = json.loads(fmod.read_text("utf-8"))
                changed = False
                entrypoints = data.get("entrypoints", {})
                if isinstance(entrypoints, dict):
                    for k, lst in entrypoints.items():
                        if isinstance(lst, list):
                            new_lst = []
                            for item in lst:
                                if isinstance(item, str):
                                    internal = item.replace(".", "/")
                                    if internal in self.entries and not self.entries[internal].is_dead:
                                        new_lst.append(self.entries[internal].new_fqn)
                                        changed = True
                                        continue
                                new_lst.append(item)
                            entrypoints[k] = new_lst
                if changed:
                    fmod.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                    updated += 1
            except Exception:
                pass

        # Update *.mixins.json
        for mpath in res_dir.glob("*.mixins.json"):
            try:
                data = json.loads(mpath.read_text("utf-8"))
                pkg = data.get("package", "")
                if not pkg:
                    continue
                pkg_slash = pkg.replace(".", "/")
                new_pkg = pkg
                changed = False
                for section in ("mixins", "client", "server"):
                    cls_list = data.get(section)
                    if isinstance(cls_list, list):
                        new_cls_list = []
                        for cname in cls_list:
                            internal = f"{pkg_slash}/{cname}"
                            if internal in self.entries and not self.entries[internal].is_dead:
                                ent = self.entries[internal]
                                new_cls_list.append(ent.new_simple)
                                new_pkg = ent.new_pkg
                                changed = True
                            else:
                                new_cls_list.append(cname)
                        data[section] = new_cls_list
                if new_pkg != pkg:
                    data["package"] = new_pkg
                    changed = True
                if changed:
                    mpath.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                    updated += 1
            except Exception:
                pass

        return updated


# ==============================================================================
# Stage 9: Deep Static Security & FurryHook Domain Auditor
# ==============================================================================

class SecurityAndDomainAuditor:
    """Performs post-deobfuscation malware/API audit and extracts Feature/Mixin/Command metadata."""

    def __init__(self) -> None:
        self.apis: List[Tuple[str, str, str, int, str]] = []
        self.urls: Set[Tuple[str, str]] = set()
        self.ips: Set[Tuple[str, str]] = set()
        self.hidden: List[Tuple[str, str, str, str]] = []
        self.binaries: List[Tuple[str, str]] = []
        self.scripts: List[Tuple[str, List[str]]] = []
        self.features: List[Dict[str, Any]] = []
        self.mixins: List[Dict[str, Any]] = []
        self.commands: List[Dict[str, str]] = []

    @staticmethod
    def _decode_array_literal(kind: str, body: str) -> Optional[Tuple[str, str]]:
        vals: List[int] = []
        for tok in body.split(","):
            tok = tok.strip().strip("()")
            tok = re.sub(r"^\((?:byte|char|int)\)\s*", "", tok)
            if not tok:
                continue
            try:
                if tok.startswith("'") and tok.endswith("'"):
                    v = ord(unescape_java_string_content(tok[1:-1]))
                else:
                    v = int(tok.rstrip("Ll"), 0)
            except Exception:
                return None
            vals.append(v & 0xFF if kind == "byte" else v)
        if len(vals) < 6:
            return None

        candidates: List[Tuple[str, str]] = []
        try:
            candidates.append(("raw", "".join(chr(v) for v in vals)))
        except ValueError:
            pass
        for key in range(1, 256):
            try:
                s = "".join(chr((v ^ key) & 0xFFFF) for v in vals)
                candidates.append((f"xor 0x{key:02x}", s))
            except ValueError:
                continue

        for method, s in candidates:
            printable = sum(32 <= ord(c) < 127 for c in s) / max(len(s), 1)
            if printable > 0.92 and (
                URL_RE.search(s) or IP_RE.search(s)
                or re.search(r"(?i)powershell|cmd\.exe|/bin/sh|webhook|discord|telegram", s)
            ):
                return method, s
        return None

    def scan_java_file(self, rel_path: str, text: str) -> None:
        lines = text.splitlines()
        for name, sev, pat in DANGEROUS_API_PATTERNS:
            for m in re.finditer(pat, text):
                ln = text.count("\n", 0, m.start()) + 1
                src = lines[ln - 1].strip()[:180] if ln <= len(lines) else ""
                self.apis.append((sev, name, rel_path, ln, src))

        # Scan strings & comments for URLs, IPs, Base64 payloads
        for is_code, chunk in ConstantInlinerAndCleaner.split_code(text):
            if is_code:
                continue
            for u in URL_RE.findall(chunk):
                if not any(h in u for h in SAFE_URL_HOSTS):
                    self.urls.add((u, rel_path))
            for ip in IP_RE.findall(chunk):
                self.ips.add((ip, rel_path))

        for m in B64_RE.finditer(text):
            try:
                decoded = base64.b64decode(m.group(1), validate=True).decode("utf-8")
                printable = sum(32 <= ord(c) < 127 for c in decoded) / max(len(decoded), 1)
                if printable > 0.92 and (
                    URL_RE.search(decoded) or IP_RE.search(decoded) or "exec" in decoded.lower()
                ):
                    self.hidden.append((rel_path, "base64", m.group(1)[:40], decoded[:200]))
            except Exception:
                pass

        for m in ARR_RE.finditer(text):
            dec = self._decode_array_literal(m.group(1), m.group(2))
            if dec:
                self.hidden.append((rel_path, f"{m.group(1)}[] {dec[0]}", m.group(0)[:40], dec[1][:200]))

        # Domain extraction: Features
        cls_m = re.search(
            r"public\s+(?:final\s+)?class\s+([A-Za-z_$][\w$]*)\s+extends\s+(?:Feature|PveFeature|gdyz|mmxv)\b",
            text,
        )
        if cls_m:
            cls_name = cls_m.group(1)
            sup_m = re.search(
                r'super\s*\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*(?:FeatureCategory|hddk)\.([A-Z_]+)',
                text,
            )
            cat_m = re.search(r"(?:FeatureCategory|hddk)\.([A-Z_]+)", text)
            settings = re.findall(
                r'new\s+(?:BooleanSetting|SliderSetting|ModeSetting|ColorSetting|BindSetting|'
                r'MultiSelectSetting|InputBindSetting|fiep|mile|kioj|iiki|lisb|eims|gftk)\s*\(\s*"([^"]+)"',
                text,
            )
            self.features.append({
                "class": cls_name,
                "file": rel_path,
                "name": sup_m.group(1) if sup_m else cls_name.replace("Feature", ""),
                "description": sup_m.group(2) if sup_m else "",
                "category": sup_m.group(3) if sup_m else (cat_m.group(1) if cat_m else "UNKNOWN"),
                "settings": sorted(set(settings)),
            })

        # Domain extraction: Mixins
        mx_m = re.search(r"@Mixin\s*\(([^)]+)\)", text)
        if mx_m:
            targets = re.findall(r"([A-Za-z_$][\w$]*)\.class|\"([^\"]+)\"", mx_m.group(1))
            tgt_names = [a or b for a, b in targets]
            hooks = re.findall(r"@(Inject|Redirect|ModifyArg|ModifyVariable|WrapMethod|WrapOperation|Accessor|Invoker)\b", text)
            cls_m2 = re.search(r"\b(?:class|interface)\s+([A-Za-z_$][\w$]*)\b", text)
            self.mixins.append({
                "class": cls_m2.group(1) if cls_m2 else Path(rel_path).stem,
                "file": rel_path,
                "targets": tgt_names,
                "annotations": sorted(set(hooks)),
            })

        # Domain extraction: Commands
        if re.search(r"extends\s+(?:ClientCommand|dsrm)\b", text):
            cmd_m = re.search(r'super\s*\(\s*"([^"]+)"\s*,\s*"([^"]*)"', text)
            cls_m3 = re.search(r"\bclass\s+([A-Za-z_$][\w$]*)\b", text)
            if cls_m3:
                self.commands.append({
                    "class": cls_m3.group(1),
                    "command": cmd_m.group(1) if cmd_m else cls_m3.group(1).replace("Command", "").lower(),
                    "description": cmd_m.group(2) if cmd_m else "",
                    "file": rel_path,
                })

    def scan_resource_file(self, path: Path, base: Path) -> None:
        rel_path = path.relative_to(base).as_posix()
        try:
            head = path.read_bytes()[:4]
        except OSError:
            return
        for mg, desc in BINARY_MAGICS.items():
            if head.startswith(mg):
                self.binaries.append((rel_path, desc))
        if head.startswith(b"PK\x03\x04") and path.suffix.lower() != ".jar":
            self.binaries.append((rel_path, "Hidden ZIP/JAR Archive"))
        if path.suffix.lower() in SCRIPT_EXTENSIONS:
            txt = path.read_text("utf-8", errors="ignore")
            hits = sorted(set(m.group(1) for m in SCRIPT_NET_RE.finditer(txt)))
            self.scripts.append((rel_path, hits))

    def write_reports(
        self,
        out_dir: Path,
        stats: Dict[str, int],
        remapper: ClassAndPackageRemapper,
    ) -> Tuple[Path, Path, Path]:
        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

        # 1. Markdown report
        md: List[str] = [
            "# FurryHook Deobfuscation & Security Audit Report",
            "",
            f"- Output directory: `{out_dir}`",
            "",
            "## Pipeline Statistics",
            "",
            f"- Classfiles inspected in JAR: **{stats.get('jar_classes', 0)}**",
            f"- Java files processed: **{stats.get('files', 0)}**",
            f"- Encrypted strings decrypted (`StrDec`): **{stats.get('strings_decrypted', 0)}**",
            f"- Invokedynamic concats resolved (`StrCat`): **{stats.get('concats_resolved', 0)}**",
            f"- Obfuscated numeric expressions folded: **{stats.get('numbers_folded', 0)}**",
            f"- Opaque `throw null;` guards removed: **{stats.get('opaque_removed', 0)}**",
            f"- Synthetic watermarks & seed fields stripped: **{stats.get('watermarks_removed', 0)}**",
            f"- Static-block literals lifted: **{stats.get('static_lifted', 0)}**",
            f"- Constants inlined / unused dropped: **{stats.get('inlined', 0)} / {stats.get('dropped', 0)}**",
            f"- CFR boilerplate / junk cleaned: **{stats.get('junk', 0)}**",
            f"- Classes remapped via `SourceFile`: **{stats.get('classes_remapped', 0)}**",
            f"- Dead decoy / runtime classes removed: **{stats.get('dead_classes_removed', 0)}**",
            "",
            f"## Extracted Features / Modules ({len(self.features)})",
            "",
        ]
        by_cat: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for feat in sorted(self.features, key=lambda x: (x["category"], x["name"])):
            by_cat[feat["category"]].append(feat)
        for cat, flist in sorted(by_cat.items()):
            md.append(f"### {cat} ({len(flist)})")
            for feat in flist:
                desc = f" — {feat['description']}" if feat["description"] else ""
                md.append(f"- **{feat['name']}** (`{feat['class']}`){desc} [{len(feat['settings'])} settings]")
            md.append("")

        md += [f"## Mixins ({len(self.mixins)})", ""]
        for mx in sorted(self.mixins, key=lambda x: x["class"]):
            tgts = ", ".join(mx["targets"]) or "?"
            anns = ", ".join(mx["annotations"]) or "-"
            md.append(f"- `{mx['class']}` -> `{tgts}` ({anns})")

        md += ["", f"## Client Commands ({len(self.commands)})", ""]
        for cmd in sorted(self.commands, key=lambda x: x["command"]):
            md.append(f"- `.{cmd['command']}` (`{cmd['class']}`) — {cmd['description']}")

        md += ["", "## Security Audit: Dangerous APIs", ""]
        if self.apis:
            md += ["| Severity | Category | Location | Code |", "|---|---|---|---|"]
            for sev, name, f, ln, src in sorted(self.apis, key=lambda x: (sev_rank.get(x[0], 9), x[2], x[3])):
                md.append(f"| {sev} | {name} | `{f}:{ln}` | `{src.replace('|', '¦')}` |")
        else:
            md.append("None detected.")

        md += ["", "## External URLs", ""]
        md += [f"- `{u}` <- `{f}`" for u, f in sorted(self.urls)] or ["None."]
        md += ["", "## Non-Local Hardcoded IPs", ""]
        md += [f"- `{ip}` <- `{f}`" for ip, f in sorted(self.ips)] or ["None."]
        md += ["", "## Decoded Hidden Blobs / XOR Arrays", ""]
        md += [f"- `{f}` [{k}] -> `{d}`" for f, k, _, d in self.hidden] or ["None."]
        md += ["", "## Embedded Binaries / Scripts", ""]
        md += [f"- Binary: `{f}` — {d}" for f, d in self.binaries]
        md += [f"- Script: `{f}` — net patterns: {', '.join(h) if h else 'none'}" for f, h in self.scripts]
        if not self.binaries and not self.scripts:
            md.append("None.")

        md_path = out_dir / "DEOBF_REPORT.md"
        md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

        # 2. JSON class mapping
        mapping_json = {
            e.old_fqn: {
                "new_fqn": None if e.is_dead else e.new_fqn,
                "dead": e.is_dead,
                "reason": e.reason,
            }
            for e in sorted(remapper.entries.values(), key=lambda x: x.old_fqn)
        }
        map_path = out_dir / "class_mapping.json"
        map_path.write_text(json.dumps(mapping_json, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        # 3. JSON analysis summary
        summary_json = {
            "stats": dict(stats),
            "features": self.features,
            "mixins": self.mixins,
            "commands": self.commands,
            "security": {
                "apis": [
                    {"severity": s, "type": n, "file": f, "line": ln, "snippet": src}
                    for s, n, f, ln, src in self.apis
                ],
                "urls": [{"url": u, "file": f} for u, f in sorted(self.urls)],
                "ips": [{"ip": ip, "file": f} for ip, f in sorted(self.ips)],
                "hidden_strings": [{"file": f, "kind": k, "decoded": d} for f, k, _, d in self.hidden],
                "binaries": [{"file": f, "type": d} for f, d in self.binaries],
            },
        }
        sum_path = out_dir / "analysis_summary.json"
        sum_path.write_text(json.dumps(summary_json, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        return md_path, map_path, sum_path


# ==============================================================================
# Stage 10: Pipeline Orchestrator & CLI
# ==============================================================================

def find_executable(explicit: Optional[str], candidates: Sequence[str], which_name: str) -> Optional[str]:
    checks = [explicit, shutil.which(which_name)] + list(candidates)
    for c in checks:
        if c and os.path.isfile(c):
            return c
    return None


def find_cfr(explicit: Optional[str]) -> Optional[str]:
    for c in [explicit] + list(DEFAULT_CFR_CANDIDATES):
        if c and os.path.isfile(c):
            return c
    return None


def run_cfr_decompile(java_bin: str, cfr_jar: str, target_jar: Path, out_dir: Path) -> None:
    cmd = [
        java_bin, "-jar", cfr_jar, str(target_jar),
        "--outputdir", str(out_dir),
        "--antiobf", "true",
        "--constobf", "true",
        "--obfcontrol", "true",
        "--rename", "true",
        "--renamedupmembers", "true",
        "--renameillegalidents", "true",
        "--sugarenums", "true",
        "--sugarboxing", "true",
        "--stringconcat", "true",
        "--decodelambdas", "true",
        "--removedeadconditionals", "true",
        "--silent", "true",
    ]
    print(f"[1/8] Running CFR decompiler on {target_jar.name}...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"CFR failed (code {res.returncode}):\n{res.stderr[:2000]}")


def extract_jar_resources(jar_path: Path, res_dir: Path) -> int:
    res_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(jar_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir() or info.filename.endswith(".class"):
                continue
            dest = (res_dir / info.filename).resolve()
            if not str(dest).startswith(str(res_dir.resolve())):
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(zf.read(info.filename))
            count += 1
    return count


def process_single_file_passes(
    args: Tuple[Path, bool, bool, StringAndIndyDeobfuscator]
) -> Tuple[Path, str, Dict[str, int]]:
    path, do_opaque, do_fold, str_deobf = args
    text = path.read_text("utf-8", errors="replace")
    local_stats: Dict[str, int] = defaultdict(int)

    text, c_cnt, p_cnt = str_deobf.deobfuscate_source(text, path)
    local_stats["strings_decrypted"] += c_cnt
    local_stats["concats_resolved"] += p_cnt

    if do_fold:
        text, f_cnt = ConstantExpressionFolder.fold_source(text)
        local_stats["numbers_folded"] += f_cnt

    if do_opaque:
        text, og_cnt, wm_cnt = OpaquePredicateEliminator.clean_source(text)
        local_stats["opaque_removed"] += og_cnt
        local_stats["watermarks_removed"] += wm_cnt

    text, lift_cnt = ConstantInlinerAndCleaner.lift_static_literals(text)
    local_stats["static_lifted"] += lift_cnt
    return path, text, dict(local_stats)


def execute_pipeline(ns: argparse.Namespace) -> int:
    t0 = time.monotonic()
    target = Path(ns.target).resolve()
    if not target.exists():
        print(f"[-] Target not found: {target}", file=sys.stderr)
        return 1

    out_root = Path(ns.output or f"{target.stem}_deobf").resolve()
    if out_root.exists() and not ns.in_place:
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    is_jar = target.is_file() and target.suffix.lower() == ".jar"
    staging_java = out_root / "_staging_java"
    java_src_dir = out_root / "src" / "main" / "java"
    res_dir = out_root / "src" / "main" / "resources"

    stats: Dict[str, int] = defaultdict(int)
    jar_meta: Dict[str, ClassMetadata] = {}

    if is_jar:
        java_bin = find_executable(ns.java, DEFAULT_JAVA_CANDIDATES, "java")
        cfr_jar = find_cfr(ns.cfr)
        if not java_bin or not cfr_jar:
            print("[-] Both Java runtime and cfr.jar are required to decompile a .jar.", file=sys.stderr)
            return 1
        print(f"[0/8] Parsing JVM bytecode metadata from {target.name}...")
        jar_meta = JVMClassFileParser.inspect_jar(target)
        stats["jar_classes"] = len(jar_meta)
        run_cfr_decompile(java_bin, cfr_jar, target, staging_java)
        res_cnt = extract_jar_resources(target, res_dir)
        print(f"      Parsed {len(jar_meta)} classfiles; extracted {res_cnt} resource files.")
    else:
        print(f"[1/8] Copying source tree from {target}...")
        shutil.copytree(target, staging_java, dirs_exist_ok=True, ignore=shutil.ignore_patterns("resources", "*.jar", "__pycache__"))
        if (target / "resources").is_dir():
            shutil.copytree(target / "resources", res_dir, dirs_exist_ok=True)

    java_files = sorted(staging_java.rglob("*.java"))
    stats["files"] = len(java_files)
    print(f"[2/8] Discovering string cipher & indy profiles across {len(java_files)} files...")
    registry = StringCipherRegistry()
    registry.discover_from_sources(java_files)
    print(f"      Active StrDec profiles: {len(registry.strdecs) // 2}, StrCat profiles: {len(registry.strcats) // 2}")

    str_deobf = StringAndIndyDeobfuscator(registry, unescape_utf8=not ns.keep_unicode_escapes)

    print(f"[3/8] Decrypting strings, folding numbers & stripping opaque predicates ({ns.threads} workers)...")
    texts: Dict[Path, str] = {}
    tasks = [(p, not ns.keep_opaque, not ns.no_fold, str_deobf) for p in java_files]
    if ns.threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=ns.threads) as pool:
            for path, new_text, lstats in pool.map(process_single_file_passes, tasks):
                texts[path] = new_text
                for k, v in lstats.items():
                    stats[k] += v
    else:
        for t in tasks:
            path, new_text, lstats = process_single_file_passes(t)
            texts[path] = new_text
            for k, v in lstats.items():
                stats[k] += v

    print(
        f"      Decrypted {stats['strings_decrypted']} strings, resolved {stats['concats_resolved']} indy concats, "
        f"folded {stats['numbers_folded']} numeric exprs, eliminated {stats['opaque_removed']} opaque guards."
    )

    print("[4/8] Inlining constants & removing boilerplate junk...")
    inliner = ConstantInlinerAndCleaner()
    inliner.collect_constants(texts)
    texts = {p: inliner.inline_constants(p, txt) for p, txt in texts.items()}
    texts = inliner.drop_unused_constants(texts)
    stats["inlined"] = inliner.inlined_count
    stats["dropped"] = inliner.dropped_count

    decryptor_fqns = {prof.class_fqn for prof in registry.strdecs.values()} | {
        prof.class_fqn for prof in registry.strcats.values()
    }
    for p in list(texts.keys()):
        texts[p], jcnt = ConstantInlinerAndCleaner.clean_junk_and_imports(texts[p], decryptor_fqns)
        stats["junk"] += jcnt

    print("[5/8] Building SourceFile class & semantic package mapping...")
    remapper = ClassAndPackageRemapper(use_semantic_packages=not ns.flat_packages)
    remapper.build_mapping(texts, staging_java, jar_meta, registry.decryptor_files)

    java_src_dir.mkdir(parents=True, exist_ok=True)
    final_texts: Dict[Path, str] = {}
    for old_path, txt in texts.items():
        old_internal = old_path.relative_to(staging_java).as_posix()[:-5]
        ent = remapper.entries.get(old_internal)
        if ent and ent.is_dead and not ns.keep_dead_classes:
            stats["dead_classes_removed"] += 1
            continue
        if not ns.no_rename and ent:
            new_txt = remapper.remap_java_source(txt, ent)
            rel_dest = Path(*ent.new_pkg.split(".")) / f"{ent.new_simple}.java" if ent.new_pkg else Path(f"{ent.new_simple}.java")
            dest_path = java_src_dir / rel_dest
            if ent.new_simple != ent.old_simple or ent.new_pkg != ent.old_pkg:
                stats["classes_remapped"] += 1
        else:
            new_txt = txt
            dest_path = java_src_dir / old_path.relative_to(staging_java)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_text(new_txt, encoding="utf-8")
        final_texts[dest_path] = new_txt

    if not ns.no_rename and res_dir.exists():
        print("[6/8] Updating fabric.mod.json and mixin configurations...")
        cfg_cnt = remapper.remap_resources(res_dir)
        print(f"      Updated {cfg_cnt} configuration files.")
    else:
        print("[6/8] Skipping config remapping (--no-rename).")

    if not ns.keep_staging and staging_java.exists():
        shutil.rmtree(staging_java)

    print("[7/8] Running security audit & domain inventory extraction...")
    auditor = SecurityAndDomainAuditor()
    for path, txt in sorted(final_texts.items()):
        auditor.scan_java_file(path.relative_to(java_src_dir).as_posix(), txt)
    if res_dir.exists():
        for rpath in res_dir.rglob("*"):
            if rpath.is_file():
                auditor.scan_resource_file(rpath, res_dir)

    print("[8/8] Writing DEOBF_REPORT.md and JSON mappings...")
    md_path, map_path, sum_path = auditor.write_reports(out_root, stats, remapper)
    elapsed = time.monotonic() - t0

    print("\n=== Deobfuscation Complete ===")
    print(f"Elapsed:           {elapsed:.2f}s")
    print(f"Source Output:     {java_src_dir}")
    print(f"Resources Output:  {res_dir}")
    print(f"Classes Remapped:  {stats['classes_remapped']} (Dead removed: {stats['dead_classes_removed']})")
    print(f"Strings / Concats: {stats['strings_decrypted']} / {stats['concats_resolved']}")
    print(f"Folded / Opaque:   {stats['numbers_folded']} / {stats['opaque_removed']}")
    print(f"Features / Mixins: {len(auditor.features)} / {len(auditor.mixins)}")
    print(f"Security Findings: {len(auditor.apis)} APIs, {len(auditor.urls)} URLs, {len(auditor.ips)} IPs")
    print(f"Reports:           {md_path}")
    print(f"                   {map_path}")
    print(f"                   {sum_path}")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="furryhook_deobfuscator.py",
        description="Single-command end-to-end Java/Fabric deobfuscator, constant folder, "
                    "opaque-predicate eliminator, SourceFile remapper, and security auditor.",
    )
    p.add_argument("target", help="Input obfuscated .jar file or decompiled source directory")
    p.add_argument("-o", "--output", help="Output directory (default: <target_stem>_deobf)")
    p.add_argument("--cfr", help="Explicit path to cfr.jar")
    p.add_argument("--java", help="Explicit path to java executable")
    p.add_argument("--in-place", action="store_true", help="Reuse existing output directory without wiping")
    p.add_argument("--no-rename", action="store_true", help="Keep obfuscated class/package names")
    p.add_argument("--flat-packages", action="store_true", help="Keep original obfuscated package names while renaming classes")
    p.add_argument("--no-fold", action="store_true", help="Disable constant numeric expression folding")
    p.add_argument("--keep-opaque", action="store_true", help="Do not eliminate opaque throw-null predicates/watermarks")
    p.add_argument("--keep-dead-classes", action="store_true", help="Keep decoy a.java and StrDec/StrCat classes")
    p.add_argument("--keep-unicode-escapes", action="store_true", help="Preserve \\uXXXX escapes instead of UTF-8")
    p.add_argument("--keep-staging", action="store_true", help="Keep raw CFR staging directory")
    p.add_argument("-j", "--threads", type=int, default=os.cpu_count() or 4, help="Worker thread count")
    return p


if __name__ == "__main__":
    sys.exit(execute_pipeline(build_arg_parser().parse_args()))
