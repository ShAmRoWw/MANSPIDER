"""Synthetic inline AD exports: no customer or usable domain credentials."""

import base64
import json


LDIF_RULE = "active-directory-ldif-secrets"
JSON_RULE = "active-directory-json-secrets"


def _encoded(value):
    return base64.b64encode(value).decode("ascii")


OPAQUE_FIXTURE = b"\x01\x00\xffSyntheticOpaqueDirectorySecret\x00"
BITLOCKER_FIXTURE = "000011-000022-000033-000044-000055-000066-000077-720885"
LAPS_PAYLOAD = {"n": "LocalFixtureAdmin", "t": "1d9d2adf0000000", "p": "$uperSecret!LapsFixture"}

STRUCTURED_INSPECTOR_CASES = (
    ("directory/computers.ldif", "dn: CN=LabPC,DC=example,DC=test\nms-Mcs-AdmPwd: LegacyLapsFixture!\n", LDIF_RULE),
    (
        "exports/computers.ldf",
        "dn: CN=LabPC,DC=example,DC=test\nmsLAPS-Password: " + json.dumps(LAPS_PAYLOAD) + "\n",
        LDIF_RULE,
    ),
    ("backups/directory.ldif.bak", "msLAPS-EncryptedPassword:: " + _encoded(OPAQUE_FIXTURE) + "\n", LDIF_RULE),
    (
        "exports/password-import.ldif",
        "unicodePwd:: " + _encoded('"ImportedFixture!"'.encode("utf-16-le")) + "\n",
        LDIF_RULE,
    ),
    ("exports/recovery.ldif", "msFVE-RecoveryPassword: " + BITLOCKER_FIXTURE + "\n", LDIF_RULE),
    ("exports/computers.json", json.dumps({"ms-Mcs-AdmPwd": "JsonLegacyFixture!"}), JSON_RULE),
    ("exports/computers.json.old", json.dumps([{"msLAPS-Password": json.dumps(LAPS_PAYLOAD)}]), JSON_RULE),
    ("exports/managed.json", json.dumps({"msDS-ManagedPassword": list(OPAQUE_FIXTURE)}), JSON_RULE),
    (
        "exports/laps-history.json",
        json.dumps({"msLAPS-EncryptedPasswordHistory": [_encoded(OPAQUE_FIXTURE)]}),
        JSON_RULE,
    ),
    ("exports/recovery.json", json.dumps({"msFVE-RecoveryPassword": BITLOCKER_FIXTURE}), JSON_RULE),
    ("exports/recovery-package.json", json.dumps({"msFVE-KeyPackage": list(OPAQUE_FIXTURE)}), JSON_RULE),
)

SOURCES = (
    (LDIF_RULE, "https://www.rfc-editor.org/rfc/rfc2849"),
    (JSON_RULE, "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference"),
    (
        JSON_RULE,
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2",
    ),
    (
        JSON_RULE,
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e",
    ),
    (
        JSON_RULE,
        "https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithnumericalpassword-win32-encryptablevolume",
    ),
)
