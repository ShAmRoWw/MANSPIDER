import re
from pathlib import Path

import pytest

from man_spider.lib.parser import FileParser
from man_spider.rules import load_builtin_rules
from tests.rule_pack_2_5_content_cases import CONTENT_CASES as NEW_CONTENT_CASES
from tests.rule_pack_2_5_content_cases import METADATA_CASES as NEW_CLIENT_METADATA_CASES
from tests.rule_pack_2_5_metadata_cases import METADATA_CASES as NEW_METADATA_CASES
from tests.rule_pack_2_5_root_cases import CONTENT_CASES as ROOT_CONTENT_CASES
from tests.rule_pack_2_5_root_cases import METADATA_CASES as ROOT_METADATA_CASES
from tests.rule_pack_2_5_structured_cases import STRUCTURED_INSPECTOR_CASES as KUBERNETES_INSPECTOR_CASES
from tests.rule_pack_2_6_ad_content_cases import CONTENT_CASES as AD_CONTENT_CASES
from tests.rule_pack_2_6_ad_metadata_cases import METADATA_CASES as AD_METADATA_CASES
from tests.rule_pack_2_6_ad_structured_cases import STRUCTURED_INSPECTOR_CASES as AD_INSPECTOR_CASES
from tests.rule_pack_2_6_gpp_cases import STRUCTURED_INSPECTOR_CASES as GPP_INSPECTOR_CASES
from tests.rule_pack_2_7_ru_root_cases import STRUCTURED_INSPECTOR_CASES as RUSSIAN_INSPECTOR_CASES
from tests.rule_pack_expansion_content_cases import CONTENT_CASES as EXPANDED_CONTENT_CASES
from tests.rule_pack_expansion_metadata_cases import METADATA_CASES as EXPANDED_METADATA_CASES
from tests.rule_pack_expansion_pgpass_cases import CONTENT_CASES as PGPASS_CONTENT_CASES


BUILTIN_RULES = load_builtin_rules()
BUILTIN_PARSER = FileParser([], quiet=True, blocked_extensions=[], rules=BUILTIN_RULES)
STRUCTURED_INSPECTOR_CASES = list(KUBERNETES_INSPECTOR_CASES) + list(AD_INSPECTOR_CASES) + list(GPP_INSPECTOR_CASES)
STRUCTURED_INSPECTOR_CASES += list(RUSSIAN_INSPECTOR_CASES)


def representative_cases(cases):
    """One positive per rule for the benchmark corpus; full matrices run separately."""
    by_rule = {}
    for case in cases:
        by_rule.setdefault(case[-1], case)
    return list(by_rule.values())


LEGACY_INTERESTING_EXTENSIONS = tuple(
    """
    bat com vbs ps1 psd1 psm1 pem key rsa reg pfx cfg conf config vmdk vhd vdi dit
    kdbx kdb 1pif agilekeychain opvault lpd dashlane psafe3 enpass bwdb msecure stickypass
    pwm rdb safe zps pmvault mywallet jpass pwmdb ppk pst ssh sql db dt 1cd p12 v8i pfl
    1ccr sqlite sqlite3 mdb accdb dbf fpt tib pub crt cer csr pkcs12 jks keystore der ini
    vhdx qcow2 ost lst bak dmp mdf ldf trn ovpn rdp rdg tfstate tfvars properties yaml yml
    one onetoc2 mobileconfig eml msg nst nsf pcap pcapng zip rar 7z tar gz tgz bz2 epf
    erf mxl txt
    """.split()
)

LEGACY_INTERESTING_FILENAMES = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".env",
    ".envrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".gitconfig",
    ".netrc",
    ".bash_history",
    ".zsh_history",
    ".aws",
    ".kube",
    ".docker",
    "_netrc",
    "SAM",
    "SYSTEM",
    "SECURITY",
    "SOFTWARE",
    "NTUSER",
    "NTUSER.DAT",
    "unattend",
    "autounattend",
    "sysprep",
    "credentials",
    "secrets",
    "password",
    "vault",
    "logins",
    "Login Data",
    "ibases",
    "1cv8conn",
    "cfgrepo",
    "1cestart",
    "1cescmn",
    "appsrvrs",
    "1cv8reg",
    "1cv8clst",
    "htpasswd",
    "wp-config",
    "Vagrantfile",
    "Dockerfile",
    "docker-compose",
    "Makefile",
    "Procfile",
    ".htpasswd",
    ".dockercfg",
    ".dockerconfigjson",
    ".terraformrc",
    "known_hosts",
    "authorized_keys",
    "sshd_config",
    "ssh_config",
    "kubeconfig",
    "acme",
    "boto",
    "s3cfg",
    "gemrc",
    "yarnrc",
    "helmrc",
    "terraformrc",
    ".boto",
    ".s3cfg",
    ".hgrc",
)

LEGACY_CONTENT_EXTENSIONS = tuple(
    """
    bat cmd vbs wsf hta ps1 psd1 psm1 ps1xml reg cfg cnf conf config ini inf
    properties txt log md tex csv tsv sql xml json yml yaml toml tf tfvars
    tfstate rdp rdg ica ovpn pdf rtf docx docm xlsx xlsm xlsb pptx pptm doc
    xls eml msg htm html bak old orig htpasswd
    """.split()
)

LEGACY_CONTENT_CASES = (
    (
        r"(?i)\b(passw(or)?d(s|\d+\w*)?|passphrase|credential[s]?|api[_ -]?key|private[ _-]?key)\b",
        "credentials",
        "credential-keyword-candidate",
    ),
    (
        r"""(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*["']?[!-~]{6,}""",
        'password = "LegacySecret123!"',
        "credential-assignment-candidate",
    ),
    (
        r"(?i)(server|data\s*source|host|uid|user\s*id)\s*=\s*[^;]{1,80};.*(password|pwd)\s*=",
        "UID=legacy-user;Password=LegacySecret123!",
        "database-connection-string-candidate",
    ),
    (
        r"(?i)-----BEGIN[ A-Z]{0,30}PRIVATE KEY-----",
        "-----BEGIN VENDOR PRIVATE KEY-----",
        "private-key-header-candidate",
    ),
    (r"AKIA[0-9A-Z]{16}", "AKIAABCDEFGHIJKLMNOP", "aws-access-key-id"),
    (
        r"(eyJ[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]{10,}",
        "eyJAAAAAAAAAAA.eyJBBBBBBBBBBB.CCCCCCCCCCC",
        "jwt-token",
    ),
    (r"xox[abprs]-[A-Za-z0-9-]{10,}", "xoxb-1234567890", "slack-access-token"),
    (r"gh[pousr]_[A-Za-z0-9]{36}", "ghp_" + "A" * 36, "github-access-token"),
    (r"glpat-[A-Za-z0-9_-]{20}", "glpat-" + "A" * 20, "gitlab-access-token"),
    (r"sk-[A-Za-z0-9]{20,}", "sk-" + "A" * 20, "generic-sk-token-candidate"),
    (r"\b(парол\w*|пароль)\b", "пароль", "russian-credential-language-signal"),
    (r"\b(логин\w*)\b", "логины", "russian-credential-language-signal"),
    (
        r"\b(уч[её]тн\w*|уч[её]тк\w*|админк\w*)\b",
        "учётные",
        "russian-credential-language-signal",
    ),
    (r"\b(секрет\w*|токен\w*)\b", "токены", "russian-credential-language-signal"),
    (
        r"\b(сертификат\w*|шифр\w*|шифрова\w*|подпис\w*)\b",
        "сертификаты",
        "russian-cryptography-language-signal",
    ),
    (
        r"\b(закрыт\w+\s+ключ\w*|приват\w+\s+ключ\w*|открыт\w+\s+ключ\w*)\b",
        "закрытый ключ",
        "russian-cryptography-language-signal",
    ),
    (
        r"\b(авториз\w*|аутентифик\w*)\b",
        "аутентификация",
        "russian-credential-language-signal",
    ),
    (r"\bдоступ\s+(к|для|админ\w*)\b", "доступ к", "russian-credential-language-signal"),
    (r"\bпин[ -]?код\w*\b", "пин-коды", "russian-credential-language-signal"),
    (
        r"\bстрок\w+\s+подключени\w+\b",
        "строка подключения",
        "russian-data-connection-language-signal",
    ),
    (r"\b(БД|база\s+данных)\s*[:=]", "БД:", "russian-data-connection-language-signal"),
    (
        r"""(?i)(пароль|логин|секрет|токен|ключ)\s*[:=]\s*["']?[!-~]{4,}""",
        'пароль: "Secret123!"',
        "russian-secret-assignment",
    ),
)

LEGACY_COVERAGE_DIRECTORIES = (
    "legacy",
    "node_modules/package",
    "Windows/WinSxS/component",
    "MSSQLSERVER/MSSQL/Binn/Templates/component",
)


def metadata(path: Path, root: Path) -> dict:
    relative = path.relative_to(root)
    return {
        "share": "Fixtures",
        "directory": str(relative.parent),
        "path": str(relative),
        "filename": path.name,
        "extension": "".join(path.suffixes).lower(),
        "size": path.stat().st_size,
        "mtime": path.stat().st_mtime,
    }


def test_builtin_pack_has_native_v3_taxonomy_and_bounded_routing():
    assert len(BUILTIN_RULES) == 251
    assert {rule["schema_version"] for rule in BUILTIN_RULES} == {3}
    assert {rule["rule_pack_version"] for rule in BUILTIN_RULES} == {"2.7.0"}
    assert all(rule["severity"] in {"critical", "high", "medium", "low", "info"} for rule in BUILTIN_RULES)
    assert all(rule["confidence"] in {"high", "medium", "low"} for rule in BUILTIN_RULES)
    assert all(rule["category"] and rule["tags"] for rule in BUILTIN_RULES)
    assert not any(
        token in rule["id"].casefold() for rule in BUILTIN_RULES for token in ("snaff", "relay", "discard", "keep")
    )
    assert all(
        rule["match"]["predicates"]
        for rule in BUILTIN_RULES
        if any(action["type"] in {"scan", "inspect"} for action in rule["actions"])
    )
    assert (
        BUILTIN_PARSER.route_rules({"path": "ordinary.bin", "filename": "ordinary.bin", "extension": ".bin"}).matched
        is False
    )
    assert {rule["id"] for rule in BUILTIN_RULES if any(action["type"] == "scan" for action in rule["actions"])} == {
        case[2] for case in CONTENT_CASES
    }
    assert {rule["id"] for rule in BUILTIN_RULES if any(action["type"] == "report" for action in rule["actions"])} == {
        case[1] for case in METADATA_CASES
    }
    assert {
        rule["id"] for rule in BUILTIN_RULES if any(action["type"] == "inspect" for action in rule["actions"])
    } == {case[1] for case in INSPECTOR_CASES} | {case[2] for case in STRUCTURED_INSPECTOR_CASES}


def test_shared_metadata_selectors_and_action_specs_are_prepared_once():
    engine = BUILTIN_PARSER.rule_engine
    text_rules = [rule for rule in BUILTIN_RULES if any(action["type"] == "scan" for action in rule["actions"])]

    assert len(engine._prepared_groups) < len(BUILTIN_RULES)
    route = engine.route({"path": "app.conf", "filename": "app.conf", "extension": ".conf"})
    routed_by_id = {rule.rule_id: rule for rule in route.content_rules}
    prepared_by_id = {rule.rule_id: rule for rule in engine.all_content_rules}
    assert text_rules
    assert all(routed_by_id[rule_id] is prepared_by_id[rule_id] for rule_id in routed_by_id)


def test_builtin_metadata_rules_cover_every_legacy_interesting_extension():
    assert len(LEGACY_INTERESTING_EXTENSIONS) == len(set(LEGACY_INTERESTING_EXTENSIONS)) == 102
    missing = []
    for directory in LEGACY_COVERAGE_DIRECTORIES:
        for extension in LEGACY_INTERESTING_EXTENSIONS:
            filename = f"fixture.{extension}"
            route = BUILTIN_PARSER.route_rules(
                {
                    "share": "Fixtures",
                    "directory": directory,
                    "path": f"{directory}/{filename}",
                    "filename": filename,
                    "extension": f".{extension}",
                    "size": 1,
                    "mtime": 0,
                }
            )
            if not route.metadata_rules:
                missing.append(f"{directory}/{extension}")

    assert missing == []


def test_builtin_metadata_rules_cover_every_legacy_interesting_filename():
    assert len(LEGACY_INTERESTING_FILENAMES) == len(set(LEGACY_INTERESTING_FILENAMES)) == 66
    missing = []
    # Legacy -f expressions are evaluated against Path(filename).stem, so each
    # expression must also retain a filename carrying one trailing suffix.
    for directory in LEGACY_COVERAGE_DIRECTORIES:
        for base_filename in LEGACY_INTERESTING_FILENAMES:
            for filename in (base_filename, f"{base_filename}.legacy-copy"):
                route = BUILTIN_PARSER.route_rules(
                    {
                        "share": "Fixtures",
                        "directory": directory,
                        "path": f"{directory}/{filename}",
                        "filename": filename,
                        "extension": "".join(Path(filename).suffixes).lower(),
                        "size": 1,
                        "mtime": 0,
                    }
                )
                if not route.metadata_rules:
                    missing.append(f"{directory}/{filename}")

    assert missing == []


def test_builtin_content_rules_route_every_legacy_content_extension():
    assert len(LEGACY_CONTENT_EXTENSIONS) == len(set(LEGACY_CONTENT_EXTENSIONS)) == 55
    required_rule_ids = {f"rule:{case[2]}" for case in LEGACY_CONTENT_CASES}
    missing = []
    for extension in LEGACY_CONTENT_EXTENSIONS:
        filename = f"fixture.{extension}"
        route = BUILTIN_PARSER.route_rules(
            {
                "share": "Fixtures",
                "directory": "legacy-content",
                "path": f"legacy-content/{filename}",
                "filename": filename,
                "extension": f".{extension}",
                "size": 1,
                "mtime": 0,
            }
        )
        routed_rule_ids = {rule.rule_id for rule in route.content_rules if rule.representation == "text"}
        for rule_id in sorted(required_rule_ids - routed_rule_ids):
            missing.append(f"{extension}:{rule_id}")

    assert missing == []


@pytest.mark.parametrize(
    ("legacy_pattern", "content", "expected_rule"),
    LEGACY_CONTENT_CASES,
)
def test_builtin_content_rules_cover_every_legacy_content_expression(legacy_pattern, content, expected_rule):
    # Keep the original expressions executable in the regression suite: a bad
    # fixture must not make a native-rule assertion appear meaningful.
    assert re.search(legacy_pattern, content, re.IGNORECASE) is not None
    route = BUILTIN_PARSER.route_rules(
        {
            "share": "Fixtures",
            "directory": "legacy-content",
            "path": "legacy-content/fixture.txt",
            "filename": "fixture.txt",
            "extension": ".txt",
            "size": len(content.encode("utf-8")),
            "mtime": 0,
        }
    )

    matched_rule_ids = {rule.rule_id.removeprefix("rule:") for rule, _match in BUILTIN_PARSER.match(content, route)}

    assert expected_rule in matched_rule_ids


CONTENT_CASES = [
    ("deploy/.env", "password=UnmaskedFixturePassword!\n", "assigned-secret"),
    ("deploy/app.conf", "access_key=AKIAABCDEFGHIJKLMNOP\n", "aws-access-key-id"),
    (
        "deploy/aws.env",
        "AWS_SECRET_ACCESS_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==\n",
        "aws-secret-access-key",
    ),
    ("chat/settings.json", 'token="xoxb-123456789012-abcdefghijklmnopqrstuv"\n', "slack-access-token"),
    ("src/app.py", "token='ghp_" + "A" * 36 + "'\n", "github-access-token"),
    ("src/app.rb", "token='glpat-" + "A" * 24 + "'\n", "gitlab-access-token"),
    ("pipelines/agent.conf", "pat=" + "A" * 75 + "AZDO" + "B" * 5 + "\n", "azure-devops-personal-access-token"),
    ("mail/app.toml", "key=SG." + "A" * 20 + "." + "B" * 32 + "\n", "sendgrid-api-key"),
    ("python/publish.ini", "token=pypi-AgEIcHlwaS5vcmc" + "A" * 32 + "\n", "pypi-api-token"),
    ("gcp/app.yaml", "google_key: AIza" + "A" * 35 + "\n", "google-api-key"),
    ("billing/app.env", "STRIPE_KEY=sk_live_" + "A" * 24 + "\n", "stripe-secret-key"),
    (
        "db/app.conf",
        "DATABASE_URL=postgresql://alice:UnmaskedDbPass!@db.example.test/app\n",
        "database-credential-uri",
    ),
    ("web/web.config", '<machineKey validationKey="0123456789ABCDEF0123456789ABCDEF" />\n', "aspnet-machine-key"),
    ("desktop/admin.rdp", "password 51:b:01020304aabbccdd\n", "rdp-password-blob"),
    ("vpn/wg.conf", "[Interface]\nPrivateKey = " + "A" * 43 + "=\n", "wireguard-private-key"),
    ("automation/vault.yml", "$ANSIBLE_VAULT;1.2;AES256\nabcdef\n", "ansible-vault-payload"),
    (
        "vpn/static.ovpn",
        "-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef\n-----END OpenVPN Static key V1-----\n",
        "openvpn-static-key",
    ),
    (
        "users/.docker/config.json",
        '{"auths":{"registry":{"auth":"YWxpY2U6c2VjcmV0"}}}\n',
        "docker-registry-auth-field",
    ),
    (
        "cluster/secret.yaml",
        "apiVersion: v1\nkind: Secret\ndata:\n  password: VW5tYXNrZWQh\n",
        "kubernetes-secret-manifest",
    ),
    ("users/.netrc", "machine example.test login alice password UnmaskedNetrcPass!\n", "netrc-password"),
    ("db/provision.sql", "CREATE LOGIN app WITH PASSWORD = 'UnmaskedSqlPass!';\n", "sql-account-password"),
    (
        "deploy/unattend.xml",
        "<AdministratorPassword><Value>UnmaskedAdminPass!</Value></AdministratorPassword>\n",
        "unattended-install-password",
    ),
    ("windows/autologon.reg", '"DefaultPassword"="UnmaskedAutoLogon!"\n', "windows-registry-autologon-password"),
    (
        "wifi/Wi-Fi-Corp.xml",
        "<sharedKey><protected>false</protected><keyMaterial>UnmaskedWifiPass!</keyMaterial></sharedKey>\n",
        "wireless-cleartext-key",
    ),
    ("vault/agent.hcl", "token=hvs." + "A" * 32 + "\n", "hashicorp-vault-token"),
    ("users/.npmrc", "//registry.npmjs.org/:_authToken=" + "a" * 40 + "\n", "npm-registry-auth-token"),
    (
        "gcp/service-account.json",
        '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nAAAA\\n-----END PRIVATE KEY-----\\n"}\n',
        "google-service-account-private-key",
    ),
    ("keys/example.txt", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n", "private-key-block"),
    (
        "editors/Auto Save Session.sublime_session",
        '{"password": "UnmaskedSublimeSessionPassword!"}\n',
        "editor-session-text-secret",
    ),
    (
        "editors/state.vscdb",
        "\x00password=UnmaskedEditorBinaryPassword!\x00",
        "editor-session-binary-secret",
    ),
    (
        "application/client.xml",
        "<GIUserPassword>UnmaskedApplicationPassword!</GIUserPassword>\n",
        "application-authentication-secret",
    ),
    ("cloud/session.env", "AWS_SESSION_TOKEN=" + "A" * 96 + "\n", "aws-session-token"),
    ("azure/storage.config", "AccountKey=" + "A" * 86 + "==\n", "azure-storage-account-key"),
    (
        "azure/storage.env",
        "URL=https://fixture.blob.core.windows.net/c?sv=2025-01-05&sp=r&sig=" + "A" * 32 + "\n",
        "azure-storage-sas-token",
    ),
    (
        "browser/logins.json",
        '{"encryptedPassword":"MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcEC"}\n',
        "browser-encrypted-password",
    ),
    (
        "database/client.py",
        "psycopg2.connect(host='db', password='UnmaskedClientPassword!')\n",
        "database-client-call-with-credentials",
    ),
    (
        "database/web.config",
        "Data Source=db.example.test;User ID=alice;Password=UnmaskedConnectionPassword!;\n",
        "database-connection-string-password",
    ),
    (
        "database/integrated.config",
        "Data Source=db.example.test;Integrated Security=SSPI;\n",
        "database-integrated-connection",
    ),
    ("transfer/app.conf", "url=sftp://alice:UnmaskedTransferPassword!@files.example.test/\n", "ftp-uri-credential"),
    (
        "database/generic.conf",
        "connection_string: server=db.example.test password=UnmaskedGenericPassword!\n",
        "generic-connection-string-password",
    ),
    (
        "source/.git-credentials",
        "https://alice:UnmaskedGitPassword!@git.example.test/project.git\n",
        "git-credential-url",
    ),
    ("http/request.log", "Authorization: Basic YWxpY2U6c2VjcmV0\n", "http-basic-authorization"),
    (
        "http/bearer.log",
        "Authorization: Bearer UnmaskedBearerToken-0123456789\n",
        "http-bearer-authorization",
    ),
    (
        "java/Database.java",
        'DriverManager.getConnection("jdbc:mysql://db/app?password=UnmaskedJavaPassword!")\n',
        "java-database-credential",
    ),
    (
        "tokens/session.json",
        "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.ABCDEFGHIJKL\n",
        "jwt-token",
    ),
    (
        "users/.kube/config",
        "users:\n- user:\n    token: UnmaskedKubernetesBearerToken-0123456789\n",
        "kubernetes-bearer-token",
    ),
    ("network/router.cfg", "enable secret UnmaskedNetworkSecret!\n", "network-device-secret"),
    ("auth/hashes.conf", "$2b$12$" + "A" * 53 + "\n", "password-hash"),
    (
        "powershell/deploy.ps1",
        'ConvertTo-SecureString "UnmaskedPowerShellPassword!" -AsPlainText -Force\n',
        "powershell-plaintext-credential",
    ),
    ("rails/master.key", "0123456789abcdef0123456789abcdef\n", "rails-master-key"),
    ("cloud/resource.py", "bucket = 's3://fixture-bucket/private/object'\n", "s3-resource-uri"),
    (
        "chat/webhook.env",
        "SLACK_WEBHOOK=https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx\n",
        "slack-webhook",
    ),
    (
        "telephony/app.env",
        "TWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef\n",
        "twilio-secret",
    ),
    ("etc/shadow", "root:$6$salt1234$" + "A" * 86 + ":20000:0:99999:7:::\n", "unix-shadow-entry"),
    (
        "windows/deploy.cmd",
        "cmdkey /generic:server.example.test /user:alice /pass:UnmaskedWindowsPassword!\n",
        "windows-command-credential",
    ),
    (
        "application/secrets.xml",
        "<clientSecret>UnmaskedXmlClientSecret!</clientSecret>\n",
        "xml-password-element",
    ),
    ("documents/audit.tex", "Store the passphrase offline.\n", "credential-keyword-candidate"),
    (
        "restore/settings.old",
        'secret = "UnmaskedLegacyCandidate!"\n',
        "credential-assignment-candidate",
    ),
    (
        "remote/connections.rdg",
        "UID=legacy-user;Password=UnmaskedConnectionCandidate!\n",
        "database-connection-string-candidate",
    ),
    (
        "keys/vendor.ps1xml",
        "-----BEGIN VENDOR PRIVATE KEY-----\nAAAA\n",
        "private-key-header-candidate",
    ),
    ("api/client.orig", "token=sk-" + "A" * 24 + "\n", "generic-sk-token-candidate"),
    ("documents/access.tsv", "учётные данные администратора\n", "russian-credential-language-signal"),
    (
        "web/cryptography.htm",
        "Используется закрытый ключ.\n",
        "russian-cryptography-language-signal",
    ),
    (
        "infrastructure/production.tfstate",
        "Строка подключения хранится отдельно.\n",
        "russian-data-connection-language-signal",
    ),
    ("remote/profile.ica", 'Пароль: "UnmaskedRussianSecret!"\n', "russian-secret-assignment"),
]


CONTENT_CASES += representative_cases(list(EXPANDED_CONTENT_CASES) + PGPASS_CONTENT_CASES)
CONTENT_CASES += representative_cases(list(NEW_CONTENT_CASES) + list(ROOT_CONTENT_CASES))
CONTENT_CASES += representative_cases(AD_CONTENT_CASES)
CONTENT_CASES += [("учётки.txt", "логин=администратор", "russian-access-identifier-assignment")]


@pytest.mark.parametrize(
    ("relative_path", "content", "expected_rule"),
    CONTENT_CASES,
)
def test_builtin_content_detectors_match_representative_unmasked_values(
    tmp_path, relative_path, content, expected_rule
):
    candidate = tmp_path / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text(content, encoding="utf-8")
    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    assert f"rule:{expected_rule}" in route.matched_rule_ids
    result = BUILTIN_PARSER.parse_file(candidate, rule_route=route)

    assert result.error is None
    assert f"rule:{expected_rule}" in {finding.rule_id for finding in result.findings}
    assert all(finding.value in content or finding.start == 0 for finding in result.findings)


METADATA_CASES = [
    ("archives/evidence.zip", "archive-container-file"),
    ("backup/workstation.tib", "backup-image-file"),
    ("projects/Dockerfile", "build-deployment-manifest-file"),
    ("certificates/acme.json", "certificate-automation-state-file"),
    ("configuration/settings.txt", "configuration-data-file"),
    ("database/application.accdb", "database-data-file"),
    ("users/.pypirc", "developer-tool-configuration-file"),
    ("mail/archive.pst", "mail-data-file"),
    ("mobile/corporate.mobileconfig", "mobile-device-configuration-file"),
    ("notes/team.one", "notes-data-file"),
    ("one-c/production.1cd", "one-c-enterprise-artifact"),
    ("keys/server.rsa", "private-key-candidate-file"),
    ("certificates/server.csr", "public-key-certificate-file"),
    ("scripts/deploy.ps1", "script-source-file"),
    ("ssh/sshd_config", "ssh-configuration-file"),
    ("registry/export.reg", "windows-registry-export-file"),
    ("web/.htpasswd", "application-credential-configuration"),
    ("jenkins/credentials.xml", "ci-server-credential-store"),
    ("backup/accounts.sqldump", "database-backup-file"),
    ("images/deployment.wim", "deployment-image-file"),
    ("sccm/SMS/data/Variables.dat", "endpoint-management-variable-file"),
    ("capture/incident.pcapng", "packet-capture-file"),
    ("vm/domain-controller.vhdx", "virtual-machine-disk-file"),
    ("Windows/System32/config/SAM", "windows-security-database-file"),
    ("users/.aws/credentials", "cloud-cli-credential-file"),
    ("users/.mozilla/firefox/profile/logins.json", "browser-credential-database"),
    ("users/.git-credentials", "git-credential-store"),
    ("users/.bash_history", "shell-history-file"),
    ("vault/team.kdbx", "credential-container-file"),
    ("keys/id_ed25519", "ssh-private-key-file"),
    ("auth/service.keytab", "kerberos-credential-cache"),
    ("etc/passwd", "unix-account-database"),
    ("network/startup-config.cfg", "network-device-configuration"),
    ("iac/terraform.tfstate.backup", "terraform-state-file"),
    ("automation/.vault_password.txt", "ansible-vault-file"),
    ("pipelines/.github/workflows/deploy.yml", "ci-runner-configuration"),
    ("cloud/service-account-production.json", "cloud-service-account-file"),
    ("keys/identity.p12", "cryptographic-key-container"),
    ("database/.pgpass", "database-client-credential-file"),
    ("users/.docker/config.json", "docker-registry-credentials"),
    ("deployment/control/customsettings.ini", "domain-deployment-configuration"),
    ("endpoint/SensorConfiguration.json", "endpoint-security-configuration"),
    ("ftp/filezilla.xml", "ftp-server-configuration"),
    ("iac/production.tfvars", "infrastructure-as-code-variable-file"),
    ("java/identity.jks", "java-keystore-file"),
    ("users/.kube/config", "kubernetes-client-configuration"),
    ("inventory/passwords.xlsx", "password-inventory-document"),
    ("pam/Vault.ini", "privileged-access-management-file"),
    ("memory/lsass.dmp", "process-memory-dump"),
    ("remote/mobaxterm.ini", "remote-access-client-config"),
    ("remote/corporate.ovpn", "remote-access-profile-file"),
    ("transfer/recentservers.xml", "remote-transfer-client-config"),
    ("application/appsettings.Production.json", "sensitive-configuration-file"),
    ("users/.zshrc", "shell-profile-file"),
    ("users/.ssh/id_work", "ssh-directory-artifact"),
    ("users/Microsoft/Credentials/fixture", "windows-dpapi-credential-artifact"),
    ("wireless/Wi-Fi-Corporate.xml", "wireless-network-profile"),
    ("reports/secret-quarterly-plan.txt", "sensitive-name-keyword"),
    ("editors/.sublime_session", "editor-session-artifact"),
]


METADATA_CASES += representative_cases(EXPANDED_METADATA_CASES)
_existing_metadata_ids = {case[1] for case in METADATA_CASES}
METADATA_CASES += representative_cases(
    [
        case
        for case in list(NEW_METADATA_CASES)
        + list(NEW_CLIENT_METADATA_CASES)
        + list(ROOT_METADATA_CASES)
        + list(AD_METADATA_CASES)
        if case[1] not in _existing_metadata_ids
    ]
)


@pytest.mark.parametrize(
    ("relative_path", "expected_rule"),
    METADATA_CASES,
)
def test_builtin_metadata_detectors_cover_sensitive_artifact_families(tmp_path, relative_path, expected_rule):
    candidate = tmp_path / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(b"fixture")

    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    assert f"rule:{expected_rule}" in route.metadata_rule_ids


INSPECTOR_CASES = [
    ("keys/identity.pem", "cryptographic-key-container"),
    ("keys/identity.key", "private-key-candidate-file"),
    ("users/.ssh/id_rsa", "ssh-private-key-file"),
]


@pytest.mark.parametrize(("relative_path", "expected_rule"), INSPECTOR_CASES)
def test_builtin_private_key_inspectors_are_wired_to_real_key_material(tmp_path, relative_path, expected_rule):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    candidate = tmp_path / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    candidate.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    assert f"rule:{expected_rule}" in {rule.rule_id for rule in route.inspector_rules}
    result = BUILTIN_PARSER.parse_file(candidate, rule_route=route)

    assert result.error is None
    assert any(
        finding.rule_id == f"rule:{expected_rule}" and finding.representation == "inspect:private-key-material"
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "relative_path",
    [
        "Sublime Text/Local/Auto Save Session.sublime_session",
        "projects/application.sublime-project",
        "projects/application.sublime-workspace",
        "Sublime Text/Packages/User/SFTP.sublime-settings",
        "projects/application.code-workspace",
        "users/.viminfo",
        "users/_viminfo",
        "users/.vim_mru_files",
        "users/.local/share/nvim/shada/main.shada",
        "users/AppData/Roaming/Code/User/workspaceStorage/012345/state.vscdb",
        "users/AppData/Roaming/Cursor/User/globalStorage/state.vscdb.backup",
        "users/AppData/Roaming/VSCodium/User/settings.json",
        "projects/.idea/workspace.xml",
        "projects/.idea/dataSources.local.xml",
        "users/AppData/Roaming/Notepad++/session.xml",
        "users/.emacs.d/recentf",
        "users/.emacs.desktop",
        "projects/application.katesession",
        "projects/.vs/application/v17/.suo",
        "xcode/UserInterfaceState.xcuserstate",
        "eclipse/.metadata/.plugins/org.eclipse.ui.workbench/workbench.xml",
    ],
)
def test_editor_session_artifact_covers_distinct_editor_state_families(tmp_path, relative_path):
    candidate = tmp_path / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(b"fixture")

    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    assert "rule:editor-session-artifact" in route.metadata_rule_ids


@pytest.mark.parametrize(
    "relative_path",
    [
        "projects/workspace.xml",
        "sessions/session.xml",
        "cache/recentf",
        "projects/application.sublime-project.txt",
    ],
)
def test_generic_session_names_outside_editor_paths_are_not_reported(tmp_path, relative_path):
    candidate = tmp_path / relative_path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(b"fixture")

    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    assert "rule:editor-session-artifact" not in route.matched_rule_ids
    assert "rule:editor-session-text-secret" not in route.matched_rule_ids
    assert "rule:editor-session-binary-secret" not in route.matched_rule_ids


def test_editor_session_secret_rule_rejects_placeholders(tmp_path):
    candidate = tmp_path / "Auto Save Session.sublime_session"
    candidate.write_text('{"password":"changeme","token":"${EDITOR_TOKEN}"}\n', encoding="utf-8")
    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    result = BUILTIN_PARSER.parse_file(candidate, rule_route=route)

    assert "rule:editor-session-artifact" in route.metadata_rule_ids
    assert "rule:editor-session-text-secret" not in {finding.rule_id for finding in result.findings}


def test_placeholders_are_not_reported_as_assigned_secrets(tmp_path):
    candidate = tmp_path / ".env"
    candidate.write_text("password=changeme\nclient_secret=${CLIENT_SECRET}\n", encoding="utf-8")
    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    result = BUILTIN_PARSER.parse_file(candidate, rule_route=route)

    assert "rule:assigned-secret" not in {finding.rule_id for finding in result.findings}


def test_low_confidence_noise_exclusion_does_not_hide_exact_provider_token(tmp_path):
    candidate = tmp_path / "vendor" / "bundle" / "password-helper.js"
    candidate.parent.mkdir(parents=True)
    token = "ghp_" + "A" * 36
    candidate.write_text(f"const password = '{token}';\n", encoding="utf-8")
    route = BUILTIN_PARSER.route_rules(metadata(candidate, tmp_path))

    assert "rule:sensitive-name-keyword" not in route.matched_rule_ids
    assert "rule:assigned-secret" not in route.matched_rule_ids
    assert "rule:github-access-token" in route.matched_rule_ids
    result = BUILTIN_PARSER.parse_file(candidate, rule_route=route)
    provider_findings = [finding for finding in result.findings if finding.rule_id == "rule:github-access-token"]

    assert [(finding.value, finding.confidence) for finding in provider_findings] == [(token, "high")]
