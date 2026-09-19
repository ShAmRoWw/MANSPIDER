"""Self-generated MS-GPPREF specimens; all passwords are synthetic."""

GPP_PASSWORD = "GppFixturePassword!"
GPP_CPASSWORD = "D75yjTDK26Xd1hjFJQNK6sZWcAjfyWoX9avgZfeozZviqMLhTcIZQKlaGHM6OMrd"
STRUCTURED_INSPECTOR_CASES = (
    (
        "Policies/fixture/Machine/Preferences/Groups/Groups.xml",
        f'<Groups><User name="FixtureAccount"><Properties userName="fixture" cpassword="{GPP_CPASSWORD}" /></User></Groups>',
        "group-policy-preference-password",
    ),
    (
        "Backups/Services.xml.bak",
        f'<NTServices><NTService name="FixtureService"><Properties accountName="EXAMPLE\\fixture" cPassword="{GPP_CPASSWORD}" /></NTService></NTServices>',
        "group-policy-preference-password",
    ),
    (
        "Preferences/ScheduledTasks.xml",
        f'<ScheduledTasks><TaskV2><Properties runAs="EXAMPLE\\fixture" cpassword="{GPP_CPASSWORD}" /></TaskV2></ScheduledTasks>',
        "group-policy-preference-password",
    ),
)

SOURCES = (
    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be",
    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/e808cc44-ef91-493a-a5a9-c35e6ca8b128",
    "https://github.com/fortra/impacket/blob/master/examples/Get-GPPPassword.py",
)
