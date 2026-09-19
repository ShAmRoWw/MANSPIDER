"""Synthetic fixtures for Web Deploy plaintext properties (not encrypted blobs)."""

CONTENT_CASES = (
    (
        "Azure.publishsettings",
        '<publishProfile userName="fixture" userPWD="DeploymentFixture!" />',
        "web-deployment-password",
    ),
    (
        "Properties/PublishProfiles/Production.pubxml",
        "<Project><PropertyGroup><UserPWD>DeploymentFixture!</UserPWD></PropertyGroup></Project>",
        "web-deployment-password",
    ),
    ("Production.pubxml.user.bak", "<UserPWD>$uperSecret!</UserPWD>", "web-deployment-password"),
    ("Azure.publishsettings", "<publishProfile userPWD='changeme' />", "web-deployment-password"),
    (
        "Azure.publishsettings.bak",
        '<publishProfile userName="alice" userPWD="Stored Attribute Secret!" destinationAppUrl="https://app.example.test" />',
        "web-deployment-password",
    ),
    (
        "Azure.publishsettings",
        '<publishProfile\n userName = "alice"\n userPWD = "StoredAttribute!"\n/>',
        "web-deployment-password",
    ),
    (
        "Azure.publishsettings",
        '<publishProfile note="&quot;userPWD=unrelated&quot;" userPWD="RealAttribute!" />',
        "web-deployment-password",
    ),
    (
        "Production.pubxml",
        "<UserPWD Condition=\"'$(Configuration)' == 'Release'\">StoredProperty!</UserPWD>",
        "web-deployment-password",
    ),
    ("Production.pubxml", "<UserPWD>\n StoredProperty! \t\n</UserPWD>", "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="$uperSecret!" />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="Single\'Quote!" />', "web-deployment-password"),
    ("Azure.publishsettings", "<publishProfile userPWD='Double\"Quote!' />", "web-deployment-password"),
)

NEGATIVE_CASES = (
    ("Azure.publishsettings", '<publishProfile userPWD="" />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="$(DeployPassword)" />', "web-deployment-password"),
    ("Azure.publishsettings", "<publishProfile userPWD='${DEPLOY_PASSWORD}' />", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>$(DeployPassword)</UserPWD>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>{{ deploy_password }}</UserPWD>", "web-deployment-password"),
    (
        "Production.pubxml.user",
        "<_EncryptedPassword>EncryptedBlobValue</_EncryptedPassword>",
        "web-deployment-password",
    ),
    ("readme.xml", "<UserPWD>DeploymentFixture!</UserPWD>", "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile data-userPWD="WrongAttribute!" />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile x:userPWD="WrongNamespace!" />', "web-deployment-password"),
    (
        "Azure.publishsettings",
        "<publishProfile description=\"blah userPWD='NotAnAttribute!'\" />",
        "web-deployment-password",
    ),
    (
        "Azure.publishsettings",
        "<publishProfile description='blah userPWD=\"NotAnAttribute!\"' />",
        "web-deployment-password",
    ),
    (
        "Azure.publishsettings",
        '<publishProfile description="blah userPWD=&quot;NotAnAttribute!&quot;" />',
        "web-deployment-password",
    ),
    ("Azure.publishsettings", 'plain text userPWD="NotAnAttribute!"', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="StoredLiteral!"garbage />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="StoredLiteral!"', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="   \t" />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="\u00a0\u2003" />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="\n\r\t " />', "web-deployment-password"),
    ("Azure.publishsettings", "<publishProfile userPWD='   ' />", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD></UserPWD>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>   </UserPWD>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>\r\n \t</UserPWD>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>  $(DeployPassword)  </UserPWD>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>prefix-$(DeployPassword)</UserPWD>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>  ${DEPLOY_PASSWORD}  </UserPWD>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>  {{ deploy_password }}  </UserPWD>", "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="prefix-$(DeployPassword)" />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="  $(DeployPassword)  " />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="$DEPLOY_PASSWORD" />', "web-deployment-password"),
    ("Azure.publishsettings", '<publishProfile userPWD="%DEPLOY_PASSWORD%" />', "web-deployment-password"),
    ("Production.pubxml", "<UserPWD>StoredProperty!</WrongProperty>", "web-deployment-password"),
    ("Production.pubxml", "<UserPWD-extra>StoredProperty!</UserPWD-extra>", "web-deployment-password"),
)

SOURCES = (
    "https://learn.microsoft.com/en-us/visualstudio/deployment/tutorial-import-publish-settings-azure?view=visualstudio",
    "https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/visual-studio-publish-profiles?view=aspnetcore-10.0",
)

METADATA_CASES = (("keys/id_rsa.legacy-copy", "credential-artifact-copy-name"),)
