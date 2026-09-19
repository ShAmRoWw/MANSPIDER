"""Small, self-authored document fixtures for default rule routing.

ODT, ODS and EPUB are deterministic packages built with the Python standard
library. The legacy PPT is an embedded LZMA-compressed, Base64-encoded binary
generated locally with LibreOffice from a synthetic single-slide ODP containing
only DOCUMENT_PASSWORD and DOCUMENT_ACCESS_KEY. Test consumers do not need
LibreOffice, an office-suite process, network access or third-party documents.

PPT provenance: handwritten ODF presentation -> LibreOffice --convert-to odp
-> --convert-to 'ppt:MS PowerPoint 97'. The slide contains two plain text
paragraphs; there are no macros, credentials, external links or embedded media.
"""

import base64
import io
import lzma
import zipfile

DOCUMENT_PASSWORD = "password=DocumentFixtureSecret!"
DOCUMENT_ACCESS_KEY = "AKIADOCFIXTURE123456"
SOURCES = (
    "https://docs.oasis-open.org/office/v1.2/os/OpenDocument-v1.2-os-part3.html",
    "https://www.w3.org/submissions/2017/SUBM-epub-ocf-20170125/",
    "https://help.libreoffice.org/latest/en-US/text/shared/guide/convertfilters.html",
    "https://docs.kreuzberg.dev/features/",
)

# Fixed bytes, not regenerated during tests. LZMA minimizes the otherwise large
# legacy compound-file container; these are our own fixture bytes, not a sample
# obtained from an external document collection.
_PPT_LZMA_BASE64 = (
    b"/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM6UP/J+hdAGgzvhyGMHdg9KSEKcLeHHYngvKRhtyIzFdigSJwUQ6p6TJIpJqMqPPSu3Jv"
    b"7HbyQHMCdfLVSA8MWoiVwy+O1fjpSn+dnoX58wtu8FdxPozvJ5dUvqaQDdja+m5ZZjrce1YASq4AXVzujNUi7xeApbpU3rlDzFJ2"
    b"My2JM9Lk64MG+EY51nCb3qRHoREVM8p9JehJdUuSTXP6izU3XfAqnJOBmZ12BsvuuWqEUfgGcuuM+MZrjnMzZTjkLYoE3leN+LSC"
    b"FieLDd7YqAjfVF7oiBbQg/vu9yaUH2UeFnHB/Jp5KTz1q+BdlHj7oWvxqKO/YNx+x5qQDdRx/ZcKdzR5xcCaMu9bPCquxtZYe/Hw"
    b"6Tobs8UiQanexOtdPEo/QkQstyJJpj3Xu230kvqKpbxzRL6al4PWTHTqgmrJ7K1TJQPTdcScrQnjQ+PmEoA+tSetUASxZtVeob/1"
    b"XUMO3M4rG6yA+bpkTP8ljOEmcEIIuhNPQJb1h4X/FNNTqrUsOno1rbK2QmR9vsImPpSgHaI50pKyEdMm9CPiyAnRgYZL5npcBjP+"
    b"0OjUTh/JhQzEtxsQTqkuFJQsdZjHXHOvNPs5Mu1A0gxk3GUP1Q7QMXC78NKZLENR8Vce9OypoKXuhTfCTp7ChCVNnL63eKTkd2vk"
    b"viiTs435KIxBchbym24d8LaY5mhlfv+/GVocF3CZ7R/voMwzwDFwM92i+Yx2AGYszF/ADxRULwbyTqpFGIGNZBbUbuZy1sLjhTh6"
    b"+Wb2Oy+A+QOi219dvurk5Y5Va9rzIuWFWIzEYgpML8eHe+5RpaYctz3hth5PqJPq2sCoGxMVL65rYhFFrYOQ+jBJc2BVHXz8taNN"
    b"X4NWRHX6d2e2Y+Hcja3s80oeVvJw5BfN2xz17+oMslZX568MNlM8Z8/6+ZgY269/wQwTQiAYE8pZlfgU6mqL5my4nEIdCv/tp8ta"
    b"UgEgxWsntgEIc56bGBI4sMzVQW+TpmB9gap2VdPQfJ08YwBNvglAPL8pWajY0sBOKTf9B5fzmlYAYn4/b3tyMtFJ6qL9tCx0o16m"
    b"b10VXKlDU7wYe2b9tbFb/FgwjPPkt1KcTi08m+wEihP0IMnE6pO+csjM5fAXNPKH+5VFSO3izJhIlAq9VROkR3V592HUlnsFrWLG"
    b"/VhOBAx/qZbWdvvNX2PqSX70um8q/3x499nmZ0DrF0zngHZFiBYYFHw9sEiffZ3qJMYt9eBp9RARqYkjKDacoXE434zUenU+RlFx"
    b"a6KeURlZ/Uj+EQW++V/5aut5HC9F7jf8TgDGdk8OV+ShYHH4TDU91Wgv8T0WO+N7UH5GxI2sKmIGZQC5m0V+77kcnpkKKOQpZhd7"
    b"6pC+gNRb1nRQ/eTTSkPkZgI8yzFpi+Svl6MbkVicZdYUc9CHso/qGnnnIV/oP9kSoNZItqFWqKnzQrC26FScJcftgTd8oRgwDBnD"
    b"1e+Qf5hKXRJqe2+/lUWrrVdIJKbA72GLRv6Mao1NV6YOEUClc34ysxL3z9Lfy+qTQJ+CUZbkQpZ/xlqfKwqJrqg4C4950hwX63A+"
    b"L5sjDYN4nbSy8Lce8RTzmHNjsZr8SLfXVXky30KDW/J0/hCFRJIo5IJCr0zUQq8T9iRfz0rkTaC9pWI0tsIZTmKsqj5cSTnVmMJt"
    b"94mmmkbgTHZuESCl0ztpzR1li5KR+dfl/KF1tTG+13ipq2kwilIy+JpfMS/dNKOQHS9lewetlHJ+q4gbGx2zmpl+gl6qhwe8Bwzs"
    b"v5WMrpuo58dAQ2xzaTAZlMHGbUh9Fdm66Hh54mFwvK6xM2ijHwMWsFj1MgZjkKEbgAAUm0V8/TGe2yynGsUI4aTyRKW+WIjdMmDs"
    b"z9xFAsf2fX32qOflR03OyVZRQYik1Sd1Zl/TKR66My2f18vpq+OdeRqBXXBwGcLT9oNv73vfwvZ3CX1mpKlDb+1JME/MxpNaVdac"
    b"KiRQGP+AKjDJce14ozhrfDDnfCbN6ftKu39P5Ts/+vLTRdSk/i5R8iq32FTwqecXHEFQ3qOypi0e16Dghv0FoeQ//sugwoyIGnCw"
    b"MsUbadawc7+Ar0HAPOP0gEWxqFzfFmSJ6YqfrNgvxfOHgNuYccENzoCQhEUaq/Ay+57LOLCt9yYKIVyQZz2teTqwtNpZZnLixrpX"
    b"fNHJx9UGF4yl0bylc6xRyluIEPE88TUeas3pCrWjIgQayZALfkD7MmX0b2abOBiPlxPyPFYkWDETBY82mUn4JB5E0tf9O4ZY54v6"
    b"AqIeUFTRp2Hw/ZpX26lKWwOee19AqGVjxNqCcAqCyqDEIVSbE/rfE6ISNZlpVBkudKd3gjpkJfKKEpWmD860F45oLMOLTzY94B/v"
    b"+pbA/Ir+ww3VUYjum7WSud6p/ANYgtvyihSdAHCtSIjn3WEPEtwWHCN8ZCRPX4sTq40rXHY4mt7stez8iI4VfU1sOW6zhi8mEJd4"
    b"cmDVrrelxTkGy+c5PgdigSqVB2kFi5T6ImWpKx0yXcD/qTaMveBiH4ch5k0zswb06ZxoUoFy0Cv1Znia4CL6o2xhkGohQO8fdZfh"
    b"kjmSxgkEiA86+fUDzsXW+iHMNwPs8dHQLYA10EDau4monIpgXHssqC2iCKZKKDoMYPdvliNyhEi/CKPbYarQ0zZNe4VzDoeTjFSp"
    b"OWIYQt+2vgMvdcgrDNM+HWNFBIixKy2nvUDYMMTDttiC0vCZwPftYSlxwTOZ4lq9dGJEO+Xnds56kKEoRTkYS6AcRm4p/kTHRKJL"
    b"wYUStzZLK1CgnVo+C2b6C8ctwEIdzaVQy3/Dimzmyx2pBLtOaWBKYlQIyj4KbpAFVCsY9E9JzLXq8O5Ii2VDT01OWeUIEtofGyHz"
    b"kYKNibJaTe7umYuz9lmAeKzpo+0sFdgg8UKG78UgYGUH4azrEqZrsZqHJpqCxcgquv8CeY9VSRNDIjWt1zGCMIRa//kAULp8k47M"
    b"TpRm0HpNPUA/B3jUUOlgqwjkjCBJ+JYW63qu0eMkFtywc7kZJurIRq4uPKbltUvypuVn/78KqrMwhmmOUsx6gXpNnvzBUd3rbVcl"
    b"jqK3CdVhKoIv+s6frPt1goE7xDofnrfq3KJMvDJHwNh01yK5bytSVvkDjiOpEz7ai/fFUrbXYdWe2Y2IJMFb5ksC7lifLdB7LPjm"
    b"SFwW9P3IEWu+/dfThTtggXZZLHMIVqsqbGXsXoWoc1uhaAteI/GZ2KKEgQ5vBuxa5aaamxgATYF/HGCsyaJnYSmkA0+xmFQhUf3w"
    b"FOGh1zqjucM3+ekLL+jU7d3u02wkdBxwYtSJEsPi67So7UsYbQGHIPW1nlrIfld9BYmVcM0PyVpjBnus2LYihztDRTRcUw1+2a+1"
    b"nje7JwGdNuZX5PdwHu4iYXjxWpXE2ss8wedVIzDTpO69F+HkT/F5ROzM5tjo7xqrQFD5hDpAlgxFbv3sgC68LMfe/Sqf6W50DksY"
    b"Nhnrwp+2Hau610uY3dB0h6xg+Xntq+HBps+qrDlcdZPOiUPxslpPd5wt5ytykOYacxSHs8k+6RolxtaJuBctHdI/ejv7L28PR2Kq"
    b"s7zEidJTCaycQC2XE7voUeMBiliWBBB/k+9Z4GBCV6gp0GboVqZdy8R7idhUmHQGWodo/F2KU8rKaK4gqjae3TFXFQl/5bWS/0sY"
    b"7EfF54Vm+ByXo4ufC53enImE/zN5HMjyc5aKJv/bge0PsfK+u+Jw+8WvNji5C/emyPY/rjBev7ilJPyKD4Ni7BB+BUPgXJO97oKV"
    b"BArWRbtfMbHBNxu88dwCIY+pLbIB8t1X485WHqTF23qPh6B7zBPyEWLNl2Ghh8DSQz49NWEq6HoxS81GD/VTS3AnUWxqL7vXETkj"
    b"7cwhd70KhElFmdN2WIlLNsLESpg8hoMawOHXh9zC7uPLydCMMJn3tuRMN8LlmeiNmmP8jW++6EiWPRwHzjiFCtcigTypr9u7raOz"
    b"y0tpmRhZS97zFUrY9F/PwArmmF2i/NC3CLCdrkQ34x86KC/vnm5AlLoqI8Q7ko/5XlPcZM4gecIUGYXfv9q0eL8KMluHzjxnC9kn"
    b"UAGiu4wRO0tQkXArVm/06Hrb3rPOXBvUczoosgZ/7c22lq/rF2Uij3+DYShsvWtOGzJGDsSzTMgIbLF3utu+XHGcW8qBEC84d4gS"
    b"vO/Rqrbouzlyjb82t/lEl1JG83SCkr622WqWugrBSeGQNp9s3Ttofn7hVywFw0EXUu/ZR4tbcAiqu5+uaFiifZlE2XtOfQK0zVhj"
    b"TwrE87MHmzeAi+sDTry+Z+UMENewBCCU4U5GCdvVM/k3rFoSQRmSDTEREXIhKyIuq6QaWHn6VwUuEewVpsGaprXw1+y6mxmw5ZaN"
    b"obkJ5C94T4Etcmcxs4odW3mKvV+nGHKClUwknYpoCYcSBnkJrgVNQnn+/FWSd0ugqmYj0FLP7xFESVAjSyxP1H1Eq7s15RL9Y+V5"
    b"7dMt/mGXBgNfyK3jpd+Aqm3BmhYRTgvtHKAgRj2aMWzqHPchytrdmsBn4oRqKbfsgTV3FVLrSozDTb1byeDkxF7GQP2LFN2EGHmk"
    b"mdVSt3jy8kgAIqKzo4DWrT7K5yiXZGNTVdDDFOaqDlZdqE6LX5vEV5fACD76oZ+hgHtDe+etSFKg+tRL84LK/mJHc6/Mspsp2PsL"
    b"PZWdsP1GL4SmqLxCKOhRSmufE5DYfSFswiXLzXyJ0CUvoW2hRD/o8wMXPfq6tpi96ZPPAl/YQtl/IakAAz6rT87EQAqdnmldwItn"
    b"kSmayspCMvM5/RT6auttCww09LYGLD/2R1NFF9HVovLVtjt+VgElnypZFRYjr22vzbCNyx3E8O4xj1Yo7tD62F8uC2QTlFN/5HJF"
    b"DR8ofYc6RdkEeQYBjV7RccP06Yrr+acfN4ezaoFNhH01KkI3TtacosZTBXgPJ6/KqiMT1M/TWISsoLylOGBxIeskFezsDZruLRjE"
    b"fWEEr3ghqxKcHtWb0j23u6W9x9h9w6YsoimOr/kkjwr1Gx8lkS9E84SRz5+CG0TIFtMQKffZRtY3Nwe163hViY5xOZ37zkFtjSsN"
    b"Srn9puedloJKOouqA0YjPEomWWnJE1fojpU92HOTza6ZuL1CwYGrBx0xW5i1IouK+8IB3pELdRvBD9C7nF1dDHVQlxPogv6Ck0el"
    b"sMr/TzEcs9zHBKNkTlXtrf8NLnU4u0/JL0an1QiUVffdw+o8hFlaHnWcqp22sdHwhEb5sfZ1OpPmp+VVXGKWWIBzmWxsUbpWuM9/"
    b"ZTw32FonBFwsJAIX4TYDvmkgdFaB29+1SFVK3CzLiJ1IerqJutEdpCe6vDbyUoaexj/N5zyIRHIxQkQZv0C5CgrFA4vBHDxsIpLh"
    b"XaPTTRIMWPKzy0Lfx2gIYYujaWExYrq4n8mgXeN/oCz/R0ZKabZ4VHswu126c+DRZwnJuRFlABsX3FGgcs8K0ZPqaqlGR7y9529u"
    b"N/18uglFOM23GTV+RX0HFXYsxIPl97XLsmybYBojQR9ld/BSuEqRBifiDLHFdtuDqUtXs3PYuveXYAJQvPY/Ms5rHkV0+AYVvUZ+"
    b"aLF6/AW6MDq2pJqYX1evte3ZGsY8YdPnvRl427ezDUNxIqyASql3mM4BLXmGE61CXCsIHNCgt8gCi9/XhS9s3HuO3/IdpgUxhZoG"
    b"Cbc6IJL7HV2l/4TBKp5WODCcRG0GD0bo6qr5Unt4sBn6oh82Hf8nSNtzKG0yuFOQqM4zCud2jKBrhC7GYbNhDK8an4yJWKp/s4Et"
    b"PVC4gdGXWbUdCweGz/XYsS1UHL4TlpzvVznLbGnyRYDFE8qLdznlzMH4ujvMilxi4qxuQnnzYiu+rzTmU9bMNcvXAOClUO9YF8FT"
    b"4NLHEJuTdRAJn6CzF7sOrW3SlEGxBGLe5LdRBeFMBSMoxTJ3EpJApSFe6Qc4jDr6axN1XbHDvMSwkay9l/sSVM0GXJfFYQW19Inu"
    b"CxH6n8Bz8H+YdB7FNrG877uRu7Q/SZ1Pdlf6DtFv89LmzjK9gurt/J5InAE2Qzd7FHwieDY7h9pDExDsk+J7/qsJ+xbySxBq+vf+"
    b"hvUservf8hyZXbBntdjOG+PaddIc5eNHpDZAKaolzJvHL16MT+UPOwEE0VupxSPUHnihc5p7hl7Qe3R669PQoIhnebxJzhVmHq84"
    b"tnDeb9wM7ff4TU873gM/VTqiIa4p49G/LjcYehPUK3AY45pms3TsOrCJpDQJ3RaBqp+oqEpyxfe434hDnYwMjy0wMGYl/b+qW0EY"
    b"6ssm0h6RrTTwl0xetyUeU1kGsDvSLsvQ/h0XeKfWNoZwviTo5xPTxdtM9wQRdcoPsnvGoar183AjIVhB2jVXaMvIKGmbI1bNvnq3"
    b"lyVcyKBEUcUbMPhHHNRilWhSlsI11gMDY/OhRKnJoaGNd8dOtky1EKn0OfbmSotYQ9JOjkXRgqJ8kIo22JUEjmOyOQbZzzsAIFbz"
    b"TVMepdxEQv/NfJufbdfFJ+V74PEn64vzR9nDnvDHpHrT690dd0DhDKDWmc8OM6c2rPuHS8yOAc1hqJ/PIN1VNZhUS94UcdkSrx+V"
    b"pehA9T2F5glLOPcJzxUSnosXpjUrpafWIHptvaM+WCcDgTT+JTDiHwA6iNdwa3WTFC7CpYVJXTwy3eQQk4GkU5G7PdWaWtlQJkND"
    b"PH2ECG+fA1hj7MAUVvwM3Xb3PL3tMwALjPgRZCLLeFz3QqR155A/P0o1lmag8zAohiZn2Pr+N0WuauaihELGg0zbhfCJ622ShacI"
    b"8rfJDkUQz8p7apcXAQd6XYTqPbUUNkc30JZEyAGQ+eE8iqBhu3tM+BemAJLC4vMKPDPu7BFWp2VeFcErV0XZANkqNYb9zcKRGW2R"
    b"66gsOTXN6tBjrCYfIKIbRlTPAvOt3ShSaB0cw3lV1TbHQsLXeGsUyu8vbNMu+aZttk8uPb7dj5Y9eUC1xsJGfQYynvGPAin0UeeB"
    b"k7ULMSMXBuj9CFdeFndgzj5dIt17fugHIM35ikUn+c3CixABjEAH5yGC71b0yuSvHA3Z94LKlVhSPXHXa3iYyOxYa7bGSLRsXSsG"
    b"BHgccy6xKtA188vVzIVWzp3KCJ8WsYCOhJByw4OQDjtjzK4KMalKChWmcq2Euul8a8Qg0tupbpNgpUBEnvp5DOv6Rqkyduo69PmR"
    b"PiEVaPu6Pbb4OYorFpjxRQ8P+KrsFrwQLNlUCsVrWbKi8+iTESjGy7oWDLOA3Fl3QqlL1+tIPpeoC8JdVklSaZD3eAF+wSfZrVv2"
    b"KPqPGytdKnE4KWSjA5mWybv5qY1z5syKflJ6f2QmyG5UoRoV3SPKr5URQxMXLTXWiFVeGexS5KZJWUWeKgobSzhTRZRjmIsWwlc+"
    b"okGK0BlA6ow3+Pg/NoY/rGMZfBvguVw3M4yja/ryUV+7QrsQuTQAAH7/zT6IhDuLxULVULbZaQOM9Xw5JcwI+YAvFoC/jMR2JaPp"
    b"zwRJEj358hGo7rDjPYTQ4EL8pmXD/rllZEECbogTj79i5M7C4qSSQCcKfF5tPumROvKPOSsEyxUuz7y/1T65dy1rA9/PSip8nNpy"
    b"5jxXEjImNPrH78KIYZXbrxNXkCw8d6curaimQHJ6eO9jbo7sO1jqrBuXTfz9NBAj+WnJz04KrVdKmOiGz+21tIRc+SUScmNsDsAZ"
    b"aWpF8OJIA+RHz8ujezEDTObiFGvnW58BvV9U9ZTL0lGteKLbU53JIQI56h6Eq3x0PlH88qf6kVmUqk80f744rNA9wLM7vujZBEvA"
    b"cHYBkBJJxJPgUsqDAORhWohmooK3wXJgbQ4BFW66GnlKjrjwZKRsjX3OyZ54KIWRz3Iluq0IJhzJtJx92y8U6txzZMYsz52U/Tu6"
    b"sg0a5vQEQh6DLaJGav7BZ4sixTzPh3/+XRJhRfAZRg1tUVFP3qLPE8YuNOnOmNL0iPqeC5D4l1BaAgUoOpnh+UT0qwQpbbBIUxi6"
    b"zcUPGMQCT046gGmjydA3zbXeHYDuCdTzYo2JOfijehRk3dErvnu1uSwtTZ8RJcTWESq5Y+V9MiZwOGGN98J24FYH+nuIpRwyegW/"
    b"r6hlu82ubBk7iqTKyOnKgD3HyhljqsHzqYJWHfgNRCCwZxeajSPuyoElkC5k0FXlZdn+Sf39pi69nnj/4UIJStENmg3jLjmCqPpc"
    b"PkOsF6ByGkeZzHO5LNZFB2kiAWrSQqGXnkBa0sf6G35lY+l2GmeBd6g7ROKRk3gdNCP5Unv7D++jQ8MSq6+XxZYFFk8BZjhAaKzp"
    b"AoIGWhsBRwbk/lQl+2oIHxk/WTQWTnyv5xgIl+QAoJOIfICiVa06HlGdCdEl2CNgDOU+ST03Rri2hibRmNIP9sNIcX8IfPsLjtAp"
    b"lEfHLKyGpMywcjG4RKlgMZC6zw5mv0tu5Gdc3ipb9n3E8P0AtO4UnLhcK0jXrjta17xdBSq6RYXUrW929jEEeHQU5X1RCDpl40FX"
    b"+stRyQW8BLIx0nRKlrj9bXK34zjZl1xqbmUF/J9URmDWqfCRkD8zrRgpDoSdPFOiXUmFDR0L4iGuqu8SKc4PynceGR2w0YmQZCoj"
    b"g2FRu6dL9WZaaWWuqCKgASJkK0SBNIKVq9REOOLwvaIMvp/Yhym0DthOhNHTeWWp7UtfgRGDKPUIYH3E1Y/wHK9ryWSQdC4+8y90"
    b"aweT63rMm+8pch/zgIDyaHz+CBiGprjk53LTBftFXAzTdHH3WIWvjcpbZeCKuO9vZ+0VgQQzGjR1s2nXITVb6KsfR3+fCA82tuxx"
    b"KicBd7Df6qvnG9eCT5gDUiEvnefZlkd63LgKi6rfqfg0TwOW4M8cHbL4UtlmjNw+vQ7UmxwdU6h9HIRum5ikqNTc+X/WYAIkHd9c"
    b"Wgm6bLI/pP8ekZVLfoTanimNwZ4z7hP0oYo+oUoU4T5noKTztgXCXLPlVAI6XtmOvLlPxKUlMcEimYYhR2EvooQTxOnuYIHJn55w"
    b"FZlC+ci66v0MYgJT+CSIHkTyLPQxysO6Q3sp/fHHV1ANnq5bWsRzNRvnbo1hZqwzipCa7SfS+YeiBd0MbN6e0mF24iMBP054rIju"
    b"U/8kdkMkeWR4oIO8KnZaWrL1ISRB8J+9g6JU1wWkt0yf2IEVsE7khety8/FvZBu1ZRsIBfAW4jfv6rq2FEpI/PQbE7q5wUgShQxJ"
    b"Aix0XoGQctBhVdWi3M/Uc/ysL882BVoTbFyVmgzjURP9gxtg93uohb0gtyNW83gkUVAOB7lhtqqaDsS7oeP66iURKZS6bsUDD4/U"
    b"8LC4S8LPpM1fourXLN+pBMvnbQB5GRwiSe0AlIinr8niH8hfki2PjsYsrZhPs82VUDpF8P37MbwWoFvcvu2+WJX6NYhSQnoyt4WE"
    b"GX4RCZ3dmXyHtNKyYqJK2GKjQPt64PxAc4JhCMo4oB1DzvVN1UZBUSP6SlmvnktvgSiFjhhb+4tFbd+FLY/fplGUjIjVtjAfr15G"
    b"nxGke6FZrEbeTchY2ab7qENTMuy+R/Cqf7WB+52V7Ca2WtbYEb6w7S67Bomv8eHEPlQOIuXrlwx+S4hMuST1itSCwS40bkHvP9p7"
    b"PoAwUy/r4PIRohbiPwFiRTcKE+q4NH9UonKunvEnB9/s1HWG6TBPy8y2qOKE+iDHg4M4jKl7LfCKYoXx648xju3I4HH5fvKdS0KM"
    b"gIQjWC3ZTw4cYxRf4UtqdZqgxgCJFYqm+1hCuaE+7UQz+kd1ceX3ri3IuXs6SaJBNl8DDQFmg9cROb9O3oZMqsOjt80cTFcarbn+"
    b"WXO+OJ08QX9xZxynkHy/rA7XLsWCI0a/ZC9WjAoMvcZg+ZC+0zZOIdrf8zyOC6T/ZN5EZz/0KywJs6cIpKDpyJ0jndGLZTP5R6cV"
    b"tvZWxCBi8QFC0Myry9cOAgtMBHOyGFHxS+YBR7j05sK0XiBkUI53PybgeW8I4S7WukmDxNYaBR+pgpljTdovBed0NYIs+7P1fcsO"
    b"WdKQbw6OEL3DREZeWPBRouNndoiRoeR6jz99xay0I262GjxAsHa+uGUkfPMjmzFLVtNKKD/rPOFGW5cR/ZkN8aa//SZBSf2UaQFX"
    b"rYrv7Tq+9XW4lunI3DzEQHYz6UBlIimqiGsehh3NkguLeRcHob8bd8/vQt25R2ckpg4g9JEAY9jzovSjs6DwjBXDkZ4tdwcCApqx"
    b"I2dbkTl3yvAFKtZKX4IuT4P5r5ZcZItbVq4bRqo0Z5rvxxtujXriyvayRhz7vER7rm31vPoqZt7z2ijk4a3RXO7HddnCp2dhq8u+"
    b"HA8u2eBrUOT2lPrZgf7R2ZBtb29ijMECxpw/aIsXvPxzqxXbPYnhg6dMsd42/AJrEme14fDUQOYmWhBUYuPDR9bVgz0vUdrjdIY2"
    b"XyU8Apy9aBsxojjj0ehUdlkrFWIqr0kCHOlJ5OE1XzfQJDgnhkBCOzT7ZFhSoSe95vFruh16FS2ao9ppuSbsIJowDM9Ee1PucKzP"
    b"pVqS4SOa+CIqvgkwH9fE5C8lhOzI0K/bJ6AqYOdOTH2f0K6SjEnShMvC6TRQYvuUeTZzReJeRGrSZhnyZXbmoOvsyygDuTmw4L3c"
    b"NaTuWiEHAEmqlGOKpWFZmrjfxgbzK5c+Sx9Gto6f+4nU6Hp8haHSf0rQme1qFom6Q8JBjIlihlpoFtn6aydNRpt+q8+t12XfMnP8"
    b"prwde2kPUZdloPBHAvheRQjSQR0dvMtNqonW7ZgTaESWqH/E+9W/Iewa9yl48WmqzjtLOlP4GSa8ZxfwNfQQgliS8R/S+0JN6SGP"
    b"F35SPQA/YanTQb1vIuV4ekO2e2xWASi/3KnLKMocv7p+1WCMrSxIn2mGb5tW1AgXv9VJ77obiHeYs2X//K7t6ovTtyjo/3/mC9fn"
    b"M6RSJceJj+gaGibWY9MVKqAbyiO052cvcO+pXf6XukY3fa2RxdVe8Codi6+9S571dETDuCwyP7/6IqZs4UccnIItFOXz/54Jah4/"
    b"L/A72zaG0WL3bqagOcciLBrgr+wUzH1iLqXQ0uAIjj4Mb5ANBEY7l040iTZsGZywIHm3Ml7v+xi+GqxzFsDJufluO/ko8wts75ej"
    b"PE5cfCh+BfdV2C/GDdpL4wSZayS3jbRiP3x7WwHWItNTxNz7LpW4ueumuZuUoVtjrooB7BtrABM8NEhwFDVct0QmSCvdAMX0vFWl"
    b"W5qptpldSxSBTBYV2MpkOdLsDDKlAJ9qWz0+2H4AHVonbKYiAkBsd27zvkbWz/qCVv7XEmYvqRw4jmRdEnocuG4AV3yczftipblr"
    b"a6q5V+hdcRvZdsC3E0B5s2lxBQ3EJJtexqHY7STCO+0AQGOfN+u+srQ4z6czI4uqxj/5VUv7N0y3QIYuh4UTg/r3I8vH0qdqHiLm"
    b"N41H+VSrCLJ3q+qZgZsJanolrUZGVUYdo7C8lx6ygjFZbTXp6+sAuTjnzU+52YT88071r7JtFh6b0DdFhkA/2N993yxQBjKuNsCE"
    b"0Bd6+Dn7iP+qiG/tkN8bljX0qSgMzdIoZrwP31AB0km7T9VJHGaYJE0lz+J1kJtuzZRQIEwyFOJYHZU3lAl8lTBotFvtLETh9G+U"
    b"KK5m28dyo5uEAtM/xLa3xPxNCgU/jOr6yq8tDLT4enO9UACPPZrXZICZ70hKXql33Ishsllq/+5oFOHkOwXYLuJouv+w9SsYuh46"
    b"TDu7ccIi45ziAK02lh68lqPtg5IrsoArbxxZPPalwqyTJkGfbbs+kMB39tj2nvQPWOgyOKvNnq1dE2mpwjFTkK9LXoJxiuFJwW8+"
    b"L7S+rpOiO9EGoi2rj3JTyyRIUfKBgesmh7Xn1Ie8FXHt0IdhKv343aPwvx95B57x5+n4lY8nWFnm9Zct/8tBnhTeTBFfNRf3NdcO"
    b"a1i+d30bIY32LX34ZQMH6OF4AnJKwGllQyPQhGB7KdaFXjrA9B4eBNAvnl/HSeJLRutDmYNS8szpiQq1LBDkuOr9gywKbWEHN2EQ"
    b"qAQu9bOA9k1cCvKXfEI9hlRHLXmac9b8BsGCqf4YpS0DRJ8JnNkNu54JteTZ97qaJcRvLQ7DqE63NNOmH3nO50Xahdz7Id59Fy8/"
    b"chBsbQ6jvQH3opirtXCo7w3KbulvOz7X4p88RixfQK0xL6vcOfhNtprYUk+q//yobfazwJ5aQsC/qWeeekan0daTE9xyn69/OACj"
    b"n8VCT0UFwCVjfZMCjMRs0luHZdXHLGr6cmjQi8g9Jn6nOYSrsH7eLnETLmGayXjMxOh5wEl+JYg82WDgNYFIMdqDZkgt4d3nTp8g"
    b"rKerKThi9hj1JkSwFxaSxVrV3laszUg5GhztQivWNzkczbJRI9V6nAooLCfrFn3Dy+XYlcs0MbrHwDU5bJWLiIMuuiZC/LlR73nF"
    b"QB9US2GxTzml9XL5GE85LghsMri5NsWfn7hqdKcBtttSp+Ys76p68lyJR6waQ5bdtW32xTtBNIkJiSZqHnQtxKDuXOMoY1o3TfZ+"
    b"HdAJzh2QW8rz7zCB8mjoytyESTOKudlHKhrI8MlzUt0NPK3ry8V0H4EL2FzzOMdqMLEZYihgmgRbkmXzYk3mcFoE7q9FRS+30rG6"
    b"/qmqkguvtOw2bPbSTiIgk2cdPKDcrlZr/8l+8O0G8NrTzbMtO62S5+87zOYNhEGFnaJSEGnJs0aobssMm5UFMLMue29yZeE/Urz/"
    b"zKCP0juNifsSYupINht3+vt9i4V47CNuD26BiFrzIKoneD4sDV+4uMUlL9+lGkKOGHifJ5r5rkDYlQFcUWybx1O+8dhZqnEQGWJ2"
    b"tbhwlSgQHWsYBH72O+APR6cXh8Ty4cPaZhlv1AokQsp11CJAvBZAsH3gIqRh/mhYSps8gbihfvYYEnA30xfVMXtbUcaDRFPT08oU"
    b"lRTO3KoNKBhaVuImKSNgAEYcM6i8Xo6gii+h5nX5fQwZ79O/bDIqiWi+kQONoNBB6U64iQgEx+2V41qcNQlNOAB0aP8Limxxv6+3"
    b"YMRSINZjj3zjamLrpvU0V0BPKp/nqxW8Xq/GzIY+3wI785n1JFJCeFxdd9rC8Ur1vTLNJS7eDK5QNBACuSBq8i0H/QU7xqTtuES2"
    b"M/LmoVS9zbXmficMu20gouo9H/wex+hZQJvJ/0PkWF6Z5OzkfbxTd9eGK1SHUx46X+xblXKVhMYKwQW62hWiEM+HCu8Eb5jodIHf"
    b"Ip1UxAXb3K4gOKFFxjVCzvXH4juhc0Eh3IOArDSoB9EKd9Z/JeRgLVplTkE8S2svYDVTYQ9/K29ul56DA38D0nMFUZ3YdAmExoAl"
    b"ZzMUNHtNZqxeRkhNbbD77pnOG//Jjz0T+SbVjAQl6pu6GkdgEFLlazqV1tXfeKQf2JL6xRoWxd7sPxS58GFDOHPVqAfGhqJjGbN5"
    b"hl7rdOymHUHKAQ2JV3Po7afB3shkitr0LfxtPPCv4M7nOP0N8wkZ+DdyXsdAn9Uf6DsCQkL1Qn3ww1DFQOY66G7t+806yN9lOTi+"
    b"3q4qfKX0arFCB2KrV8pfI0oNDGCHfoFSodeuDvaRghqFifssLmiI686pzWOx78Q6+rEH9TZl3lNVsimrux76XkOQOrzqXEMCKTDb"
    b"h7JhZ+xmbTAIhRUa9hbNub4KW3gvYyYrA47XcSgP06FixYtbG+LQDUPTzPK9LCwAJsxdtjAxBvwAAYRQgIglADxh65SxxGf7AgAA"
    b"AAAEWVo="
)


def _zip_payload(mimetype: str, parts: dict[str, str]) -> bytes:
    """Create a deterministic ZIP; ODF/EPUB require the mimetype entry first."""

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for filename, text in {"mimetype": mimetype, **parts}.items():
            info = zipfile.ZipInfo(filename, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED if filename == "mimetype" else zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, text.encode("utf-8"))
    return payload.getvalue()


def _odf_payload(kind: str, body: str) -> bytes:
    mimetype = f"application/vnd.oasis.opendocument.{kind}"
    content = f"""<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
 xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" office:version="1.2">
 <office:body>{body}</office:body>
</office:document-content>"""
    manifest = f"""<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
 manifest:version="1.2">
 <manifest:file-entry manifest:full-path="/" manifest:media-type="{mimetype}"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"""
    return _zip_payload(mimetype, {"content.xml": content, "META-INF/manifest.xml": manifest})


def _epub_payload() -> bytes:
    return _zip_payload(
        "application/epub+zip",
        {
            "META-INF/container.xml": """<?xml version="1.0" encoding="UTF-8"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
 <rootfiles><rootfile full-path="OEBPS/content.opf"
 media-type="application/oebps-package+xml"/></rootfiles>
</container>""",
            "OEBPS/content.opf": """<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="2.0" unique-identifier="book-id">
 <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:identifier id="book-id">urn:manspider:synthetic-document-fixture</dc:identifier>
  <dc:title>Synthetic document fixture</dc:title><dc:language>en</dc:language>
 </metadata>
 <manifest><item id="chapter" href="chapter.xhtml" media-type="application/xhtml+xml"/>
  <item id="ncx" href="toc.ncx" media-type="application/x-dtbncx+xml"/>
 </manifest><spine toc="ncx"><itemref idref="chapter"/></spine>
</package>""",
            "OEBPS/toc.ncx": """<?xml version="1.0" encoding="UTF-8"?>
<ncx xmlns="http://www.daisy.org/z3986/2005/ncx/" version="2005-1">
 <head><meta name="dtb:uid" content="urn:manspider:synthetic-document-fixture"/></head>
 <docTitle><text>Synthetic document fixture</text></docTitle>
 <navMap><navPoint id="chapter" playOrder="1">
  <navLabel><text>Fixture</text></navLabel><content src="chapter.xhtml"/>
 </navPoint></navMap>
</ncx>""",
            "OEBPS/chapter.xhtml": f"""<?xml version="1.0" encoding="UTF-8"?>
<html xmlns="http://www.w3.org/1999/xhtml"><head><title>Fixture</title></head>
 <body><p>{DOCUMENT_PASSWORD}</p><p>{DOCUMENT_ACCESS_KEY}</p></body></html>""",
        },
    )


def document_payloads() -> dict[str, bytes]:
    """Return proven ODT/ODS/EPUB/PPT samples keyed by dotted extension."""

    paragraphs = f"<text:p>{DOCUMENT_PASSWORD}</text:p><text:p>{DOCUMENT_ACCESS_KEY}</text:p>"
    rows = "".join(
        '<table:table-row><table:table-cell office:value-type="string">'
        f"<text:p>{value}</text:p></table:table-cell></table:table-row>"
        for value in (DOCUMENT_PASSWORD, DOCUMENT_ACCESS_KEY)
    )
    return {
        ".odt": _odf_payload("text", f"<office:text>{paragraphs}</office:text>"),
        ".ods": _odf_payload(
            "spreadsheet",
            f'<office:spreadsheet><table:table table:name="Fixture">{rows}</table:table></office:spreadsheet>',
        ),
        ".epub": _epub_payload(),
        ".ppt": lzma.decompress(base64.b64decode(_PPT_LZMA_BASE64, validate=True)),
    }
