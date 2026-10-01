# Jaynshare server installation

Operator trust: every account on this host that can reach
the server process's loopback listener or control the jaynshare systemd
unit is trusted as the operator. That group must hold no untrusted user.

Decision record: pooling an account requires your dated
decision record, kept somewhere you own: the account's kind and plan as its
owner reports it, who decided that pooling it is permitted, and when.

Read these statements before you run `server preflight` or
`server install`. They are operator obligations that no command carries
out for you.

## Quickstart

```
release fetch <version> --out <dir>  # or unpack a kit you already have
jaynshare config new --out ~/jaynshare.toml   # minimal, valid scaffold
$EDITOR ~/jaynshare.toml             # set accounts, pools and routes
jaynshare server install --config ~/jaynshare.toml --from <dir>
```

`config new` refuses to overwrite an existing file. Installation never
synthesizes a configuration; the scaffold is a separate operator verb.

## Fleet update

Update every server host from this machine, one host at a time; a host
whose update fails rolls itself back and the loop moves on:

```sh
for h in host1 host2 host3; do
  ssh "$h" 'jaynshare server update --version <version>'
done
```

## Who is the operator

Every account able to reach the server process's loopback -- or to control
its systemd unit -- is trusted as the operator. That control group
therefore must have no untrusted user: an account that can connect to the
loopback service or stop the unit can read the pool's state. Do not share
any such account or shell with a user the pool does not fully trust.

Account pooling is a terms decision, not a technical one. Before an
account serves engineers, keep your own dated decision record: the
account's kind and plan as its owner reports it, who decided that pooling
it is permitted, and when. Re-read it before a material upgrade or a
change in who has access. No command asks for either statement; you
carry both obligations by reading this page and installing anyway.

## Addresses and ingress

A listener address must be loopback, IPv4 private (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`), IPv4 shared address space
(`100.64.0.0/10`) or IPv6 unique-local (`fc00::/7`). Preflight refuses
`0.0.0.0`, `::`, link-local, multicast and globally routable addresses,
even where a firewall appears to block them. The list is not
configurable.

For a non-loopback listener, filter ingress on that private interface --
or on its source range only. Preflight verifies that the published
address is assigned to this host and names the interface; check a rule
that admits traffic on it and nothing else. Opening the port globally
violates the private-listener rule and fails preflight. The installer never alters a
firewall: creating, changing or deleting firewall rules is operator work,
before or after the commands, never inside them.

## Clear text on the private network

Beside the connection settings, both server and client: a plain-HTTP
base URL exposes the client secret and request content in clear to the
private network, and the CONNECT proxy exposes its proxy credential
there. Mitigate with TLS on the base URL (`data_plane.tls_certificate_file`
and `data_plane.tls_private_key_file`) and with network segmentation of
the private network. A private address never provides encryption.

## Deployment boundary

Host access is operator access. Whoever is root on the server host
reads the pool's state and enters the server's loopback trust zone, so
they must be the operator. Another tenant needs its own VM, and an
enrolled engineer never receives host access.
