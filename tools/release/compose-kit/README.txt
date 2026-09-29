Jaynshare -- Compose deployment kit

This archive deploys one Jaynshare pool instance as one Docker Compose
project. It holds compose.yaml (the project, with the image pinned to
this release's index digest), env.example (the variables it reads) and
this file.

Requirements

  * Linux, with rootless Docker Engine 28.0.0 or later and Docker
    Compose 2.20.2 or later. A rootful, remote or older daemon is
    refused by preflight; rootless mode keeps the daemon and the
    container out of host root.
  * One project per pool instance. Several projects on one machine are
    supported only when one trusted operator controls all of them; see
    "Trust" below.

The configuration file

The project mounts exactly one configuration file, read-only, and sets
only JAYNSHARE_CONFIG to it. Prepare the file owner-only (mode 0600),
owned by the service identity: the host subordinate uid that the
image's fixed numeric uid maps to, not your own uid. A host shell
cannot read it afterwards, by design; operator verbs read it inside
the project. Hand the file over from inside the daemon's own user
namespace -- for example with a throwaway rootless container that
chowns it to the service uid, which lands on the host as the
subordinate uid -- and move it back the same way to edit it, returning
it to the service identity before the project starts.

Deployment

  1. Create the configuration directory and hand over config.toml as
     above.
  2. Copy env.example and set JAYNSHARE_CONFIG_DIR,
     JAYNSHARE_HOST_IP (an explicit loopback or private address) and
     JAYNSHARE_HOST_PORT (an explicit unique port). Adjust the limits
     only if you need to; they are never omitted.
  3. Run the install verb of the Jaynshare binary:

       jaynshare container install --project <name> \
         --from jaynshare-<version>-compose.zip \
         --config /path/to/config.toml \
         --publish <host-ip>:<port>

     The project name matches [a-z0-9][a-z0-9_-]{0,31} and is the
     instance identity. The install verifies the release, materializes
     the project and starts it with pulling disabled, then requires a
     healthy status within 30 seconds.

`docker compose -p <name> exec server jaynshare status` is the
operator's status read; it must agree with the container health and
name the version and configuration digest. `container update`
pulls and verifies the new digest, snapshots the project volume
owner-only, replaces only this project's container, and deletes the
snapshot only after health succeeds; on failure it restores the old
digest, volume bytes and running state and reports the rollback.

Backup and restore

  jaynshare container backup --project <name> --out <archive>
  jaynshare container restore --project <name> --from <archive>

Backup and restore operate on one stopped project and keep the archive
owner-only. The archive is verified before anything is replaced, and
one instance's volume is never mounted into another instance.

Removal

  jaynshare container uninstall --project <name>

removes only this project's container and network and keeps the
configuration and the volume. With --purge (interactive only) the
exact project, configuration source and volume are printed and a
confirmation is read; credentials, audit and trust material then
become irrecoverable. No step ever runs a daemon-wide image, volume,
network or system prune.

Staged pre-enrolment clients

Before any client is enrolled, the operator can stage the real Claude Code
client in a throwaway container that joins the server's network namespace,
and remove it afterwards:

    docker run --rm --network container:<the server container> \
      --env ANTHROPIC_BASE_URL=http://127.0.0.1:17421 <client image> ...

The connection then genuinely originates on the instance loopback and is
admitted as the loopback operator. The container holds no
enrollment and no stored secret, and the platform image never gains the
client. A host caller through a published port arrives under a
translated address (the bridge gateway, or slirp4netns' 10.0.2.2) and is
refused as a loopback principal: pre-enrolment clients never go
through the publication.

Trust

Operator trust: every account on this host that can
reach the server process's loopback listener or control the jaynshare
systemd unit is trusted as the operator. That group must hold no
untrusted user.

Decision record: pooling an account requires your dated
decision record, kept somewhere you own: the account's kind and plan as
its owner reports it, who decided that pooling it is permitted, and
when. No command asks for either statement; you carry both obligations
by reading this file and installing anyway.

Access to the rootless Docker daemon, its socket or `docker compose
exec` is operator access: it can read the volume and enter the
server's loopback trust zone. Never grant it to an enrolled engineer
or a different tenant. Pools managed by mutually untrusted operators
must run on separate virtual machines, with separate kernels and
daemons; Docker networks and project names are not a tenant boundary.
