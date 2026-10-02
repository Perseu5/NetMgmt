# FreeRADIUS installer for RHEL 9 (NPS replacement)

`install-freeradius.sh` installs and configures FreeRADIUS (RHEL 9 AppStream, 3.0.x) for:

- **Wired 802.1X with EAP-TLS**: workstation (computer) certificates issued by your AD CS. User certificates can optionally be allowed too.
  - The account must exist and be enabled in Active Directory.
  - The identity must match the certificate.
  - Certificates are checked for revocation through the CA's CRL or OCSP.
- **VLAN assignment by AD group**: replaces your NPS network policies. The first matching group wins, nested groups count, and an optional default VLAN catches everything else.
- **Network device administrator logins**: authorised by AD group membership (full or read-only), with the right privilege attributes returned for each vendor.
- **RadSec**: RADIUS over TLS on TCP/2083, with mutual certificate authentication.
- Optional **EAP-TTLS/PAP** for password-based 802.1X.

It installs only `freeradius`, `freeradius-ldap` and `freeradius-utils`. Everything else it uses (openssl, curl, firewalld, SELinux tools) comes with RHEL 9.

**Versions:** tested end to end with both FreeRADIUS builds RHEL 9 has shipped: 3.0.21 (RHEL 9.0–9.6) and 3.0.27 (RHEL 9.7 and later). There is no 3.0.22–3.0.26 for RHEL 9. Update `freeradius` and `openssl` together (a normal `dnf update` does): a FreeRADIUS build refuses to start against a newer OpenSSL than it was built for (`libssl version mismatch`).

## Windows GPO change (one-time)

Today the workstations use PEAP with the workstation certificate inside it (PEAP-TLS). FreeRADIUS does not support PEAP-TLS. The same workstation certificate works with plain **EAP-TLS**, which Windows supports natively and which is what NPS calls "Smart Card or other certificate". No smart cards are involved; the name just covers any certificate.

Make this change in the wired GPO: **Computer Configuration → Policies → Windows Settings → Security Settings → Wired Network (IEEE 802.3) Policies → \<policy\> → Security**.

| Setting | Value |
|---|---|
| Enable IEEE 802.1X authentication | ✔ |
| Choose a network authentication method | **Microsoft: Smart Card or other certificate** (instead of Protected EAP (PEAP)) |
| Properties → When connecting | **Use a certificate on this computer**, ✔ Use simple certificate selection |
| Properties → Verify the server's identity | ✔. Under "Connect to these servers", enter the FreeRADIUS server certificate's DNS name; keep the NPS names during migration. |
| Properties → Trusted Root Certification Authorities | ✔ the root CA that issued the FreeRADIUS server certificate |
| Advanced settings → Authentication mode | **Computer authentication** |

How to cut over safely:

- NPS also supports plain EAP-TLS. Add "Microsoft: Smart Card or other certificate" to the NPS network policy's EAP types, then push the GPO change **before** moving any switches. Workstations keep working against NPS throughout.
- The workstation certificate needs the Client Authentication EKU and the computer's FQDN in its DNS SAN. The AD CS *Workstation Authentication* and *Computer* templates already do both.
- The script defaults to `EAPTLS_ACCOUNTS='computers'`: only `host/<fqdn>` identities are accepted, so a user certificate cannot be used to get on the network.

## Quick start

```bash
cp freeradius-install.conf.example freeradius-install.conf
cp clients.csv.example clients.csv
cp vlans.csv.example vlans.csv
chmod 600 freeradius-install.conf clients.csv
vi freeradius-install.conf clients.csv vlans.csv     # put cert files where the paths point
sudo ./install-freeradius.sh
sudo ./install-freeradius.sh --test                   # check a user or computer, see its VLAN
```

Anything missing from the answer file is prompted for. If you leave `LDAP_BIND_PASSWORD` empty, the script prompts for it so it isn't stored on disk.

## How NPS concepts map

| NPS | Here |
|---|---|
| RADIUS clients | `clients.csv` |
| Network policy conditions (Windows Groups) | `DOT1X_GROUP_DN` (who may connect) plus `vlans.csv` (which VLAN) |
| Policy order | Line order in `vlans.csv`: the first match wins |
| Tunnel-Type / Tunnel-Medium-Type / Tunnel-Pvt-Group-ID settings | Sent automatically for the matched VLAN |
| Certificate → AD account mapping, "account disabled" check | `eap-tls-authz` virtual server (LDAP lookup of an enabled account) |
| CRL checking | `CRL_URLS` + `freeradius-crl-update.timer`, or `OCSP_URL` |
| Device-admin policies (Service-Type, Cisco-AV-Pair, etc.) | `ADMIN_GROUP_DN` / `READONLY_GROUP_DN` + `nas_type` |

## How requests are handled

| Request | Checks | Result |
|---|---|---|
| EAP-TLS (802.1X) | <ol><li>The certificate chains to `EAP_CLIENT_CA`, hasn't expired, and isn't revoked.</li><li>The identity matches the certificate.</li><li>The AD account (user or computer) exists and is enabled.</li><li>The account is in `DOT1X_GROUP_DN`, if set.</li></ol> | Accept with the VLAN of the first matching group, or `DEFAULT_VLAN` |
| EAP-TTLS/PAP (if enabled) | The LDAP bind succeeds and the account is in `DOT1X_GROUP_DN`, if set. | Accept with the VLAN as above |
| Device login (PAP) | The LDAP bind succeeds and the user is in `ADMIN_GROUP_DN` or `READONLY_GROUP_DN`. | Vendor privilege attributes |
| MAB / PPP / CHAP | — | Rejected |

How identities are matched to certificates and to AD:

- **Computers** (`host/pc01.corp.example.com`): the name must match a DNS SAN or the CN of the certificate. The AD computer object is found by `dNSHostName`.
- **Users** (`jdoe@corp.example.com`): the identity must match the UPN SAN or the CN. The AD user is found by `sAMAccountName` or `userPrincipalName`.

If identity matching rejects legitimate clients during the pilot, set `EAPTLS_CHECK_IDENTITY='no'`. Check `/var/log/radius/radius.log` first: the reject reason includes the identity and the certificate CN.

### AD groups: important

`Domain Computers` and `Domain Users` are **primary groups**. AD does not record primary-group membership in the `member` attribute, so LDAP can't see it, not even when the primary group is nested in another group. NPS can see it because it reads the Windows security token. If your NPS policies match on those groups, create regular security groups for them. The script warns if you configure a primary group.

Privilege attributes returned for device logins, chosen by `nas_type` in `clients.csv`:

| nas_type | Admin | Read-only |
|---|---|---|
| `cisco` (IOS/IOS-XE) | `Cisco-AVPair = shell:priv-lvl=15` | `shell:priv-lvl=1` |
| `cisco-nxos` | `Cisco-AVPair = shell:roles="network-admin"` | `shell:roles="network-operator"` |
| `juniper` | `Juniper-Local-User-Name = remote-admin` | `remote-readonly` (you must create these template users on the device) |
| `other` (HPE/Aruba, Dell, …) | `Service-Type = Administrative-User` | `Service-Type = NAS-Prompt-User` |

## Certificate revocation

- **CRL** (`CRL_URLS`): the script downloads the CRLs over HTTP and checks that each one is signed by `EAP_CLIENT_CA`. A systemd timer refreshes them every 4 hours. `radiusd` restarts (about a second) **only when a CRL changed**, because FreeRADIUS loads CRLs at start-up.
  - If a CRL expires because the CA stopped publishing, EAP-TLS fails for everyone. NPS behaves the same way. Monitor `journalctl -u freeradius-crl-update`.
  - Delta CRLs are not used, so a revocation takes effect when AD CS publishes the next **base** CRL. That's weekly by default; shorten the base CRL period on the CA if you need faster revocation.
- **OCSP** (`OCSP_URL`): checks revocation in real time, if you run the AD CS Online Responder.
- With neither configured, disabling or deleting the AD account still blocks the device on its next authentication.

## RadSec

- Network devices connect to TCP/2083 and must present a client certificate issued by `RADSEC_CLIENT_CA`.
- The client's source IP must also be listed in `clients.csv` with `transport=radsec`. The shared secret for RadSec is always `radsec`.
- TLS 1.2 only. FreeRADIUS 3.0.x's TLS 1.3 support is not production quality.

## Operations

| Task | Command |
|---|---|
| Logs (accepts and rejects, with the reason) | `/var/log/radius/radius.log` |
| Debug (shows every decision) | `sudo systemctl stop radiusd && sudo radiusd -X` |
| Test an account and see its VLAN | `sudo ./install-freeradius.sh --test` (use `host/<fqdn>` with a blank password for a computer) |
| Force a CRL refresh | `sudo freeradius-crl-update` |
| Roll back | `sudo ./install-freeradius.sh --restore /var/lib/freeradius-installer/backups/<file>.tar.gz` |
| Generated client secrets | `/root/freeradius-client-secrets.txt` lists secrets generated in the last run. Delete it once they are configured on the devices. |

Files the script manages carry a header saying so. Change the answer file or CSVs and re-run the script rather than editing them by hand.

## Re-running, and servers that already have FreeRADIUS

The script is safe to re-run; every run rebuilds the configuration from the answer file and CSVs.

- **Packages:** if they are already installed, they are left as they are (not upgraded).
- **Backups:** each run saves `/etc/raddb` to `/var/lib/freeradius-installer/backups/raddb-<timestamp>.tar.gz`. The first run also saves `raddb-package-defaults.tar.gz`; on a server that was already configured by hand, that file holds **your original configuration**.
- **Replaced:** `clients.conf` (clients not in `clients.csv` are dropped), `mods-available/ldap` and `eap`, `policy.d/ldap_auth`, the script's own sites, and `certs/site/`. The `default` and `inner-tunnel` sites are disabled (the files stay in `sites-available`). In `radiusd.conf` only `auth = yes` is set.
- **Left alone:** other enabled sites and modules, other `policy.d` files, `users`, `proxy.conf`, the rest of `radiusd.conf`. Firewall and SELinux changes are only ever added.
- **Port conflicts:** if another enabled site listens on UDP 1812/1813, UDP 18120 or the RadSec port, the script stops and names it before touching the running server.
- **Automatic rollback:** if anything fails after the backup (config check, CRL download, `radiusd` not starting), `/etc/raddb` is restored. A running `radiusd` is not touched unless the failure happened at the restart; then it is restarted on the previous configuration. The failed configuration is kept in `/var/lib/freeradius-installer/last-failed-config.tar.gz`.
- **Generated secrets stay the same:** a blank secret in `clients.csv` is generated once and kept (root-only) in `/var/lib/freeradius-installer/client-secrets`, so re-running does not break devices that are already configured.
- **Short interruption:** each successful run restarts `radiusd` (about a second). RadSec devices reconnect on their own retry timer, which can take a few seconds more.
