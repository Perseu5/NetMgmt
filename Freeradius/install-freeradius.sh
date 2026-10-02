#!/usr/bin/env bash
#
# install-freeradius.sh - FreeRADIUS installer for RHEL 9
#
# Sets up FreeRADIUS (RHEL 9 AppStream, 3.0.x) with:
#   * 802.1X EAP-TLS (machine/user certificates) with the account checked in
#     Active Directory, optional EAP-TTLS/PAP, and VLAN assignment by AD group
#     (the NPS "network policy" equivalent), CRL/OCSP revocation checking
#   * Network device administrator logins (PAP) authorised by LDAP group,
#     with per-vendor privilege attributes returned to the device
#   * RadSec (RADIUS over TLS, TCP/2083) with mutual certificate authentication
#   * User-provided certificates (PEM, DER or PKCS#12)
#
# Only the freeradius, freeradius-ldap and freeradius-utils packages are
# installed. Everything else used here (openssl, firewalld, SELinux tools)
# ships with RHEL.
#
# Usage:
#   sudo ./install-freeradius.sh [-c freeradius-install.conf] [-y]
#   sudo ./install-freeradius.sh --test
#   sudo ./install-freeradius.sh --restore /var/lib/freeradius-installer/backups/<file>.tar.gz
#
set -Eeuo pipefail
umask 027

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RADDB=/etc/raddb
SITE_CERTS=$RADDB/certs/site
STATE_DIR=/var/lib/freeradius-installer
BACKUP_DIR=$STATE_DIR/backups
SECRETS_OUT=/root/freeradius-client-secrets.txt
SECRETS_STORE=$STATE_DIR/client-secrets
MANAGED_MARK="# Managed by install-freeradius.sh - re-run the installer instead of editing by hand."

CONFIG_FILE=""
ASSUME_YES=0
MODE=install
RESTORE_FILE=""
WORK=""
LAST_BACKUP=""
ROLLBACK_ARMED=0     # set once /etc/raddb is backed up; any later failure restores it
WAS_ACTIVE=0         # radiusd was running before this run
RESTARTED=0          # this run has restarted radiusd

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
	C_RED=$'\e[31m' C_YEL=$'\e[33m' C_GRN=$'\e[32m' C_BLD=$'\e[1m' C_RST=$'\e[0m'
else
	C_RED="" C_YEL="" C_GRN="" C_BLD="" C_RST=""
fi
step() { printf '\n%s==> %s%s\n' "$C_BLD" "$*" "$C_RST"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s[ok]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '    %s[warning]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()  { printf '\n%s[error]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; rollback; exit 1; }

cleanup() { if [[ -n "$WORK" && -d "$WORK" ]]; then rm -rf "$WORK"; fi; }
trap cleanup EXIT
trap 'die "Unexpected failure at line $LINENO: $BASH_COMMAND"' ERR

usage() {
	cat <<'EOF'
Usage: install-freeradius.sh [options]

  -c, --config FILE    Answer file (default: ./freeradius-install.conf if present).
                       Anything missing from it is prompted for interactively.
  -y, --yes            Non-interactive: never prompt, fail if a value is missing.
      --test           Send test logins to the running server (device-admin and
                       802.1X inner-tunnel paths) and show the result.
      --restore FILE   Restore /etc/raddb from a backup taken by this script.
  -h, --help           Show this help.
EOF
}

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

# Quote a value as a FreeRADIUS single-quoted string (no variable expansion).
cfq() {
	local s=$1
	s=${s//\\/\\\\}
	s=${s//\'/\\\'}
	printf "'%s'" "$s"
}

is_yes() { [[ "${1,,}" =~ ^(y|yes|true|1|on)$ ]]; }

# Resolve a path relative to the directory holding the answer file.
resolve_path() {
	local p=$1
	[[ -z "$p" ]] && return 0
	if [[ "$p" != /* ]]; then
		p="${CONFIG_DIR:-$SCRIPT_DIR}/$p"
	fi
	printf '%s' "$p"
}

# ask VAR "question" [default] [secret]
ask() {
	local var=$1 question=$2 default=${3-} secret=${4-} answer
	[[ -n "${!var-}" ]] && return 0
	if (( ASSUME_YES )) || [[ ! -t 0 ]]; then
		if [[ -n "$default" ]]; then
			printf -v "$var" '%s' "$default"
			return 0
		fi
		die "$var is required but not set in the answer file."
	fi
	while :; do
		if [[ -n "$secret" ]]; then
			read -r -s -p "    $question: " answer; echo
		elif [[ -n "$default" ]]; then
			read -r -p "    $question [$default]: " answer
			answer=${answer:-$default}
		else
			read -r -p "    $question: " answer
		fi
		[[ -n "$answer" ]] && break
		echo "    A value is required."
	done
	printf -v "$var" '%s' "$answer"
}

# ask for an optional value; an empty answer leaves it blank
ask_optional() {
	local var=$1 question=$2 answer
	[[ -n "${!var-}" ]] && return 0
	(( ASSUME_YES )) || [[ ! -t 0 ]] && return 0
	read -r -p "    $question (leave blank to skip): " answer
	printf -v "$var" '%s' "$answer"
}

confirm() {
	(( ASSUME_YES )) && return 0
	[[ -t 0 ]] || return 0
	local a
	read -r -p "    $1 [y/N]: " a
	is_yes "$a"
}

require_file() {
	local label=$1 path=$2
	[[ -f "$path" ]] || die "$label not found: $path"
	[[ -r "$path" ]] || die "$label is not readable: $path"
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
set_defaults() {
	LDAP_TYPE=${LDAP_TYPE-}
	LDAP_SERVERS=${LDAP_SERVERS-}
	LDAP_SECURITY=${LDAP_SECURITY-}
	LDAP_BASE_DN=${LDAP_BASE_DN-}
	LDAP_USER_BASE_DN=${LDAP_USER_BASE_DN-}
	LDAP_GROUP_BASE_DN=${LDAP_GROUP_BASE_DN-}
	LDAP_BIND_DN=${LDAP_BIND_DN-}
	LDAP_BIND_PASSWORD=${LDAP_BIND_PASSWORD-}
	LDAP_CA_CERT=${LDAP_CA_CERT-}
	ADMIN_GROUP_DN=${ADMIN_GROUP_DN-}
	READONLY_GROUP_DN=${READONLY_GROUP_DN-}
	DOT1X_GROUP_DN=${DOT1X_GROUP_DN-}
	EAP_METHODS=${EAP_METHODS:-tls}
	EAP_CLIENT_CA=${EAP_CLIENT_CA-}
	EAPTLS_CHECK_IDENTITY=${EAPTLS_CHECK_IDENTITY:-yes}
	EAPTLS_ACCOUNTS=${EAPTLS_ACCOUNTS:-computers}
	VLAN_MAP_FILE=${VLAN_MAP_FILE-}
	DEFAULT_VLAN=${DEFAULT_VLAN-}
	CRL_URLS=${CRL_URLS-}
	OCSP_URL=${OCSP_URL-}
	CA_CERT=${CA_CERT-}
	SERVER_PFX=${SERVER_PFX-}
	SERVER_PFX_PASSWORD=${SERVER_PFX_PASSWORD-}
	SERVER_CERT=${SERVER_CERT-}
	SERVER_KEY=${SERVER_KEY-}
	SERVER_KEY_PASSWORD=${SERVER_KEY_PASSWORD-}
	SERVER_CHAIN=${SERVER_CHAIN-}
	RADSEC_ENABLE=${RADSEC_ENABLE-}
	RADSEC_PORT=${RADSEC_PORT:-2083}
	RADSEC_PFX=${RADSEC_PFX-}
	RADSEC_PFX_PASSWORD=${RADSEC_PFX_PASSWORD-}
	RADSEC_CERT=${RADSEC_CERT-}
	RADSEC_KEY=${RADSEC_KEY-}
	RADSEC_KEY_PASSWORD=${RADSEC_KEY_PASSWORD-}
	RADSEC_CHAIN=${RADSEC_CHAIN-}
	RADSEC_CLIENT_CA=${RADSEC_CLIENT_CA-}
	CLIENTS_FILE=${CLIENTS_FILE-}
	JUNIPER_ADMIN_USER=${JUNIPER_ADMIN_USER:-remote-admin}
	JUNIPER_READONLY_USER=${JUNIPER_READONLY_USER:-remote-readonly}
	LISTEN_IPV6=${LISTEN_IPV6:-auto}
	OPEN_FIREWALL=${OPEN_FIREWALL:-yes}
	RPM_DIR=${RPM_DIR-}
}

load_config() {
	if [[ -z "$CONFIG_FILE" && -f "$SCRIPT_DIR/freeradius-install.conf" ]]; then
		CONFIG_FILE="$SCRIPT_DIR/freeradius-install.conf"
	fi
	if [[ -n "$CONFIG_FILE" ]]; then
		require_file "Answer file" "$CONFIG_FILE"
		CONFIG_DIR=$(cd "$(dirname "$CONFIG_FILE")" && pwd)
		# shellcheck disable=SC1090
		source "$CONFIG_FILE"
		info "Loaded answer file $CONFIG_FILE"
	else
		CONFIG_DIR=$SCRIPT_DIR
		info "No answer file found; answering interactively."
	fi
	set_defaults
}

gather_answers() {
	step "Collecting settings"

	echo "  LDAP directory"
	ask LDAP_TYPE "Directory type (ad or openldap)" "ad"
	LDAP_TYPE=${LDAP_TYPE,,}
	[[ "$LDAP_TYPE" =~ ^(ad|openldap)$ ]] || die "LDAP_TYPE must be 'ad' or 'openldap'."
	ask LDAP_SERVERS "LDAP server host names, space separated (host or host:port)"
	ask LDAP_SECURITY "Connection security (ldaps, starttls or plain)" "ldaps"
	LDAP_SECURITY=${LDAP_SECURITY,,}
	[[ "$LDAP_SECURITY" =~ ^(ldaps|starttls|plain)$ ]] || die "LDAP_SECURITY must be ldaps, starttls or plain."
	ask LDAP_BASE_DN "Base DN (e.g. DC=corp,DC=example,DC=com)"
	ask LDAP_BIND_DN "Service account DN used to search the directory"
	ask LDAP_BIND_PASSWORD "Service account password" "" secret
	if [[ "$LDAP_SECURITY" != plain ]]; then
		ask_optional LDAP_CA_CERT "CA certificate that issued the LDAP server certificate (blank = system trust store)"
	fi

	echo "  Authorisation groups (full DNs)"
	ask_optional ADMIN_GROUP_DN "Group whose members get FULL admin on network devices"
	ask_optional READONLY_GROUP_DN "Group whose members get READ-ONLY access on network devices"
	ask_optional DOT1X_GROUP_DN "Group allowed on the network via 802.1X (blank = any enabled AD user/computer)"

	echo "  802.1X"
	ask EAP_METHODS "EAP methods: tls (certificates), ttls (passwords), or 'tls ttls'" "tls"
	if [[ " $EAP_METHODS " == *" tls "* ]]; then
		ask_optional EAP_CLIENT_CA "CA that issues the workstation/user certificates (blank = same as CA_CERT)"
		ask_optional CRL_URLS "HTTP URL(s) of the issuing CA's CRL, space separated"
	fi
	ask_optional VLAN_MAP_FILE "CSV file mapping AD groups to VLANs"

	echo "  Certificates (PEM, DER, or PKCS#12 .pfx/.p12)"
	ask CA_CERT "CA certificate (root, plus intermediates if you like) that issued the server certificate"
	if [[ -z "$SERVER_CERT" && -z "$SERVER_PFX" ]]; then
		local kind="pem"
		(( ASSUME_YES )) || [[ ! -t 0 ]] || read -r -p "    Is the server certificate a PKCS#12 bundle (.pfx/.p12)? [y/N]: " kind
		if is_yes "$kind"; then
			ask SERVER_PFX "Server PKCS#12 file"
			ask SERVER_PFX_PASSWORD "PKCS#12 password" "" secret
		fi
	fi
	if [[ -z "$SERVER_PFX" ]]; then
		ask SERVER_CERT "Server certificate file"
		ask SERVER_KEY "Server private key file"
		ask_optional SERVER_CHAIN "Intermediate CA chain file"
	fi

	echo "  RadSec"
	ask RADSEC_ENABLE "Enable RadSec (RADIUS over TLS on TCP/$RADSEC_PORT)? (yes/no)" "yes"
	if is_yes "$RADSEC_ENABLE"; then
		ask_optional RADSEC_CLIENT_CA "CA that issues the RadSec CLIENT (network device) certificates (blank = same as CA_CERT)"
	fi

	echo "  RADIUS clients"
	ask CLIENTS_FILE "CSV file listing network devices" "clients.csv"
}

validate_answers() {
	step "Validating settings"

	CA_CERT=$(resolve_path "$CA_CERT")
	LDAP_CA_CERT=$(resolve_path "$LDAP_CA_CERT")
	SERVER_PFX=$(resolve_path "$SERVER_PFX")
	SERVER_CERT=$(resolve_path "$SERVER_CERT")
	SERVER_KEY=$(resolve_path "$SERVER_KEY")
	SERVER_CHAIN=$(resolve_path "$SERVER_CHAIN")
	RADSEC_PFX=$(resolve_path "$RADSEC_PFX")
	RADSEC_CERT=$(resolve_path "$RADSEC_CERT")
	RADSEC_KEY=$(resolve_path "$RADSEC_KEY")
	RADSEC_CHAIN=$(resolve_path "$RADSEC_CHAIN")
	RADSEC_CLIENT_CA=$(resolve_path "$RADSEC_CLIENT_CA")
	EAP_CLIENT_CA=$(resolve_path "$EAP_CLIENT_CA")
	VLAN_MAP_FILE=$(resolve_path "$VLAN_MAP_FILE")
	CLIENTS_FILE=$(resolve_path "$CLIENTS_FILE")
	RPM_DIR=$(resolve_path "$RPM_DIR")

	EAP_METHODS=${EAP_METHODS,,}
	local m
	EAP_TLS=no EAP_TTLS=no
	for m in $EAP_METHODS; do
		case "$m" in
			tls)  EAP_TLS=yes ;;
			ttls) EAP_TTLS=yes ;;
			*)    die "EAP_METHODS may contain only 'tls' and 'ttls' (got '$m')." ;;
		esac
	done
	[[ "$EAP_TLS$EAP_TTLS" != nono ]] || die "EAP_METHODS is empty."
	EAPTLS_ACCOUNTS=${EAPTLS_ACCOUNTS,,}
	[[ "$EAPTLS_ACCOUNTS" =~ ^(computers|computers\ users|users\ computers)$ ]] ||
		die "EAPTLS_ACCOUNTS must be 'computers' or 'computers users'."
	if [[ "$EAP_TLS" == yes ]]; then
		[[ -n "$EAP_CLIENT_CA" ]] && require_file "EAP_CLIENT_CA" "$EAP_CLIENT_CA"
		[[ -z "$CRL_URLS" && -z "$OCSP_URL" ]] &&
			warn "No CRL_URLS or OCSP_URL: revoked certificates are only blocked by disabling/deleting the AD account."
		if [[ -n "$CRL_URLS" ]] && ! command -v curl >/dev/null; then
			die "CRL_URLS needs curl (part of the RHEL 9 base install) but it is missing."
		fi
	fi
	[[ -z "$DEFAULT_VLAN" || "$DEFAULT_VLAN" =~ ^[A-Za-z0-9_.-]+$ ]] || die "DEFAULT_VLAN '$DEFAULT_VLAN' is not a valid VLAN ID or name."

	require_file "CA_CERT" "$CA_CERT"
	[[ -n "$LDAP_CA_CERT" ]] && require_file "LDAP_CA_CERT" "$LDAP_CA_CERT"
	if [[ -n "$SERVER_PFX" ]]; then
		require_file "SERVER_PFX" "$SERVER_PFX"
	else
		require_file "SERVER_CERT" "$SERVER_CERT"
		require_file "SERVER_KEY" "$SERVER_KEY"
		[[ -n "$SERVER_CHAIN" ]] && require_file "SERVER_CHAIN" "$SERVER_CHAIN"
	fi
	if is_yes "$RADSEC_ENABLE"; then
		[[ "$RADSEC_PORT" =~ ^[0-9]+$ ]] || die "RADSEC_PORT must be a number."
		[[ -n "$RADSEC_PFX" ]] && require_file "RADSEC_PFX" "$RADSEC_PFX"
		if [[ -n "$RADSEC_CERT" || -n "$RADSEC_KEY" ]]; then
			require_file "RADSEC_CERT" "$RADSEC_CERT"
			require_file "RADSEC_KEY" "$RADSEC_KEY"
		fi
		[[ -n "$RADSEC_CHAIN" ]] && require_file "RADSEC_CHAIN" "$RADSEC_CHAIN"
		[[ -n "$RADSEC_CLIENT_CA" ]] && require_file "RADSEC_CLIENT_CA" "$RADSEC_CLIENT_CA"
	fi
	require_file "CLIENTS_FILE" "$CLIENTS_FILE"

	if [[ "$LDAP_SECURITY" == plain ]]; then
		warn "LDAP_SECURITY=plain sends user passwords to the directory in clear text."
		confirm "Continue with an unencrypted LDAP connection?" || die "Aborted."
	fi
	if [[ -z "$ADMIN_GROUP_DN" && -z "$READONLY_GROUP_DN" ]]; then
		warn "No admin groups set: network device administrator logins will be rejected."
	fi

	case "${LISTEN_IPV6,,}" in
		auto) if [[ -f /proc/net/if_inet6 ]]; then LISTEN_IPV6=yes; else LISTEN_IPV6=no; fi ;;
		*)    is_yes "$LISTEN_IPV6" && LISTEN_IPV6=yes || LISTEN_IPV6=no ;;
	esac

	parse_clients
	parse_vlans
	local g
	for g in "$ADMIN_GROUP_DN" "$READONLY_GROUP_DN" "$DOT1X_GROUP_DN"; do
		[[ -n "$g" ]] && warn_primary_group "$g"
	done
	ok "Settings look complete"
}

# ---------------------------------------------------------------------------
# vlans.csv:  group_dn;vlan   (first matching group wins)
# Semicolon-separated because group DNs contain commas.
# ---------------------------------------------------------------------------
declare -a VL_GROUP VL_VLAN

# AD primary groups are not stored in the "member" attribute, so LDAP cannot see them.
warn_primary_group() {
	if [[ "${1,,}" =~ ^cn=domain\ (computers|users|controllers), ]]; then
		warn "'${1%%,*}' is an AD primary group. Primary-group membership is invisible to LDAP (also when nested inside another group), so this will never match. Use a regular security group with the accounts as members."
	fi
}

parse_vlans() {
	[[ -z "$VLAN_MAP_FILE" ]] && return 0
	require_file "VLAN_MAP_FILE" "$VLAN_MAP_FILE"
	local line n=0 group vlan
	while IFS= read -r line || [[ -n "$line" ]]; do
		n=$((n + 1))
		line=${line%$'\r'}
		[[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
		[[ "$line" == *";"* ]] || die "$VLAN_MAP_FILE line $n: expected 'group DN;vlan'."
		group=${line%;*}; vlan=${line##*;}
		group="${group#"${group%%[![:space:]]*}"}"; group="${group%"${group##*[![:space:]]}"}"
		vlan=$(echo "$vlan" | xargs)
		[[ "${group,,}" == group_dn ]] && continue   # header row
		[[ "$group" == *=*,*=* ]] || die "$VLAN_MAP_FILE line $n: '$group' does not look like a group DN."
		[[ "$vlan" =~ ^[A-Za-z0-9_.-]+$ ]] || die "$VLAN_MAP_FILE line $n: '$vlan' is not a valid VLAN ID or name."
		warn_primary_group "$group"
		VL_GROUP+=("$group"); VL_VLAN+=("$vlan")
	done <"$VLAN_MAP_FILE"
	info "${#VL_GROUP[@]} VLAN mapping(s)${DEFAULT_VLAN:+, default VLAN $DEFAULT_VLAN}"
}

# ---------------------------------------------------------------------------
# clients.csv:  name,address,secret,nas_type,transport
# A blank secret is generated once and kept in $SECRETS_STORE, so re-running the
# installer does not change the secret already configured on the device.
# CL_GENERATED: 0 = from clients.csv, 1 = generated this run, 2 = reused from an earlier run
# ---------------------------------------------------------------------------
declare -a CL_NAME CL_ADDR CL_SECRET CL_TYPE CL_TRANSPORT CL_GENERATED
parse_clients() {
	local line n=0 name addr secret type transport rest stored_name stored_secret
	declare -A seen=() stored=()
	if [[ -r "$SECRETS_STORE" ]]; then
		while IFS=, read -r stored_name stored_secret; do
			[[ -n "$stored_name" && -n "$stored_secret" ]] && stored[$stored_name]=$stored_secret
		done <"$SECRETS_STORE"
	fi
	while IFS= read -r line || [[ -n "$line" ]]; do
		n=$((n + 1))
		line=${line%$'\r'}
		[[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
		IFS=, read -r name addr secret type transport rest <<<"$line"
		name=$(echo "$name" | xargs); addr=$(echo "$addr" | xargs)
		type=$(echo "${type:-other}" | xargs); type=${type,,}; type=${type:-other}
		transport=$(echo "${transport:-udp}" | xargs); transport=${transport,,}; transport=${transport:-udp}
		# secrets may legitimately contain spaces; only trim the edges
		secret="${secret#"${secret%%[![:space:]]*}"}"; secret="${secret%"${secret##*[![:space:]]}"}"

		[[ "${name,,}" == name && "${addr,,}" == address ]] && continue   # header row
		[[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "$CLIENTS_FILE line $n: invalid client name '$name' (letters, digits, . _ - only)."
		[[ -z "${seen[$name]-}" ]] || die "$CLIENTS_FILE line $n: duplicate client name '$name'."
		seen[$name]=1
		[[ "$addr" =~ ^[0-9A-Fa-f:./]+$ ]] || die "$CLIENTS_FILE line $n: '$addr' is not an IPv4/IPv6 address or CIDR prefix."
		[[ "$type" =~ ^(cisco|cisco-nxos|juniper|other)$ ]] || die "$CLIENTS_FILE line $n: nas_type must be cisco, cisco-nxos, juniper or other (got '$type')."
		[[ "$transport" =~ ^(udp|radsec)$ ]] || die "$CLIENTS_FILE line $n: transport must be udp or radsec (got '$transport')."
		if [[ "$transport" == radsec ]] && ! is_yes "$RADSEC_ENABLE"; then
			die "$CLIENTS_FILE line $n: client '$name' uses radsec but RADSEC_ENABLE is not yes."
		fi

		local generated=0
		if [[ "$transport" == radsec ]]; then
			secret=radsec     # RFC 6614: the shared secret over TLS is always "radsec"
		elif [[ -z "$secret" && -n "${stored[$name]-}" ]]; then
			secret=${stored[$name]}
			generated=2
		elif [[ -z "$secret" ]]; then
			secret=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)
			generated=1
		elif (( ${#secret} < 16 )); then
			warn "Client '$name' has a shared secret shorter than 16 characters."
		fi

		CL_NAME+=("$name"); CL_ADDR+=("$addr"); CL_SECRET+=("$secret")
		CL_TYPE+=("$type"); CL_TRANSPORT+=("$transport"); CL_GENERATED+=("$generated")
	done <"$CLIENTS_FILE"
	(( ${#CL_NAME[@]} > 0 )) || die "$CLIENTS_FILE does not define any clients."
	info "${#CL_NAME[@]} RADIUS client(s) defined"
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
preflight() {
	step "Pre-flight checks"
	[[ $EUID -eq 0 ]] || die "Run this script as root (sudo)."
	# shellcheck disable=SC1091
	. /etc/os-release
	if [[ "${VERSION_ID%%.*}" != 9 || ! " ${ID-} ${ID_LIKE-} " =~ \ (rhel|centos|fedora)\  ]]; then
		warn "This script targets RHEL 9; detected ${PRETTY_NAME:-unknown}."
		confirm "Continue anyway?" || die "Aborted."
	else
		ok "${PRETTY_NAME}"
	fi
	command -v openssl >/dev/null || die "openssl is required (part of the RHEL base OS)."
	WORK=$(mktemp -d)
}

install_packages() {
	step "Installing FreeRADIUS packages"
	local pkgs=(freeradius freeradius-ldap freeradius-utils)
	if rpm -q "${pkgs[@]}" >/dev/null 2>&1; then
		ok "Already installed: $(rpm -q freeradius)"
		return
	fi
	if [[ -n "$RPM_DIR" ]]; then
		[[ -d "$RPM_DIR" ]] || die "RPM_DIR does not exist: $RPM_DIR"
		info "Installing from local RPMs in $RPM_DIR"
		dnf -y --disablerepo='*' install "$RPM_DIR"/*.rpm
	else
		dnf -y install "${pkgs[@]}"
	fi
	ok "Installed: $(rpm -q freeradius)"
}

backup_config() {
	step "Backing up current configuration"
	install -d -m 700 "$BACKUP_DIR"
	local ts; ts=$(date +%Y%m%d-%H%M%S)
	if [[ ! -f "$BACKUP_DIR/raddb-package-defaults.tar.gz" ]] && ! grep -rqs "install-freeradius.sh" "$RADDB/clients.conf"; then
		# Named "package-defaults" for compatibility; on a server that was already
		# configured by hand this holds that original configuration.
		tar --selinux --acls --xattrs -czf "$BACKUP_DIR/raddb-package-defaults.tar.gz" -C / etc/raddb
		info "Saved the configuration as it was before this installer first ran: $BACKUP_DIR/raddb-package-defaults.tar.gz"
	fi
	LAST_BACKUP="$BACKUP_DIR/raddb-$ts.tar.gz"
	tar --selinux --acls --xattrs -czf "$LAST_BACKUP" -C / etc/raddb
	systemctl is-active --quiet radiusd && WAS_ACTIVE=1
	ROLLBACK_ARMED=1
	ok "Backup: $LAST_BACKUP"
}

# Called by die() once the backup exists: put /etc/raddb back as it was. radiusd is
# only touched if this run already restarted it: then it is started again on the
# restored configuration (or left stopped if it was not running before).
rollback() {
	(( ROLLBACK_ARMED )) || return 0
	ROLLBACK_ARMED=0
	trap - ERR
	set +e
	warn "Restoring the previous configuration from $LAST_BACKUP"
	rm -rf "$RADDB"
	if ! tar --selinux --acls --xattrs -xzf "$LAST_BACKUP" -C /; then
		warn "Could not extract $LAST_BACKUP; restore it by hand with: $0 --restore $LAST_BACKUP"
		return 0
	fi
	command -v restorecon >/dev/null && restorecon -RF "$RADDB"
	# Keep the CRL refresh timer in line with the restored configuration.
	if [[ -f "$SITE_CERTS/crl-urls" && -x "$CRL_UPDATER" ]]; then
		systemctl enable --now freeradius-crl-update.timer >/dev/null 2>&1
	else
		systemctl disable --now freeradius-crl-update.timer >/dev/null 2>&1
	fi
	if (( ! RESTARTED )); then
		ok "Previous configuration restored; radiusd was not restarted and is unaffected"
	elif (( WAS_ACTIVE )); then
		if systemctl restart radiusd && sleep 2 && systemctl is-active --quiet radiusd; then
			ok "Previous configuration restored; radiusd is running on it again"
		else
			warn "Previous configuration restored, but radiusd does not start on it either. Check: journalctl -u radiusd"
		fi
	else
		systemctl stop radiusd >/dev/null 2>&1
		ok "Previous configuration restored (radiusd was not running before and is left stopped)"
	fi
}

restore_backup() {
	local file=$1
	require_file "Backup" "$file"
	[[ $EUID -eq 0 ]] || die "Run this script as root (sudo)."
	step "Restoring $file"
	systemctl stop radiusd 2>/dev/null || true
	rm -rf "$RADDB"
	tar --selinux --acls --xattrs -xzf "$file" -C /
	restorecon -RF "$RADDB" 2>/dev/null || true
	if radiusd -C >/dev/null 2>&1; then
		systemctl start radiusd && ok "Configuration restored and radiusd started."
	else
		warn "Configuration restored, but it does not pass 'radiusd -C'; radiusd left stopped."
	fi
}

# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

# Normalise any PEM bundle or single DER certificate into clean PEM.
normalize_certs() {
	local in=$1 out=$2
	if grep -q -- '-----BEGIN CERTIFICATE-----' "$in"; then
		openssl crl2pkcs7 -nocrl -certfile "$in" 2>/dev/null | openssl pkcs7 -print_certs 2>/dev/null |
			awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{p=0}' >"$out"
	else
		openssl x509 -inform DER -in "$in" -out "$out" 2>/dev/null || die "$in is not a PEM or DER certificate."
	fi
	[[ -s "$out" ]] || die "No certificates could be read from $in."
}

# Split a PEM bundle into <dir>/cert-N.pem, print the count.
split_certs() {
	local in=$1 dir=$2
	awk -v d="$dir" '/-----BEGIN CERTIFICATE-----/{n++; f=sprintf("%s/cert-%d.pem", d, n)} n{print > f} END{print n+0}' "$in"
}

pubkey_of_cert() { openssl x509 -noout -pubkey -in "$1" 2>/dev/null; }
pubkey_of_key()  { openssl pkey -pubout -in "$1" 2>/dev/null; }

# prepare_keypair LABEL CERT KEY KEYPASS CHAIN PFX PFXPASS OUT_BASENAME
#   Produces $SITE_CERTS/OUT.pem (leaf first, then chain) and OUT.key (unencrypted, 0640 root:radiusd)
prepare_keypair() {
	local label=$1 cert=$2 key=$3 keypass=$4 chain=$5 pfx=$6 pfxpass=$7 out=$8
	local d="$WORK/$out"; mkdir -p "$d"

	if [[ -n "$pfx" ]]; then
		local legacy=()
		export _FR_PFXPASS="$pfxpass"
		if ! openssl pkcs12 -in "$pfx" -passin env:_FR_PFXPASS -noout 2>/dev/null; then
			legacy=(-legacy)
			openssl pkcs12 "${legacy[@]}" -in "$pfx" -passin env:_FR_PFXPASS -noout 2>/dev/null ||
				die "$label: cannot open $pfx (wrong password or not a PKCS#12 file)."
		fi
		openssl pkcs12 "${legacy[@]}" -in "$pfx" -passin env:_FR_PFXPASS -nocerts -noenc -out "$d/key.raw" 2>/dev/null
		openssl pkcs12 "${legacy[@]}" -in "$pfx" -passin env:_FR_PFXPASS -nokeys -out "$d/certs.raw" 2>/dev/null
		unset _FR_PFXPASS
		openssl pkey -in "$d/key.raw" -out "$d/key.pem" 2>/dev/null || die "$label: no private key inside $pfx."
		normalize_certs "$d/certs.raw" "$d/certs.pem"
	else
		local passarg=(-passin pass:)
		if [[ -n "$keypass" ]]; then
			export _FR_KEYPASS="$keypass"
			passarg=(-passin env:_FR_KEYPASS)
		fi
		if ! openssl pkey "${passarg[@]}" -in "$key" -out "$d/key.pem" 2>/dev/null &&
			! openssl pkey "${passarg[@]}" -inform DER -in "$key" -out "$d/key.pem" 2>/dev/null; then
			unset _FR_KEYPASS
			die "$label: cannot read private key $key (encrypted? set the matching *_KEY_PASSWORD)."
		fi
		unset _FR_KEYPASS
		normalize_certs "$cert" "$d/certs.pem"
		if [[ -n "$chain" ]]; then
			normalize_certs "$chain" "$d/chain.pem"
			cat "$d/chain.pem" >>"$d/certs.pem"
		fi
	fi

	# Put the certificate that matches the key first, followed by the rest of the chain.
	local count i leaf="" keypub
	count=$(split_certs "$d/certs.pem" "$d")
	keypub=$(pubkey_of_key "$d/key.pem")
	for ((i = 1; i <= count; i++)); do
		if [[ "$(pubkey_of_cert "$d/cert-$i.pem")" == "$keypub" ]]; then leaf=$i; break; fi
	done
	[[ -n "$leaf" ]] || die "$label: none of the supplied certificates matches the private key."
	{
		cat "$d/cert-$leaf.pem"
		for ((i = 1; i <= count; i++)); do
			[[ $i -eq $leaf ]] && continue
			# skip exact duplicates of the leaf
			cmp -s "$d/cert-$i.pem" "$d/cert-$leaf.pem" || cat "$d/cert-$i.pem"
		done
	} >"$d/fullchain.pem"

	# Validate
	local verify_out
	if ! verify_out=$(openssl verify -CAfile "$SITE_CERTS/ca.pem" -untrusted "$d/fullchain.pem" "$d/cert-$leaf.pem" 2>&1); then
		die "$label: certificate does not chain to CA_CERT:
$verify_out"
	fi
	if ! openssl verify -purpose sslserver -CAfile "$SITE_CERTS/ca.pem" -untrusted "$d/fullchain.pem" "$d/cert-$leaf.pem" >/dev/null 2>&1; then
		warn "$label: certificate lacks the TLS Web Server Authentication (serverAuth) usage; Windows and many supplicants will refuse it."
	fi
	if ! openssl x509 -checkend 0 -noout -in "$d/cert-$leaf.pem" >/dev/null; then
		die "$label: certificate has expired."
	elif ! openssl x509 -checkend $((30 * 86400)) -noout -in "$d/cert-$leaf.pem" >/dev/null; then
		warn "$label: certificate expires within 30 days."
	fi

	install -m 0640 -o root -g radiusd "$d/fullchain.pem" "$SITE_CERTS/$out.pem"
	install -m 0640 -o root -g radiusd "$d/key.pem" "$SITE_CERTS/$out.key"
	ok "$label: $(openssl x509 -noout -subject -in "$d/cert-$leaf.pem" | sed 's/^subject=//'), expires $(openssl x509 -noout -enddate -in "$d/cert-$leaf.pem" | cut -d= -f2)"
}

install_certs() {
	step "Installing certificates"
	install -d -m 0750 -o root -g radiusd "$SITE_CERTS"

	normalize_certs "$CA_CERT" "$WORK/ca.pem"
	install -m 0640 -o root -g radiusd "$WORK/ca.pem" "$SITE_CERTS/ca.pem"
	ok "CA certificate(s): $(grep -c 'BEGIN CERTIFICATE' "$SITE_CERTS/ca.pem")"

	prepare_keypair "EAP server certificate" "$SERVER_CERT" "$SERVER_KEY" "$SERVER_KEY_PASSWORD" \
		"$SERVER_CHAIN" "$SERVER_PFX" "$SERVER_PFX_PASSWORD" server

	if is_yes "$RADSEC_ENABLE"; then
		if [[ -n "$RADSEC_PFX" || -n "$RADSEC_CERT" ]]; then
			prepare_keypair "RadSec server certificate" "$RADSEC_CERT" "$RADSEC_KEY" "$RADSEC_KEY_PASSWORD" \
				"$RADSEC_CHAIN" "$RADSEC_PFX" "$RADSEC_PFX_PASSWORD" radsec
		else
			install -m 0640 -o root -g radiusd "$SITE_CERTS/server.pem" "$SITE_CERTS/radsec.pem"
			install -m 0640 -o root -g radiusd "$SITE_CERTS/server.key" "$SITE_CERTS/radsec.key"
			info "RadSec uses the EAP server certificate"
		fi
		if [[ -n "$RADSEC_CLIENT_CA" ]]; then
			normalize_certs "$RADSEC_CLIENT_CA" "$WORK/radsec-client-ca.pem"
			install -m 0640 -o root -g radiusd "$WORK/radsec-client-ca.pem" "$SITE_CERTS/radsec-client-ca.pem"
		else
			install -m 0640 -o root -g radiusd "$SITE_CERTS/ca.pem" "$SITE_CERTS/radsec-client-ca.pem"
		fi
		ok "RadSec client CA installed"
	fi

	# CA(s) trusted to issue 802.1X client certificates. Keep this to your internal
	# issuing CA: any certificate it signed will pass EAP-TLS validation.
	if [[ -n "$EAP_CLIENT_CA" ]]; then
		normalize_certs "$EAP_CLIENT_CA" "$WORK/eap-client-ca.pem"
		install -m 0640 -o root -g radiusd "$WORK/eap-client-ca.pem" "$SITE_CERTS/eap-client-ca.pem"
	else
		install -m 0640 -o root -g radiusd "$SITE_CERTS/ca.pem" "$SITE_CERTS/eap-client-ca.pem"
	fi
	if [[ "$EAP_TLS" == yes ]]; then
		ok "802.1X client certificate CA: $(openssl x509 -noout -subject -in "$SITE_CERTS/eap-client-ca.pem" | sed 's/^subject=//')"
		# Compare the first base64 line of the CA certificate with the OS public trust bundle.
		local bundle=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
		if [[ -f "$bundle" ]] && grep -qxF "$(sed -n 2p "$SITE_CERTS/eap-client-ca.pem")" "$bundle"; then
			warn "The 802.1X client CA appears to be a PUBLIC CA. Anyone with a certificate from it could pass EAP-TLS; set EAP_CLIENT_CA to your internal issuing CA."
		fi
	fi

	if [[ -n "$LDAP_CA_CERT" ]]; then
		normalize_certs "$LDAP_CA_CERT" "$WORK/ldap-ca.pem"
		install -m 0640 -o root -g radiusd "$WORK/ldap-ca.pem" "$SITE_CERTS/ldap-ca.pem"
		LDAP_CA_PATH="$SITE_CERTS/ldap-ca.pem"
	else
		LDAP_CA_PATH=/etc/pki/tls/certs/ca-bundle.crt
	fi
}

# ---------------------------------------------------------------------------
# Certificate revocation (CRL) for EAP-TLS
#   CRLs are fetched over HTTP with curl (RHEL base OS), verified against the
#   client CA, placed in certs/site/crl and hashed. A systemd timer refreshes
#   them and restarts radiusd only when a CRL actually changed.
# ---------------------------------------------------------------------------
CRL_UPDATER=/usr/local/sbin/freeradius-crl-update

setup_crl() {
	if [[ "$EAP_TLS" != yes || -z "$CRL_URLS" ]]; then
		CRL_ENABLED=no
		systemctl disable --now freeradius-crl-update.timer >/dev/null 2>&1 || true
		rm -rf "$SITE_CERTS/crl"
		return 0
	fi
	step "Certificate revocation lists"
	install -d -m 0750 -o root -g radiusd "$SITE_CERTS/crl"
	printf '%s\n' $CRL_URLS >"$SITE_CERTS/crl-urls"
	chmod 0640 "$SITE_CERTS/crl-urls"

	cat >"$CRL_UPDATER" <<'EOF'
#!/usr/bin/env bash
# Managed by install-freeradius.sh
# Fetch the CRLs listed in /etc/raddb/certs/site/crl-urls for FreeRADIUS EAP-TLS.
# Usage: freeradius-crl-update [--no-restart]
set -uo pipefail
SITE=/etc/raddb/certs/site
DIR=$SITE/crl
CA=$SITE/eap-client-ca.pem
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
changed=0 failed=0 i=0
while read -r url; do
	[[ -z "$url" || "$url" == \#* ]] && continue
	i=$((i + 1))
	if ! curl -fsS --max-time 30 -o "$TMP/raw" "$url"; then
		echo "ERROR: could not download $url"; failed=1; continue
	fi
	if ! openssl crl -in "$TMP/raw" -out "$TMP/crl.pem" 2>/dev/null &&
	   ! openssl crl -inform DER -in "$TMP/raw" -out "$TMP/crl.pem" 2>/dev/null; then
		echo "ERROR: $url is not a CRL"; failed=1; continue
	fi
	if ! openssl crl -in "$TMP/crl.pem" -CAfile "$CA" -noout 2>&1 | grep -q 'verify OK'; then
		echo "ERROR: CRL from $url is not signed by a CA in $CA"; failed=1; continue
	fi
	next=$(openssl crl -in "$TMP/crl.pem" -noout -nextupdate | cut -d= -f2)
	if [[ -n "$next" ]] && (( $(date -d "$next" +%s) < $(date +%s) )); then
		echo "ERROR: CRL from $url expired at $next (is the CA publishing?)"; failed=1; continue
	fi
	dest="$DIR/crl-$i.pem"
	if ! cmp -s "$TMP/crl.pem" "$dest"; then
		install -m 0640 -o root -g radiusd "$TMP/crl.pem" "$dest"
		echo "Updated $dest from $url (next update $next)"
		changed=1
	fi
done <"$SITE/crl-urls"

if (( changed )); then
	openssl rehash "$DIR" >/dev/null 2>&1 || true
	command -v restorecon >/dev/null && restorecon -R "$DIR"
	if [[ "${1-}" != --no-restart ]] && systemctl is-active --quiet radiusd; then
		# EAP TLS contexts are only loaded at start-up
		systemctl restart radiusd && echo "radiusd restarted to load the new CRL(s)"
	fi
fi
exit $failed
EOF
	chmod 0750 "$CRL_UPDATER"

	cat >/etc/systemd/system/freeradius-crl-update.service <<EOF
[Unit]
Description=Refresh CRLs for FreeRADIUS EAP-TLS
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$CRL_UPDATER
EOF
	cat >/etc/systemd/system/freeradius-crl-update.timer <<'EOF'
[Unit]
Description=Refresh CRLs for FreeRADIUS EAP-TLS every 4 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=4h
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
	if ! "$CRL_UPDATER" --no-restart; then
		die "Could not fetch a valid CRL from CRL_URLS. Fix the URLs (they must be reachable over HTTP from this server), or leave CRL_URLS empty to skip revocation checking."
	fi
	systemctl daemon-reload
	systemctl enable --now freeradius-crl-update.timer >/dev/null 2>&1
	CRL_ENABLED=yes
	ok "CRL checking enabled; refreshed every 4 hours by freeradius-crl-update.timer"
}

# ---------------------------------------------------------------------------
# LDAP connectivity (TLS handshake + certificate check using openssl only)
# ---------------------------------------------------------------------------
declare -a LDAP_URIS LDAP_HOSTS LDAP_PORTS
build_ldap_uris() {
	local entry host port scheme defport
	case "$LDAP_SECURITY" in
		ldaps) scheme=ldaps; defport=636 ;;
		*)     scheme=ldap;  defport=389 ;;
	esac
	for entry in $LDAP_SERVERS; do
		entry=${entry#ldap://}; entry=${entry#ldaps://}
		if [[ "$entry" =~ ^\[(.*)\]:([0-9]+)$ ]]; then host=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
		elif [[ "$entry" =~ ^([^:]+):([0-9]+)$ ]]; then host=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
		else host=$entry; port=$defport; fi
		LDAP_HOSTS+=("$host"); LDAP_PORTS+=("$port")
		if [[ "$host" == *:* ]]; then LDAP_URIS+=("$scheme://[$host]:$port"); else LDAP_URIS+=("$scheme://$host:$port"); fi
	done
	(( ${#LDAP_URIS[@]} > 0 )) || die "LDAP_SERVERS is empty."
}

check_ldap() {
	step "Checking LDAP servers"
	local i host port out args
	for i in "${!LDAP_HOSTS[@]}"; do
		host=${LDAP_HOSTS[$i]}; port=${LDAP_PORTS[$i]}
		if [[ "$LDAP_SECURITY" == plain ]]; then
			if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
				ok "$host:$port reachable"
			else
				warn "$host:$port is not reachable from this server."
			fi
			continue
		fi
		args=(-connect "$host:$port" -CAfile "$LDAP_CA_PATH" -verify_return_error -verify_hostname "$host")
		[[ "$LDAP_SECURITY" == starttls ]] && args+=(-starttls ldap)
		if out=$(timeout 10 openssl s_client "${args[@]}" </dev/null 2>&1) && grep -q 'Verify return code: 0 (ok)' <<<"$out"; then
			ok "$host:$port TLS OK, certificate trusted and matches host name"
		else
			warn "$host:$port TLS check failed: $(grep -m1 -E 'verify error|Verify return code|connect|errno|error' <<<"$out" || echo 'no response')"
			warn "FreeRADIUS will not be able to reach this server until that is fixed."
		fi
	done
}

# ---------------------------------------------------------------------------
# FreeRADIUS configuration
# ---------------------------------------------------------------------------
write_ldap_module() {
	local user_base=${LDAP_USER_BASE_DN:-$LDAP_BASE_DN}
	local group_base=${LDAP_GROUP_BASE_DN:-$LDAP_BASE_DN}
	local uname='%{%{Stripped-User-Name}:-%{User-Name}}'
	local user_filter group_filter membership_filter start_tls=no uri

	if [[ "$LDAP_TYPE" == ad ]]; then
		# Enabled accounts only. People match on sAMAccountName or UPN; computers (802.1X
		# machine authentication, identity host/<fqdn>) match on dNSHostName or NAME\$.
		# Nested groups are resolved with LDAP_MATCHING_RULE_IN_CHAIN.
		user_filter="(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
		user_filter+="(|(&(objectCategory=person)(|(sAMAccountName=$uname)(userPrincipalName=%{User-Name})))"
		user_filter+="(&(objectCategory=computer)(|(dNSHostName=$uname)(sAMAccountName=$uname\$)))))"
		group_filter="(objectClass=group)"
		membership_filter="(member:1.2.840.113556.1.4.1941:=%{control:LDAP-UserDn})"
	else
		user_filter="(uid=$uname)"
		group_filter="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
		membership_filter="(|(member=%{control:LDAP-UserDn})(uniqueMember=%{control:LDAP-UserDn})(memberUid=$uname))"
	fi
	[[ "$LDAP_SECURITY" == starttls ]] && start_tls=yes

	{
		echo "$MANAGED_MARK"
		echo "ldap {"
		for uri in "${LDAP_URIS[@]}"; do
			echo "	server = $(cfq "$uri")"
		done
		cat <<EOF
	identity = $(cfq "$LDAP_BIND_DN")
	password = $(cfq "$LDAP_BIND_PASSWORD")
	base_dn = $(cfq "$LDAP_BASE_DN")

	user {
		base_dn = $(cfq "$user_base")
		filter = "$user_filter"
		scope = 'sub'
	}

	group {
		base_dn = $(cfq "$group_base")
		filter = '$group_filter'
		scope = 'sub'
		name_attribute = cn
		membership_filter = "$membership_filter"
		membership_attribute = 'memberOf'
		cacheable_name = 'no'
		cacheable_dn = 'no'
	}

	options {
		chase_referrals = no
		rebind = yes
		res_timeout = 10
		srv_timelimit = 5
		net_timeout = 3
		idle = 60
		probes = 3
		interval = 3
		ldap_debug = 0x0000
	}

	tls {
		start_tls = $start_tls
		ca_file = $(cfq "$LDAP_CA_PATH")
		require_cert = 'demand'
	}

	pool {
		# start = 0 lets radiusd start even if the directory is briefly unreachable at boot
		start = 0
		min = 1
		spare = 4
		max = \${thread[pool].max_servers}
		uses = 0
		retry_delay = 30
		lifetime = 0
		idle_timeout = 60
	}
}
EOF
	} >"$RADDB/mods-available/ldap"
	ln -sfn ../mods-available/ldap "$RADDB/mods-enabled/ldap"
	ok "LDAP module"
}

write_eap_module() {
	local default_type=ttls crl_opts ocsp_opts tls_sub="" ttls_sub=""
	[[ "$EAP_TLS" == yes ]] && default_type=tls

	if [[ "${CRL_ENABLED:-no}" == yes ]]; then
		crl_opts=$'\t\tca_path = ${certdir}/site/crl\n\t\tcheck_crl = yes\n\t\tcheck_all_crl = no'
	else
		crl_opts=$'\t\tcheck_crl = no'
	fi
	if [[ -n "$OCSP_URL" ]]; then
		ocsp_opts=$'\t\tocsp {\n\t\t\tenable = yes\n\t\t\toverride_cert_url = yes\n\t\t\turl = '"$(cfq "$OCSP_URL")"$'\n\t\t\tuse_nonce = yes\n\t\t\ttimeout = 3\n\t\t\tsoftfail = no\n\t\t}'
	else
		ocsp_opts=$'\t\tocsp {\n\t\t\tenable = no\n\t\t}'
	fi
	if [[ "$EAP_TLS" == yes ]]; then
		tls_sub=$'\n\t#  EAP-TLS: certificate validated against eap-client-ca.pem (+ CRL/OCSP), then the\n\t#  account is checked in AD by the "eap-tls-authz" virtual server.\n\ttls {\n\t\ttls = tls-common\n\t\tvirtual_server = "eap-tls-authz"\n\t}\n'
	fi
	if [[ "$EAP_TTLS" == yes ]]; then
		ttls_sub=$'\n\t#  EAP-TTLS with PAP inside: password checked by an LDAP bind.\n\tttls {\n\t\ttls = tls-common\n\t\tdefault_eap_type = md5\n\t\tvirtual_server = "ldap-inner-tunnel"\n\t\trequire_client_cert = no\n\t}\n'
	fi

	cat >"$RADDB/mods-available/eap" <<EOF
$MANAGED_MARK
eap {
	default_eap_type = $default_type
	timer_expire = 60
	ignore_unknown_eap_types = no
	cisco_accounting_username_bug = no
	max_sessions = \${max_requests}

	tls-config tls-common {
		private_key_file = \${certdir}/site/server.key
		certificate_file = \${certdir}/site/server.pem
		# Trust anchors for CLIENT certificates (EAP-TLS) - internal CA only
		ca_file = \${certdir}/site/eap-client-ca.pem
		auto_chain = yes
$crl_opts
		cipher_list = "PROFILE=SYSTEM"
		cipher_server_preference = yes
		# FreeRADIUS 3.0.x recommends TLS 1.2 as the maximum for EAP
		tls_min_version = "1.2"
		tls_max_version = "1.2"
		ecdh_curve = "prime256v1"
		fragment_size = 1024
		include_length = yes
		cache {
			enable = no
		}
		verify {
		}
$ocsp_opts
	}
$tls_sub$ttls_sub}
EOF
	ln -sfn ../mods-available/eap "$RADDB/mods-enabled/eap"
	ok "EAP module ($(echo "$EAP_METHODS" | sed 's/\bttls\b/EAP-TTLS\/PAP/; s/\btls\b/EAP-TLS/'))"
}

# Generates the unlang that decides the admin role; empty groups are skipped.
admin_role_unlang() {
	local first=1 kw
	if [[ -n "$ADMIN_GROUP_DN" ]]; then
		cat <<EOF
		if (LDAP-Group == $(cfq "$ADMIN_GROUP_DN")) {
			update control {
				&Tmp-String-0 := 'admin'
			}
		}
EOF
		first=0
	fi
	if [[ -n "$READONLY_GROUP_DN" ]]; then
		(( first )) && kw=if || kw=elsif
		cat <<EOF
		$kw (LDAP-Group == $(cfq "$READONLY_GROUP_DN")) {
			update control {
				&Tmp-String-0 := 'readonly'
			}
		}
EOF
		first=0
	fi
	if (( first )); then
		cat <<'EOF'
		update request {
			&Module-Failure-Message := 'Device administration disabled: no admin groups configured'
		}
		reject
EOF
	else
		cat <<'EOF'
		else {
			update request {
				&Module-Failure-Message := 'User is not in a network administrator group'
			}
			reject
		}
EOF
	fi
}

# EAPTLS_ACCOUNTS=computers: only machine identities (host/<fqdn>) may use EAP-TLS
computers_only_unlang() {
	[[ "$EAPTLS_ACCOUNTS" == computers ]] || return 0
	cat <<'EOF'
		if (!(&User-Name =~ /^host\/.+$/i)) {
			update request {
				&Module-Failure-Message := "Only computer certificates are allowed (identity '%{User-Name}' is not host/<fqdn>)"
			}
			reject
		}
EOF
}

dot1x_group_unlang() {
	[[ -z "$DOT1X_GROUP_DN" ]] && return 0
	cat <<EOF
		if (!(LDAP-Group == $(cfq "$DOT1X_GROUP_DN"))) {
			update request {
				&Module-Failure-Message := 'Account is not in the 802.1X access group'
			}
			reject
		}
EOF
}

# unlang for "first matching group wins" VLAN assignment
vlan_unlang() {
	local i kw=if attrs
	vlan_reply() {
		printf '\t\tupdate reply {\n\t\t\t&Tunnel-Type := VLAN\n\t\t\t&Tunnel-Medium-Type := IEEE-802\n\t\t\t&Tunnel-Private-Group-Id := %s\n\t\t}\n' "$(cfq "$1")"
	}
	if (( ${#VL_GROUP[@]} == 0 )); then
		if [[ -n "$DEFAULT_VLAN" ]]; then
			vlan_reply "$DEFAULT_VLAN" | sed 's/^\t//'
		else
			printf '\tnoop\n'
		fi
		return
	fi
	for i in "${!VL_GROUP[@]}"; do
		printf '\t%s (LDAP-Group == %s) {\n' "$kw" "$(cfq "${VL_GROUP[$i]}")"
		vlan_reply "${VL_VLAN[$i]}"
		printf '\t}\n'
		kw=elsif
	done
	if [[ -n "$DEFAULT_VLAN" ]]; then
		printf '\telse {\n'
		vlan_reply "$DEFAULT_VLAN"
		printf '\t}\n'
	fi
}

# unlang that binds the EAP identity to the client certificate
identity_check_unlang() {
	local dict=/usr/share/freeradius/dictionary.freeradius.internal upn=yes
	if [[ -f "$dict" ]] && ! grep -q 'TLS-Client-Cert-Subject-Alt-Name-Upn' "$dict"; then
		upn=no
		warn "This FreeRADIUS build has no TLS-Client-Cert-Subject-Alt-Name-Upn; user certificates are matched on CN only."
	fi
	cat <<'EOF'
#  The EAP identity must belong to the certificate that was presented, so that a
#  valid certificate cannot be used to claim another account's groups/VLAN.
#    computers: host/<fqdn>  must match a DNS SAN or the CN of the certificate
#    users:     user@domain  must match the UPN SAN, or user / user@domain the CN
eap_tls_check_identity {
	if (&User-Name =~ /^host\/(.+)$/i) {
		if (&TLS-Client-Cert-Common-Name && ("%{tolower:%{TLS-Client-Cert-Common-Name}}" == "%{tolower:%{1}}")) {
			update control {
				&Tmp-String-1 := 'bound'
			}
		}
		update request {
			&Tmp-String-2 := "%{tolower:%{1}}"
		}
		foreach &TLS-Client-Cert-Subject-Alt-Name-Dns {
			if ("%{tolower:%{Foreach-Variable-0}}" == "%{Tmp-String-2}") {
				update control {
					&Tmp-String-1 := 'bound'
				}
			}
		}
	}
	else {
		if (&TLS-Client-Cert-Common-Name && (("%{tolower:%{TLS-Client-Cert-Common-Name}}" == "%{tolower:%{User-Name}}") || ("%{tolower:%{TLS-Client-Cert-Common-Name}}" == "%{tolower:%{Stripped-User-Name}}"))) {
			update control {
				&Tmp-String-1 := 'bound'
			}
		}
EOF
	if [[ "$upn" == yes ]]; then
		cat <<'EOF'
		foreach &TLS-Client-Cert-Subject-Alt-Name-Upn {
			if ("%{tolower:%{Foreach-Variable-0}}" == "%{tolower:%{User-Name}}") {
				update control {
					&Tmp-String-1 := 'bound'
				}
			}
		}
EOF
	fi
	cat <<'EOF'
	}
	#  Test for presence: in 3.0 a comparison against a missing attribute is an
	#  evaluation error, not "false", so !(... == 'bound') would never reject.
	if (!&control:Tmp-String-1) {
		update request {
			&Module-Failure-Message := "EAP identity '%{User-Name}' does not match the client certificate (CN '%{TLS-Client-Cert-Common-Name}')"
		}
		reject
	}
}
EOF
}

write_policy() {
	{
		cat <<'EOF'
# Managed by install-freeradius.sh - re-run the installer instead of editing by hand.

#  Map the EAP / login identity to the directory name in Stripped-User-Name:
#    host/PC01.corp.example.com -> pc01.corp.example.com (computer, matched on dNSHostName)
#    jdoe@corp.example.com      -> jdoe
#  DOMAIN\user is not supported.
ldap_strip_realm {
	if (&User-Name =~ /^host\/(.+)$/i) {
		update request {
			&Stripped-User-Name := "%{tolower:%{1}}"
		}
	}
	elsif (&User-Name =~ /^([^@]+)@[^@]+$/) {
		update request {
			&Stripped-User-Name := "%{1}"
		}
	}
}

#  Refuse empty passwords before they reach the directory
#  (an LDAP bind with an empty password is an anonymous bind).
require_password {
	if (!&User-Password || (&User-Password == '')) {
		update request {
			&Module-Failure-Message := 'No password supplied'
		}
		reject
	}
}

#  Look the account up in LDAP (enabled accounts only) and reject if it is not there.
ldap_require_account {
	ldap
	if (notfound) {
		update request {
			&Module-Failure-Message := "Account '%{%{Stripped-User-Name}:-%{User-Name}}' not found or disabled in the directory"
		}
		reject
	}
}

#  Look the user up, then verify the password with an LDAP bind.
ldap_lookup_and_bind {
	ldap_require_account
	update control {
		&Auth-Type := LDAP
	}
}

EOF
		echo "#  802.1X VLAN assignment: first matching group wins."
		echo "assign_vlan {"
		vlan_unlang
		echo "}"
		echo
		if is_yes "$EAPTLS_CHECK_IDENTITY"; then
			identity_check_unlang
		else
			printf 'eap_tls_check_identity {\n\tnoop\n}\n'
		fi
	} >"$RADDB/policy.d/ldap_auth"
	ok "Policies (${#VL_GROUP[@]} VLAN mapping(s)${DEFAULT_VLAN:+, default VLAN $DEFAULT_VLAN})"
}

write_sites() {
	local listen6=""
	if [[ "$LISTEN_IPV6" == yes ]]; then
		listen6=$(cat <<'EOF'

	listen {
		type = auth
		ipv6addr = ::
		port = 0
	}
	listen {
		type = acct
		ipv6addr = ::
		port = 0
	}
EOF
)
	fi

	cat >"$RADDB/sites-available/radius-ldap" <<EOF
$MANAGED_MARK
#
#  Main virtual server.
#    * 802.1X (EAP) requests go to the eap module. EAP-TLS accounts are checked in
#      "eap-tls-authz", EAP-TTLS passwords in "ldap-inner-tunnel". On success the
#      VLAN is assigned from AD group membership (policy assign_vlan).
#    * Plain PAP requests are treated as network device administrator logins and
#      are authorised by LDAP group, with privilege attributes set per nas_type.
#
server radius-ldap {
	listen {
		type = auth
		ipaddr = *
		port = 0
	}
	listen {
		type = acct
		ipaddr = *
		port = 0
	}$listen6

	authorize {
		filter_username
		preprocess
		ldap_strip_realm

		if (&EAP-Message) {
			eap
			return
		}

		# ---- Network device administrator login (PAP) ----
		if ((&Service-Type == Framed-User) || (&Service-Type == Call-Check)) {
			update request {
				&Module-Failure-Message := 'Non-EAP network access (MAB/PPP) is not supported'
			}
			reject
		}
		require_password
		ldap_lookup_and_bind
$(admin_role_unlang)
	}

	authenticate {
		eap
		Auth-Type LDAP {
			ldap
		}
	}

	preacct {
		preprocess
		acct_unique
	}

	accounting {
		detail
		attr_filter.accounting_response
	}

	post-auth {
		if (&control:Tmp-String-0 && (&control:Tmp-String-0 == 'admin')) {
			switch "%{client:nas_type}" {
				case "cisco" {
					update reply {
						&Cisco-AVPair += 'shell:priv-lvl=15'
					}
				}
				case "cisco-nxos" {
					update reply {
						&Cisco-AVPair += 'shell:roles="network-admin"'
					}
				}
				case "juniper" {
					update reply {
						&Juniper-Local-User-Name := $(cfq "$JUNIPER_ADMIN_USER")
					}
				}
				case {
					update reply {
						&Service-Type := Administrative-User
					}
				}
			}
		}
		elsif (&control:Tmp-String-0 && (&control:Tmp-String-0 == 'readonly')) {
			switch "%{client:nas_type}" {
				case "cisco" {
					update reply {
						&Cisco-AVPair += 'shell:priv-lvl=1'
					}
				}
				case "cisco-nxos" {
					update reply {
						&Cisco-AVPair += 'shell:roles="network-operator"'
					}
				}
				case "juniper" {
					update reply {
						&Juniper-Local-User-Name := $(cfq "$JUNIPER_READONLY_USER")
					}
				}
				case {
					update reply {
						&Service-Type := NAS-Prompt-User
					}
				}
			}
		}
		# ---- 802.1X: VLAN from AD groups ----
		elsif (&session-state:Tmp-String-3 && (&session-state:Tmp-String-3 == 'ttls')) {
			# EAP-TTLS: decided in the inner tunnel (the outer identity may be anonymous)
			update reply {
				&Tunnel-Type := &session-state:Tunnel-Type
				&Tunnel-Medium-Type := &session-state:Tunnel-Medium-Type
				&Tunnel-Private-Group-Id := &session-state:Tunnel-Private-Group-Id
			}
		}
		elsif (&EAP-Message) {
			# EAP-TLS: the identity was bound to the certificate in eap-tls-authz
			assign_vlan
		}

		Post-Auth-Type REJECT {
			attr_filter.access_reject
			eap
			remove_reply_message_if_eap
		}
	}
}
EOF

	cat >"$RADDB/sites-available/eap-tls-authz" <<EOF
$MANAGED_MARK
#
#  Runs after a successful EAP-TLS handshake (the certificate already passed chain,
#  expiry and CRL/OCSP checks). Equivalent of NPS mapping the certificate to an AD
#  account: the account must exist and be enabled, the identity must match the
#  certificate, and (optionally) the account must be in the 802.1X group.
#
server eap-tls-authz {
	authorize {
$(computers_only_unlang)
		ldap_strip_realm
		eap_tls_check_identity
		ldap_require_account
$(dot1x_group_unlang)
		update control {
			&Auth-Type := Accept
		}
	}
}
EOF

	cat >"$RADDB/sites-available/ldap-inner-tunnel" <<EOF
$MANAGED_MARK
#
#  Inner tunnel for EAP-TTLS: the real username and password (PAP) arrive here.
#
server ldap-inner-tunnel {
	authorize {
		filter_username
		require_password
		ldap_strip_realm
		ldap_lookup_and_bind
$(dot1x_group_unlang)
	}

	authenticate {
		Auth-Type LDAP {
			ldap
		}
	}

	post-auth {
		assign_vlan
		# hand the VLAN to the outer server (see post-auth in radius-ldap)
		update outer.session-state {
			&Tmp-String-3 := 'ttls'
			&Tunnel-Type := &reply:Tunnel-Type
			&Tunnel-Medium-Type := &reply:Tunnel-Medium-Type
			&Tunnel-Private-Group-Id := &reply:Tunnel-Private-Group-Id
		}
		Post-Auth-Type REJECT {
			attr_filter.access_reject
		}
	}
}
EOF

	cat >"$RADDB/sites-available/ldap-test" <<EOF
$MANAGED_MARK
#
#  Local diagnostics only (127.0.0.1:18120, used by install-freeradius.sh --test).
#  Runs the 802.1X directory checks for an account and returns the VLAN it would
#  get. The password is verified when one is sent; without one only the account
#  and group checks run (so computer accounts such as host/pc01.corp.example.com
#  can be tested). Not reachable from the network.
#
server ldap-test {
	listen {
		ipaddr = 127.0.0.1
		port = 18120
		type = auth
	}

	authorize {
		ldap_strip_realm
		ldap_require_account
$(dot1x_group_unlang)
		if (&User-Password) {
			update control {
				&Auth-Type := LDAP
			}
		}
		else {
			update control {
				&Auth-Type := Accept
			}
		}
	}

	authenticate {
		Auth-Type LDAP {
			ldap
		}
	}

	post-auth {
		assign_vlan
	}
}
EOF

	local site
	rm -f "$RADDB/sites-enabled/default" "$RADDB/sites-enabled/inner-tunnel"
	for site in radius-ldap ldap-test eap-tls-authz ldap-inner-tunnel; do
		rm -f "$RADDB/sites-enabled/$site"
	done
	local enabled=(radius-ldap ldap-test)
	[[ "$EAP_TLS" == yes ]] && enabled+=(eap-tls-authz)
	[[ "$EAP_TTLS" == yes ]] && enabled+=(ldap-inner-tunnel)
	for site in "${enabled[@]}"; do
		ln -sfn "../sites-available/$site" "$RADDB/sites-enabled/$site"
	done
	ok "Virtual servers: ${enabled[*]}"
}

client_block() {
	local name=$1 addr=$2 secret=$3 type=$4 proto=$5 addrkey=ipaddr
	[[ "$addr" == *:* ]] && addrkey=ipv6addr
	cat <<EOF
	client $name {
		$addrkey = $addr
		secret = $(cfq "$secret")
		shortname = $name
		nas_type = $type
EOF
	[[ -n "$proto" ]] && printf '\t\tproto = %s\n' "$proto"
	printf '\t}\n'
}

write_clients() {
	local i local_secret
	local_secret=$(openssl rand -hex 16)
	{
		echo "$MANAGED_MARK"
		echo "#  Edit clients.csv and re-run the installer to change this list."
		echo
		echo "#  Used by 'install-freeradius.sh --test'"
		client_block localhost 127.0.0.1 "$local_secret" other "" | sed 's/^\t//'
		for i in "${!CL_NAME[@]}"; do
			[[ "${CL_TRANSPORT[$i]}" == udp ]] || continue
			echo
			client_block "${CL_NAME[$i]}" "${CL_ADDR[$i]}" "${CL_SECRET[$i]}" "${CL_TYPE[$i]}" "" | sed 's/^\t//'
		done
	} >"$RADDB/clients.conf"

	# Keep every generated secret (new or reused) so the next run reuses it.
	install -d -m 700 "$STATE_DIR"
	(
		umask 077
		for i in "${!CL_NAME[@]}"; do
			if (( CL_GENERATED[i] )); then printf '%s,%s\n' "${CL_NAME[$i]}" "${CL_SECRET[$i]}"; fi
		done >"$SECRETS_STORE"
	)

	# Hand out only the secrets that are new in this run, so they can be configured on the devices.
	NEW_SECRETS=0
	for i in "${!CL_NAME[@]}"; do (( CL_GENERATED[i] == 1 )) && NEW_SECRETS=1; done
	if (( NEW_SECRETS )); then
		{
			echo "# FreeRADIUS shared secrets generated $(date -Is). Configure these on the devices, then delete this file."
			echo "# They are kept (root-only) in $SECRETS_STORE and reused when the installer is re-run."
			for i in "${!CL_NAME[@]}"; do
				(( CL_GENERATED[i] == 1 )) && printf '%s,%s,%s\n' "${CL_NAME[$i]}" "${CL_ADDR[$i]}" "${CL_SECRET[$i]}"
			done
		} >"$SECRETS_OUT"
		chmod 600 "$SECRETS_OUT"
	fi
	local udp=0
	for i in "${!CL_NAME[@]}"; do [[ "${CL_TRANSPORT[$i]}" == udp ]] && udp=$((udp + 1)); done
	ok "clients.conf ($udp UDP client(s))"
}

write_radsec() {
	if ! is_yes "$RADSEC_ENABLE"; then
		rm -f "$RADDB/sites-enabled/radsec"
		info "RadSec disabled"
		return
	fi

	# Older 3.0 builds only accept "auth" on a TLS listener; use auth+acct when the package supports it.
	local ltype=auth
	if grep -qE '^[[:space:]]*#?[[:space:]]*type[[:space:]]*=[[:space:]]*auth\+acct' "$RADDB/sites-available/tls" 2>/dev/null; then
		ltype=auth+acct
	else
		warn "This FreeRADIUS build does not advertise auth+acct on TLS listeners; RadSec will carry authentication only."
	fi

	local i
	{
		cat <<EOF
$MANAGED_MARK
#
#  RadSec (RFC 6614): RADIUS over TLS on TCP/$RADSEC_PORT.
#  Network devices must present a client certificate issued by radsec-client-ca.pem.
#
listen {
	ipaddr = *
	port = $RADSEC_PORT
	type = $ltype
	proto = tcp
	virtual_server = radius-ldap
	clients = radsec

	limit {
		max_connections = 64
		lifetime = 0
		idle_timeout = 900
	}

	tls {
		private_key_file = \${certdir}/site/radsec.key
		certificate_file = \${certdir}/site/radsec.pem
		ca_file = \${certdir}/site/radsec-client-ca.pem
		auto_chain = yes
		require_client_cert = yes
		cipher_list = "PROFILE=SYSTEM"
		cipher_server_preference = yes
		tls_min_version = "1.2"
		tls_max_version = "1.2"
		ecdh_curve = "prime256v1"
		fragment_size = 8192
		check_crl = no
		cache {
			enable = no
		}
		verify {
		}
	}
}
EOF
		if [[ "$LISTEN_IPV6" == yes ]]; then
			cat <<EOF

listen {
	ipv6addr = ::
	port = $RADSEC_PORT
	type = $ltype
	proto = tcp
	virtual_server = radius-ldap
	clients = radsec

	limit {
		max_connections = 64
		lifetime = 0
		idle_timeout = 900
	}

	tls {
		private_key_file = \${certdir}/site/radsec.key
		certificate_file = \${certdir}/site/radsec.pem
		ca_file = \${certdir}/site/radsec-client-ca.pem
		auto_chain = yes
		require_client_cert = yes
		cipher_list = "PROFILE=SYSTEM"
		cipher_server_preference = yes
		tls_min_version = "1.2"
		tls_max_version = "1.2"
		ecdh_curve = "prime256v1"
		fragment_size = 8192
		check_crl = no
		cache {
			enable = no
		}
		verify {
		}
	}
}
EOF
		fi
		echo
		echo "clients radsec {"
		local count=0
		for i in "${!CL_NAME[@]}"; do
			[[ "${CL_TRANSPORT[$i]}" == radsec ]] || continue
			client_block "${CL_NAME[$i]}" "${CL_ADDR[$i]}" radsec "${CL_TYPE[$i]}" tls
			count=$((count + 1))
		done
		if (( count == 0 )); then
			# FreeRADIUS needs at least one client in the section; this one can never connect.
			client_block radsec-placeholder 127.0.0.1 radsec other tls
		fi
		echo "}"
	} >"$RADDB/sites-available/radsec"
	ln -sfn ../sites-available/radsec "$RADDB/sites-enabled/radsec"
	ok "RadSec listener on TCP/$RADSEC_PORT ($ltype)"
}

tweak_radiusd_conf() {
	# Log accepts/rejects to /var/log/radius/radius.log (passwords are never logged).
	sed -i -E 's/^([[:space:]]*)auth = no$/\1auth = yes/' "$RADDB/radiusd.conf"
	ok "Authentication logging enabled"
}

fix_permissions() {
	local f
	for f in mods-available/ldap mods-available/eap policy.d/ldap_auth clients.conf \
		sites-available/radius-ldap sites-available/ldap-inner-tunnel sites-available/radsec \
		sites-available/eap-tls-authz sites-available/ldap-test; do
		[[ -f "$RADDB/$f" ]] || continue
		chown root:radiusd "$RADDB/$f"
		chmod 0640 "$RADDB/$f"
	done
	chown -R root:radiusd "$SITE_CERTS"
	if command -v restorecon >/dev/null; then
		restorecon -RF "$RADDB"
	fi
}

check_config() {
	step "Checking FreeRADIUS configuration"
	local log="$WORK/radiusd-check.log"
	if radiusd -XC >"$log" 2>&1; then
		ok "radiusd -XC passed"
		return
	fi
	echo "---- last 40 lines of 'radiusd -XC' ----" >&2
	tail -n 40 "$log" >&2
	echo "----------------------------------------" >&2
	cp "$log" "$STATE_DIR/last-failed-check.log"
	die "Configuration check failed. Full log: $STATE_DIR/last-failed-check.log"
}

# Another enabled virtual server listening on a port we use makes radiusd fail at
# start-up ("Address already in use"), which 'radiusd -XC' does not detect.
check_listener_conflicts() {
	local f base conflicts=""
	local ours=" radius-ldap ldap-test eap-tls-authz ldap-inner-tunnel radsec "
	local tcp_port=""
	is_yes "$RADSEC_ENABLE" && tcp_port=$RADSEC_PORT
	for f in "$RADDB"/sites-enabled/*; do
		[[ -e "$f" ]] || continue
		base=${f##*/}
		[[ "$ours" == *" $base "* ]] && continue
		# Print "proto port" for every listen section (port 0 / unset = the type's default).
		while read -r proto port; do
			if [[ "$proto" == udp && " 1812 1813 18120 " == *" $port "* ]] ||
				[[ "$proto" == tcp && -n "$tcp_port" && "$port" == "$tcp_port" ]]; then
				conflicts+=$'\n'"      sites-enabled/$base listens on ${proto^^}/$port"
			fi
		done < <(awk '
			{ sub(/#.*/, "") }
			/(^|[[:space:]])listen[[:space:]]*\{/ && !inl { inl = 1; ld = depth; type = ""; port = ""; proto = "udp" }
			inl && depth == ld + 1 {
				if ($0 ~ /^[[:space:]]*type[[:space:]]*=/)  { v = $0; sub(/.*=[[:space:]]*/, "", v); gsub(/[[:space:]"\x27]/, "", v); type = v }
				if ($0 ~ /^[[:space:]]*port[[:space:]]*=/)  { v = $0; sub(/.*=[[:space:]]*/, "", v); gsub(/[[:space:]"\x27]/, "", v); port = v }
				if ($0 ~ /^[[:space:]]*proto[[:space:]]*=/) { v = $0; sub(/.*=[[:space:]]*/, "", v); gsub(/[[:space:]"\x27]/, "", v); proto = v }
			}
			{
				o = gsub(/\{/, "{"); c = gsub(/\}/, "}"); depth += o - c
				if (inl && depth <= ld) {
					if (port == "" || port == "0") port = (type == "acct") ? 1813 : (type ~ /^auth/) ? 1812 : ""
					if (port != "") print proto, port
					inl = 0
				}
			}' "$f")
	done
	[[ -z "$conflicts" ]] && return 0
	die "Other enabled virtual servers use ports this configuration needs:$conflicts
    Disable them (remove the link in $RADDB/sites-enabled/) or change their ports, then re-run."
}

configure_selinux() {
	command -v getenforce >/dev/null || return 0
	[[ "$(getenforce)" == Disabled ]] && return 0
	step "SELinux"
	if is_yes "$RADSEC_ENABLE"; then
		if ! command -v semanage >/dev/null; then
			warn "semanage not available; ensure TCP/$RADSEC_PORT is labelled radius_port_t."
		elif semanage port -l | awk '$1=="radius_port_t" && $2=="tcp"' | grep -qE "[ ,]$RADSEC_PORT(,|$)"; then
			ok "TCP/$RADSEC_PORT already labelled radius_port_t"
		else
			semanage port -a -t radius_port_t -p tcp "$RADSEC_PORT" 2>/dev/null ||
				semanage port -m -t radius_port_t -p tcp "$RADSEC_PORT"
			ok "Labelled TCP/$RADSEC_PORT as radius_port_t"
		fi
	fi
	ok "File contexts restored on $RADDB"
}

configure_firewall() {
	is_yes "$OPEN_FIREWALL" || return 0
	step "Firewall"
	local extra=""
	is_yes "$RADSEC_ENABLE" && extra=" and TCP/$RADSEC_PORT"
	if ! systemctl is-active --quiet firewalld; then
		warn "firewalld is not running; open UDP 1812-1813$extra yourself if needed."
		return
	fi
	firewall-cmd --permanent --add-service=radius >/dev/null
	if is_yes "$RADSEC_ENABLE"; then
		firewall-cmd --permanent --add-port="$RADSEC_PORT/tcp" >/dev/null
	fi
	firewall-cmd --reload >/dev/null
	ok "Opened RADIUS (1812-1813)$extra in zone $(firewall-cmd --get-default-zone)"
}

start_service() {
	step "Starting radiusd"
	systemctl enable radiusd >/dev/null 2>&1
	RESTARTED=1
	systemctl restart radiusd || true
	sleep 2
	if systemctl is-active --quiet radiusd; then
		ok "radiusd is running"
	else
		journalctl -u radiusd -n 30 --no-pager >&2 || true
		tar -czf "$STATE_DIR/last-failed-config.tar.gz" -C / etc/raddb 2>/dev/null || true
		die "radiusd failed to start with the new configuration (saved as $STATE_DIR/last-failed-config.tar.gz for debugging)."
	fi
	ROLLBACK_ARMED=0
	if command -v ausearch >/dev/null && ausearch -m avc -c radiusd -ts recent >/dev/null 2>&1; then
		warn "SELinux denials for radiusd were logged; review with: ausearch -m avc -c radiusd -ts recent"
	fi
}

summary() {
	local cn san methods="" revocation="none (disable the AD account to block a device)"
	[[ "$EAP_TLS" == yes ]] && methods="EAP-TLS ('Microsoft: Smart Card or other certificate', NOT inside PEAP)"
	[[ "$EAP_TTLS" == yes ]] && methods+="${methods:+; }EAP-TTLS with PAP"
	[[ "${CRL_ENABLED:-no}" == yes ]] && revocation="CRL, refreshed every 4h (freeradius-crl-update.timer)"
	if [[ -n "$OCSP_URL" ]]; then
		revocation="OCSP $OCSP_URL"
		[[ "${CRL_ENABLED:-no}" == yes ]] && revocation+=" + CRL"
	fi
	cn=$(openssl x509 -noout -subject -nameopt multiline -in "$SITE_CERTS/server.pem" | awk -F' = ' '/commonName/{print $2}')
	san=$(openssl x509 -noout -ext subjectAltName -in "$SITE_CERTS/server.pem" 2>/dev/null | tail -n +2 | xargs || true)
	step "Done"
	cat <<EOF
    Ports      : UDP 1812 (auth), UDP 1813 (acct)$(is_yes "$RADSEC_ENABLE" && echo ", TCP $RADSEC_PORT (RadSec)")
    Logs       : /var/log/radius/radius.log   (accept/reject with reason)
    Backups    : $BACKUP_DIR

    802.1X supplicant settings (Windows wired GPO)
      EAP method          : $methods
      Trusted root CA     : $(openssl x509 -noout -subject -in "$SITE_CERTS/ca.pem" | sed 's/^subject=//')
      Server name to check: ${cn:-?}${san:+   (SAN: $san)}
      Revocation checking : $revocation
      VLAN mappings       : ${#VL_GROUP[@]}${DEFAULT_VLAN:+ (default VLAN $DEFAULT_VLAN)}

    Network device administration
      Full admin group    : ${ADMIN_GROUP_DN:-<not set>}
      Read-only group     : ${READONLY_GROUP_DN:-<not set>}

    Test a login:   sudo $0 --test
    Troubleshoot:   sudo systemctl stop radiusd && sudo radiusd -X
EOF
	if (( ${NEW_SECRETS:-0} )); then
		echo
		warn "New shared secrets were generated for some clients: $SECRETS_OUT (root-only). Configure them on the devices, then delete the file."
	fi
}

# ---------------------------------------------------------------------------
# --test
# ---------------------------------------------------------------------------
run_tests() {
	[[ $EUID -eq 0 ]] || die "Run this script as root (sudo)."
	command -v radclient >/dev/null || die "radclient not found (freeradius-utils)."
	systemctl is-active --quiet radiusd || die "radiusd is not running."
	local secret user pass esc_user esc_pass
	secret=$(sed -n "/^client localhost {/,/}/s/^[[:space:]]*secret = '\([0-9a-f]*\)'\$/\1/p" "$RADDB/clients.conf")
	[[ -n "$secret" ]] || die "Could not find the localhost client secret in $RADDB/clients.conf."
	echo "Enter a user (jdoe or jdoe@corp.example.com) or a computer (host/pc01.corp.example.com)."
	read -r -p "Account to test: " user
	read -r -s -p "Password (leave blank for computers / to skip the password check): " pass; echo
	esc_user=${user//\\/\\\\}; esc_user=${esc_user//\"/\\\"}
	esc_pass=${pass//\\/\\\\}; esc_pass=${esc_pass//\"/\\\"}

	step "802.1X directory checks and VLAN (127.0.0.1:18120)"
	info "Account enabled, 802.1X group, password (if given) -> Tunnel-Private-Group-Id is the VLAN"
	{
		printf 'User-Name = "%s"\n' "$esc_user"
		[[ -n "$pass" ]] && printf 'User-Password = "%s"\n' "$esc_pass"
	} | radclient -x -r 1 -t 5 127.0.0.1:18120 auth "$secret" 2>&1 | grep -vi 'password' || true
	info "EAP-TLS also requires a valid certificate whose name matches the identity; that part can only be tested from a real workstation."

	if [[ -n "$pass" && "$user" != host/* ]]; then
		step "Network device administrator login (UDP 1812, PAP)"
		printf 'User-Name = "%s"\nUser-Password = "%s"\nService-Type = Login-User\n' "$esc_user" "$esc_pass" |
			radclient -x -r 1 -t 5 127.0.0.1:1812 auth "$secret" 2>&1 | grep -vi 'password' || true
	fi

	echo
	info "Reject reasons are logged in /var/log/radius/radius.log"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
	while (( $# )); do
		case "$1" in
			-c|--config) CONFIG_FILE=${2:?--config needs a file}; shift ;;
			-y|--yes) ASSUME_YES=1 ;;
			--test) MODE=test ;;
			--restore) MODE=restore; RESTORE_FILE=${2:?--restore needs a file}; shift ;;
			-h|--help) usage; exit 0 ;;
			*) usage; die "Unknown option: $1" ;;
		esac
		shift
	done

	case "$MODE" in
		test) run_tests; exit 0 ;;
		restore) restore_backup "$RESTORE_FILE"; exit 0 ;;
	esac

	printf '%sFreeRADIUS installer for RHEL 9 (802.1X EAP-TLS + AD VLANs + device admin + RadSec)%s\n' "$C_BLD" "$C_RST"
	preflight
	load_config
	gather_answers
	validate_answers
	build_ldap_uris
	install_packages
	backup_config
	install_certs
	setup_crl
	check_ldap
	step "Writing FreeRADIUS configuration"
	write_ldap_module
	write_eap_module
	write_policy
	write_sites
	write_clients
	write_radsec
	check_listener_conflicts
	tweak_radiusd_conf
	fix_permissions
	check_config
	configure_selinux
	configure_firewall
	start_service
	summary
}

main "$@"
