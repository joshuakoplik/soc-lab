# Extends the stock wordpress:7.0.1-php8.3-apache image with a second,
# independent vulnerability: CVE-2025-32463, a local privilege-escalation
# flaw in sudo's -R/--chroot handling (sudo switches into the attacker-
# specified chroot directory -- and loads an nsswitch.conf / NSS module
# from inside it -- before fully evaluating the caller's sudoers
# privileges). Affects sudo 1.9.14 through 1.9.17 inclusive, fixed in
# 1.9.17p1; CVSS 9.3, exploitable by ANY local user regardless of sudoers
# entries (confirmed live against this exact build: an unprivileged user
# invoking `sudo -R <dir> ...` is prompted for a password rather than
# rejected with "not in the sudoers file" -- the vulnerable code path
# runs before that check). See CVE-2025-32463 / the sudo project's own
# chroot_bug advisory for the mechanism; not reproduced here on purpose,
# same reasoning as the WordPress CVE pair below -- this file configures
# the target to the correct vulnerable version, exploitation is for the
# red-team/attacker side.
#
# The base image's own Debian release (trixie) already ships sudo
# 1.9.16p2 -- but patched (the security fix landed as a point-release
# bump, `+deb13u2`, without changing the visible upstream version
# string). A naive `apt-get install sudo` today pulls that patched
# build. Rather than manually downgrading (installing an old .deb over a
# current one, which is real forensic evidence of tampering an attacker
# could actually notice -- version older than the OS's own history),
# this repoints apt at a Debian snapshot.debian.org mirror from BEFORE
# the fix existed (2025-06-30) so `apt-get install sudo` resolves the
# vulnerable build as -- genuinely, as far as apt's own metadata is
# concerned -- the current, only-available version for this source.
# Nothing to notice from `apt-cache policy`/`madison`. Reverted back to
# the image's normal live sources afterward, so nothing else in the
# container (and nothing an attacker might later `apt-get install`
# through the RCE) drifts to mid-2025 package state -- only sudo itself
# is deliberately old.
FROM wordpress:7.0.1-php8.3-apache

RUN cp /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list.d/debian.sources.orig && \
    printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/20250630T203427Z\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\nCheck-Valid-Until: no\n' \
        > /etc/apt/sources.list.d/debian.sources && \
    apt-get update -qq && \
    apt-get install -y --no-install-recommends sudo && \
    rm -rf /var/lib/apt/lists/* && \
    mv /etc/apt/sources.list.d/debian.sources.orig /etc/apt/sources.list.d/debian.sources

# Two flags. Both readable only through actual code execution (neither
# sits under the served document root /var/www/html), never over plain
# HTTP:
#   flag1 -- reachable the moment ANY shell access exists (the www-data
#            user Apache/PHP itself runs as), no privilege escalation
#            needed.
#   flag2 -- root-owned, mode 600: reachable only after actually
#            exploiting CVE-2025-32463 (or some other path to root).
RUN mkdir -p /var/www && \
    echo 'FLAG{wp_apache_f00th0ld}' > /var/www/flag1.txt && \
    chown www-data:www-data /var/www/flag1.txt && \
    chmod 644 /var/www/flag1.txt && \
    echo 'FLAG{wp_r00t_35c4l4t10n}' > /root/flag2.txt && \
    chown root:root /root/flag2.txt && \
    chmod 600 /root/flag2.txt
