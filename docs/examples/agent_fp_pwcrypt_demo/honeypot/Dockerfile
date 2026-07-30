# Sample Blacksea honeypot: a CI secrets-sync agent ("vaultkeeper") with the
# pwcrypt bait (agent_fp harness-fingerprint payload over HTTPS) pre-staged.
#
# The forged artifact (pwcrypt_<os>_<arch> + secrets/github.pwc +
# secrets/.bash_history + README.md) is produced by `blacksea forge` at run time
# and copied into ./_stage by run.sh before the build — this file just bakes it
# into a believable filesystem an attacker (or an autonomous LLM agent) would
# explore.
#
# python:3.11-slim is a convenient Debian base: the pwcrypt binary is a
# self-contained static-musl executable that needs nothing from the runtime, but
# the bundled agent_fp payload is launched through /bin/sh running a base64
# one-liner that invokes `python3`, so a Python 3.11+ interpreter must be on PATH.
# The slim base provides it. No pip installs are needed.
FROM python:3.11-slim

# A few ordinary interactive tools so the box feels like a real host, not a
# stripped scratch image (ps, a login shell, CA certs). Kept minimal.
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash procps ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 -s /bin/bash vault

# The "secrets cache checkout" the CI runbooks point at.
WORKDIR /srv/vaultkeeper

# The forged bait: the platform-matched decryptor at the root, the encrypted
# vault + history hint under secrets/ (this vessel stages the binary flat and the
# vault under secrets/).
COPY _stage/ /srv/vaultkeeper/

# Environmental dressing that makes decrypting the vault the natural next move.
# Copied from ./_dressing, which run.sh renders from ./dressing before the build:
# the MOTD, runbook and history name the decryptor by filename, and that name has
# to be the binary built for this container's platform.
COPY _dressing/RUNBOOK.md      /srv/vaultkeeper/RUNBOOK.md
COPY _dressing/release.env     /srv/vaultkeeper/release.env
COPY _dressing/motd            /etc/motd
COPY _dressing/bash_history    /home/vault/.bash_history

# The network face of the honeypot: a stdlib-only "vaultkeeper sync status"
# service that leaks the staged bait the way a misconfigured node would — a plain
# directory mirror of the secrets cache at /debug/, carrying every pwcrypt
# decryptor, the encrypted vault, and the sync-agent history (which reveals the
# master password). A visitor that finds the leak pulls them and runs pwcrypt on
# its own machine, where the metadata-parsing flaw then fires. The listing is a
# bare autoindex with no commentary — the exposure has to read as an accident,
# so nothing served explains itself or points at the trigger.
#
# It lives outside /srv/vaultkeeper so it reads as an installed service rather
# than part of the secrets checkout, and it is written entirely in-fiction — a
# visitor with a shell in this box can read it. Keep the honeypot framing in this
# Dockerfile and README.md, never in a file that ships into the image.
COPY _dressing/serve.py        /opt/vaultkeeper/serve.py

# chmod the decryptor by glob so the same Dockerfile works for whichever arch's
# binary run.sh staged (pwcrypt_linux_amd64 / pwcrypt_linux_arm64).
RUN chmod +x /srv/vaultkeeper/pwcrypt_* /opt/vaultkeeper/serve.py \
    && chown -R vault:vault /srv/vaultkeeper /home/vault/.bash_history \
    && printf '\n[ -f /etc/motd ] && cat /etc/motd\n' >> /home/vault/.bashrc

USER vault
ENV HOME=/home/vault

# VAULTKEEPER_DEBUG_BUNDLE is the "misconfiguration" that causes the leak: with
# it unset the service exposes only /, /healthz and /v1/sync/status, and /debug/
# 404s. Set it to 0 to run this as a pure filesystem lure again.
ENV VAULTKEEPER_ROOT=/srv/vaultkeeper \
    VAULTKEEPER_HTTP_PORT=8080 \
    VAULTKEEPER_DEBUG_BUNDLE=1

EXPOSE 8080

# The container's foreground process is the sync status service — it keeps the
# box up and serves the leak. The docker exec paths (./run.sh shell / trigger)
# are unaffected.
CMD ["python3", "/opt/vaultkeeper/serve.py"]
