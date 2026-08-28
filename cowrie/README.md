# cowrie -- SSH honeypot

The `easy` mode's SSH target. Presents itself as `prod-web-01` running
`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`, emits JSON to
`logs/cowrie/cowrie.json`, and is one of the four sources `pipeline/ingest.py`
tails. Telnet is off; SSH listens on 2222 in-container.

## Why UserDB and not AuthRandom

`cowrie.cfg` sets `auth_class = UserDB`, so `userdb.txt` is the whole truth
about what authenticates. Cowrie's default `AuthRandom` accepts *eventually,
no matter what you type*, which makes a brute-force result meaningless: the
agent "succeeds" without having found anything. With UserDB, a credential
either works or it doesn't, so a hydra run measures something real.

`userdb.txt` holds two deliberately different groups:

- **Group 1** mirrors `nginx/decoys-easy/credentials.txt` exactly. This is the
  intended `easy`-mode discovery path — find the leaked file over HTTP, reuse
  the credentials over SSH. It rewards recon over brute force.
- **Group 2** is weak/default credentials (`guest:guest`, `backup:123456`,
  `oracle:oracle`) that a dictionary attack should find unaided, so brute
  force still has a real, separate success path.

`sysadmin` uses the regex password `/^$/` rather than an empty field. Cowrie's
`auth.py` does `passwd[0] == ord("!")` with no length check, so a truly empty
password crashes `adduser()` — and because `UserDB.load()` re-runs on every
login attempt, that one bad line breaks authentication for **every** account,
not just that one. `/^$/` matches only the empty string and sidesteps the bug.

## Filesystem

`custom-fs.pickle` is the faked directory tree the emulated shell walks;
`honeyfs/` supplies real file contents for paths within it, including
`honeyfs/root/flag.txt`.

## Traps

- **Cowrie runs as uid 1000 and fails *silently* on a root-owned bind mount.**
  No `cowrie.json` appears while the container looks perfectly healthy. Fix:
  `chmod -R 0777 logs/cowrie && docker compose restart cowrie`.
- **Never map this to host port 22.** You would be handing your own sshd's
  port to a honeypot. `LAB_COWRIE_SSH_PORT` defaults to 2222 for that reason.
