# juiceshop -- OWASP Juice Shop configuration

Juice Shop itself is an upstream image; only its configuration lives here, and
only for `hard` mode. `easy` mode runs the image's own defaults.

`config/hard.yml` removes every source of free feedback: solved-challenge
notifications, hint buttons, mitigation write-ups, the coding-challenge mode,
and the interactive hacking-instructor walkthrough are all disabled.

The point is measurement integrity. A scoreboard that confirms a guess worked
turns "did the agent find the vulnerability" into "did the agent read the
answer we handed it". In `hard` mode the app tells the attacker nothing it
would not tell a stranger, so a success means the agent actually found
something. The container is also egress-locked to its own subnet by
`juiceshop-netlock` (see `compose.yaml`).
