"""labctl CLI. Run via the top-level `./labctl` wrapper (which prefers the venv
interpreter) or `python3 -m pipeline.labctl <cmd>`.

    Lab state (delegates to lab-mode.sh / reset.sh / npc-range):
      labctl up <mode> [dealer-target]     labctl down [mode]
      labctl switch <mode>                 labctl posture [remote|insider]
      labctl reset [reset.sh flags] [--confirm]
      labctl clean [--db|--hunt] [--confirm]
      labctl flock up <template> [--network N] | down [flock|--all] | status

    Process control (labctl owns the PID registry in .labctl/state.json):
      labctl start hunter|attacker|ingest|dashboard [--provider P --model M -- extra...]
      labctl stop <name>                   labctl restart <name>

    Whole-lab view / policy loop:
      labctl status [--json] [--no-docker]
      labctl watch [--once] [--stop-agents]
"""

import argparse
import json
import sys

from . import config, orchestrate, procman, state, supervisor

PROC_NAMES = ("hunter", "attacker", "ingest", "dashboard", "supervisor")


def _print_result(res, quiet_ok=True):
    if res.get("stdout"):
        sys.stdout.write(res["stdout"])
        if not res["stdout"].endswith("\n"):
            sys.stdout.write("\n")
    if res.get("stderr"):
        sys.stderr.write(res["stderr"])
        if not res["stderr"].endswith("\n"):
            sys.stderr.write("\n")
    return res.get("rc", 0)


def _cmd_status(args):
    data = orchestrate.status(include_docker=not args.no_docker)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    # human-readable
    print(f"mode: {data['mode']}   posture: {data['posture']}   (since {data['switched_at']})")
    print("processes:")
    for name in config.MANAGED:
        p = data["processes"][name]
        tag = "up" if p["up"] else "down"
        extra = f" pid={p['pid']}" if p["pid"] else ""
        if p["adopted"]:
            extra += " (adopted)"
        print(f"  {name:<10} {tag}{extra}")
    sup = data["supervisor"]
    print(f"  {'supervisor':<10} {'up' if sup['up'] else 'down'}"
          f"{' pid=' + str(sup['pid']) if sup['pid'] else ''}")
    h = data["signals"]["hunter"]
    if h:
        print(f"hunt: #{h['hunt_id']} status={h['status']} chunks={h['chunk_count']} "
              f"({h['provider']}/{h['model']})")
    runs = data["signals"]["active_attack_runs"]
    if runs:
        print("active attack runs: " + ", ".join(f"#{r['id']}({r['stage']})" for r in runs))
    flocks = data.get("flocks") or []
    if flocks:
        print("flocks: " + ", ".join(
            f"{f['name']}(clients {f['clients']}, traffic {'on' if f['traffic'] else 'off'})"
            for f in flocks))
    pol = data["policies"]
    print("policies: " + ", ".join(f"{k.replace('policy_', '')}={'on' if v else 'off'}"
                                    for k, v in pol.items()))
    if data.get("lab_status_text"):
        print("\n--- lab-mode.sh status ---")
        print(data["lab_status_text"].rstrip())
    return 0


def _cmd_start(args):
    if args.name not in config.MANAGED:
        sys.stderr.write(f"start: unknown process '{args.name}' "
                         f"(one of: {', '.join(config.MANAGED)})\n")
        return 2
    opts = {"provider": args.provider, "model": args.model, "extra": args.extra or []}
    started, entry = procman.start(args.name, opts)
    if started:
        print(f"started {args.name} (pid {entry['pid']}); log: {entry.get('log')}")
    else:
        print(f"{args.name} already up (pid {entry.get('pid')})")
    return 0


def _cmd_stop(args):
    if args.name not in PROC_NAMES:
        sys.stderr.write(f"stop: unknown process '{args.name}'\n")
        return 2
    stopped = procman.stop(args.name)
    print(f"{'stopped' if stopped else 'not running'}: {args.name}")
    return 0


def _cmd_restart(args):
    if args.name not in config.MANAGED:
        sys.stderr.write(f"restart: unknown process '{args.name}'\n")
        return 2
    opts = {"provider": args.provider, "model": args.model, "extra": args.extra or []}
    _started, entry = procman.restart(args.name, opts)
    print(f"restarted {args.name} (pid {entry.get('pid')})")
    return 0


def _split_confirm(rest):
    confirm = "--confirm" in rest
    return [a for a in rest if a != "--confirm"], confirm


def build_parser():
    p = argparse.ArgumentParser(prog="labctl", description="SOC lab manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    up = sub.add_parser("up", help="bring a mode up (lab-mode.sh up)")
    up.add_argument("mode")
    up.add_argument("target", nargs="?", default=None)

    dn = sub.add_parser("down", help="tear a mode down (lab-mode.sh down)")
    dn.add_argument("mode", nargs="?", default=None)

    sw = sub.add_parser("switch", help="switch to a mode (lab-mode.sh switch)")
    sw.add_argument("mode")

    po = sub.add_parser("posture", help="get/set attacker posture (lab-mode.sh posture)")
    po.add_argument("value", nargs="?", default=None, choices=[None, "remote", "insider"])

    rs = sub.add_parser("reset", help="reset.sh passthrough; add --confirm for a DB wipe")
    rs.add_argument("flags", nargs=argparse.REMAINDER)

    cl = sub.add_parser("clean", help="clean DB state (--hunt default, --db needs --confirm)")
    cl.add_argument("--db", action="store_true")
    cl.add_argument("--hunt", action="store_true")
    cl.add_argument("--confirm", action="store_true")

    fl = sub.add_parser("flock", help="NPC flocks + traffic generator (make -C npc-range)")
    fl.add_argument("action", choices=["up", "down", "status", "reconcile", "traffic-start", "traffic-stop"])
    fl.add_argument("name", nargs="?", default=None,
                    help="template (up), or flock name (down / traffic-start / traffic-stop)")
    fl.add_argument("--network", default=None)

    st = sub.add_parser("status", help="whole-lab status")
    st.add_argument("--json", action="store_true")
    st.add_argument("--no-docker", action="store_true", help="skip the slow docker/flock text view")

    for verb in ("start", "restart"):
        sp = sub.add_parser(verb, help=f"{verb} a managed process")
        sp.add_argument("name", choices=list(config.MANAGED))
        sp.add_argument("--provider", default=None)
        sp.add_argument("--model", default=None)
        sp.add_argument("extra", nargs=argparse.REMAINDER,
                        help="extra args passed through after --")

    sto = sub.add_parser("stop", help="stop a managed process")
    sto.add_argument("name", choices=list(PROC_NAMES))

    wa = sub.add_parser("watch", help="run the supervisor policy loop (foreground)")
    wa.add_argument("--once", action="store_true")
    wa.add_argument("--stop-agents", action="store_true",
                    help="also stop hunter/attacker when the supervisor exits")

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    cmd = args.cmd

    if cmd == "up":
        return _print_result(orchestrate.lab_mode("up", args.mode, args.target))
    if cmd == "down":
        return _print_result(orchestrate.lab_mode("down", args.mode))
    if cmd == "switch":
        return _print_result(orchestrate.lab_mode("switch", args.mode))
    if cmd == "posture":
        return _print_result(orchestrate.lab_mode("posture", args.value))
    if cmd == "reset":
        flags, confirm = _split_confirm(list(args.flags or []))
        return _print_result(orchestrate.reset(flags, confirm=confirm))
    if cmd == "clean":
        what = "db" if args.db else "hunt"
        return _print_result(orchestrate.clean(what, confirm=args.confirm))
    if cmd == "flock":
        template = args.name if args.action == "up" else None
        name = args.name if args.action in ("down", "traffic-start", "traffic-stop") else None
        return _print_result(orchestrate.flock(args.action, template=template,
                                               name=name, network=args.network))
    if cmd == "status":
        return _cmd_status(args)
    if cmd == "start":
        # strip a leading '--' argparse leaves in REMAINDER
        if args.extra and args.extra[0] == "--":
            args.extra = args.extra[1:]
        return _cmd_start(args)
    if cmd == "restart":
        if args.extra and args.extra[0] == "--":
            args.extra = args.extra[1:]
        return _cmd_restart(args)
    if cmd == "stop":
        return _cmd_stop(args)
    if cmd == "watch":
        return supervisor.run(once=args.once, stop_agents_on_exit=args.stop_agents)
    return 2


if __name__ == "__main__":
    sys.exit(main())
