"""Mininet topology: multi-switch Open vSwitch lab (s1, s2, s3).

    h1 (10.10.0.1) --\
    h2 (10.10.0.2) ---+-- s2 --+
                               +-- s1 (OVS, OpenFlow 1.3) -- controller (127.0.0.1:6653)
    h3 (10.10.0.3) ------ s3 --+   |     \
                                   |      srv (10.10.0.100) runs protected service :9000
                            root namespace (10.10.0.254) = the VM itself, where the
                            auth server (:5000) listens, reachable from every host

Run (needs root; start the controller first):
    sudo -E env "PATH=$PATH" python3 network/topology.py            # opens the Mininet CLI
    sudo -E env "PATH=$PATH" python3 network/topology.py --no-cli   # run until Ctrl-C
Switches, links, hosts, MACs and ports come from config/config.json so that the
controller's rules and the topology always agree.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import REPO_ROOT, lab_switches, load_config  # noqa: E402
from common.events import EventLog  # noqa: E402


class Lab:
    """Builds, starts and stops the Mininet lab (also used by the integration tests)."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.events = EventLog(cfg["paths"]["events_log"], "topology")
        self.net = None
        self.service_proc = None
        self.state_path = os.path.join(cfg["paths"]["run_dir"], "topology_state.json")

    def start(self, wait_seconds=25):
        from mininet.net import Mininet
        from mininet.node import Node, OVSSwitch, RemoteController

        lab, ctl = self.cfg["lab"], self.cfg["controller"]
        switches_cfg = lab_switches(self.cfg)
        default_sw = switches_cfg[0]["name"]

        # Mininet hosts inherit this process's environment: make `python3 -m auth.client` work inside them
        os.environ["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{os.environ.get('PYTHONPATH', '')}".rstrip(os.pathsep)
        os.environ["CNAUTH_CONFIG"] = self.cfg["_config_path"]
        net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=False, autoStaticArp=False, build=False)
        net.addController("c0", controller=RemoteController, ip=ctl["openflow_host"], port=ctl["openflow_port"])

        sw_nodes = {}
        any_userspace = False
        for sw in switches_cfg:
            extra = {"datapath": sw["datapath"]} if sw.get("datapath") else {}
            if sw.get("datapath") == "user":
                any_userspace = True
            sw_nodes[sw["name"]] = net.addSwitch(sw["name"], dpid=sw["dpid"], protocols="OpenFlow13",
                                                 failMode="secure", **extra)

        for link in lab.get("links", []):
            net.addLink(sw_nodes[link["s1"]], sw_nodes[link["s2"]], port1=link["p1"], port2=link["p2"])

        prefix = lab["prefix_len"]
        for name, h in lab["hosts"].items():
            if h["role"] != "management":
                host = net.addHost(name, ip=f"{h['ip']}/{prefix}", mac=h["mac"])
                target_sw = sw_nodes[h.get("switch", default_sw)]
                net.addLink(host, target_sw, port2=h["port"])

        root_cfg = lab["hosts"]["root"]
        root = Node("root", inNamespace=False)
        root_sw = sw_nodes[root_cfg.get("switch", default_sw)]
        root_link = net.addLink(root, root_sw, port2=root_cfg["port"], addr1=root_cfg["mac"])

        net.build()
        net.start()
        root.setIP(f"{root_cfg['ip']}/{prefix}", intf=root_link.intf1)
        self.net = net
        if any_userspace:
            self._disable_offload(net, root_link.intf1.name)
        connected = net.waitConnected(timeout=wait_seconds)
        if connected:
            time.sleep(1.5)  # let the controller finish installing the base rules
        self._start_service()
        self._write_state()
        self.events.emit("topology_started", switches=[s["name"] for s in switches_cfg],
                         hosts=sorted(lab["hosts"]), switch_connected=bool(connected))
        return bool(connected)

    @staticmethod
    def _disable_offload(net, root_intf):
        """Only for the userspace OVS datapath (VMs without the kernel module): veth checksum
        offload corrupts TCP there.  Not needed (and not run) with the default kernel datapath."""
        flags = "tx off rx off tso off gso off gro off".split()
        for host in net.hosts:
            for intf in host.intfList():
                if intf.name != "lo":
                    host.cmd("ethtool", "-K", intf.name, *flags)
        subprocess.run(["ethtool", "-K", root_intf, *flags], capture_output=True)

    def _start_service(self):
        svc = self.cfg["services"]["protected-echo"]
        srv = self.net.get(svc["host"])
        env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), CNAUTH_CONFIG=self.cfg["_config_path"])
        logfile = open(os.path.join(self.cfg["paths"]["log_dir"], "protected_service.log"), "ab")
        self.service_proc = srv.popen([sys.executable, str(REPO_ROOT / "network" / "protected_service.py"),
                                       "--host", self.cfg["lab"]["hosts"][svc["host"]]["ip"], "--port", str(svc["port"])],
                                      stdout=logfile, stderr=subprocess.STDOUT, env=env, cwd=str(REPO_ROOT))
        time.sleep(0.5)

    def _write_state(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        switches = [s["name"] for s in lab_switches(self.cfg)]
        state = {"pid": os.getpid(), "started_at": time.time(), "switch": switches[0], "switches": switches,
                 "hosts": self.cfg["lab"]["hosts"], "service_pid": self.service_proc.pid,
                 "service": self.cfg["services"]["protected-echo"]}
        with open(self.state_path, "w") as fh:
            json.dump(state, fh)
        os.chmod(self.state_path, 0o644)

    def host(self, name):
        return self.net.get(name)

    def stop(self):
        if self.service_proc and self.service_proc.poll() is None:
            self.service_proc.terminate()
            try:
                self.service_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.service_proc.kill()
        if self.net:
            self.net.stop()
            self.net = None
        try:
            os.remove(self.state_path)
        except OSError:
            pass
        self.events.emit("topology_stopped")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config")
    parser.add_argument("--no-cli", action="store_true", help="do not open the Mininet CLI; wait for Ctrl-C")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("error: Mininet needs root. Run: sudo -E env \"PATH=$PATH\" python3 network/topology.py", file=sys.stderr)
        return 1
    from mininet.log import setLogLevel
    setLogLevel("info")
    lab = Lab(load_config(args.config))
    try:
        if not lab.start():
            print("WARNING: switches did not connect to the controller. Is the controller running on "
                  f"{lab.cfg['controller']['openflow_host']}:{lab.cfg['controller']['openflow_port']}?")
        else:
            print("switches connected to the controller; lab is ready")
        if args.no_cli:
            done = []
            signal.signal(signal.SIGTERM, lambda *_: done.append(1))
            while not done:
                time.sleep(1)
        else:
            from mininet.cli import CLI
            print("Try:  h1 python3 network/service_client.py     |     h1 python3 -m auth.client login --user alice")
            CLI(lab.net)
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
