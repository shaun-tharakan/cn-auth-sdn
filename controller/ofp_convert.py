"""Translate RuleSpec objects into OpenFlow 1.3 messages (os-ken parser)."""
from controller.flow_rules import RuleSpec

SPECIAL_PORTS = {"FLOOD": "OFPP_FLOOD", "CONTROLLER": "OFPP_CONTROLLER", "IN_PORT": "OFPP_IN_PORT"}
FULL_COOKIE_MASK = 0xFFFFFFFFFFFFFFFF


def _port(ofp, port):
    return getattr(ofp, SPECIAL_PORTS[port]) if isinstance(port, str) else int(port)


def build_actions(dp, actions):
    ofp, parser = dp.ofproto, dp.ofproto_parser
    out = []
    for kind, port in actions:
        if kind != "output":
            raise ValueError(f"unsupported action {kind!r}")
        out.append(parser.OFPActionOutput(_port(ofp, port), 128 if port == "CONTROLLER" else ofp.OFPCML_MAX))
    return out


def flow_add(dp: object, spec: RuleSpec):
    """FlowMod(ADD).  No instructions at all means *drop* in OpenFlow 1.3."""
    ofp, parser = dp.ofproto, dp.ofproto_parser
    actions = build_actions(dp, spec.actions)
    instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
    return parser.OFPFlowMod(
        datapath=dp, cookie=spec.cookie, cookie_mask=0, table_id=0, command=ofp.OFPFC_ADD,
        idle_timeout=0, hard_timeout=spec.hard_timeout, priority=spec.priority,
        buffer_id=ofp.OFP_NO_BUFFER, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
        flags=ofp.OFPFF_SEND_FLOW_REM if spec.notify_on_removal else 0,
        match=parser.OFPMatch(**spec.match), instructions=instructions)


def flow_delete_cookie(dp, cookie):
    """FlowMod(DELETE) of every flow whose cookie equals ``cookie`` exactly."""
    ofp, parser = dp.ofproto, dp.ofproto_parser
    return parser.OFPFlowMod(
        datapath=dp, cookie=cookie, cookie_mask=FULL_COOKIE_MASK, table_id=ofp.OFPTT_ALL,
        command=ofp.OFPFC_DELETE, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch())


def flow_delete_all(dp):
    ofp, parser = dp.ofproto, dp.ofproto_parser
    return parser.OFPFlowMod(
        datapath=dp, cookie=0, cookie_mask=0, table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
        out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=parser.OFPMatch())
