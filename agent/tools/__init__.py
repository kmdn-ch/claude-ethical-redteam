from .nuclei import run as run_nuclei, TOOL_SPEC as nuclei_spec
from .sqlmap import run as run_sqlmap, TOOL_SPEC as sqlmap_spec
from .ffuf import run as run_ffuf, TOOL_SPEC as ffuf_spec
from .recon import run as run_recon, TOOL_SPEC as recon_spec
from .set_phish import run as generate_phish_template, TOOL_SPEC as phish_spec
from .cleanup import run as cleanup_temp, TOOL_SPEC as cleanup_spec
from .bettercap import run as run_bettercap, TOOL_SPEC as bettercap_spec
from .zphisher import run as generate_zphisher_template, TOOL_SPEC as zphisher_spec
from .cyberstrike import run as run_cyberstrike, TOOL_SPEC as cyberstrike_spec
from .read_log import run as read_log, TOOL_SPEC as read_log_spec
from .payloads import run as run_payloads, TOOL_SPEC as payloads_spec

ALL_TOOLS = [
    nuclei_spec, sqlmap_spec, ffuf_spec, recon_spec, phish_spec, cleanup_spec,
    bettercap_spec, zphisher_spec, cyberstrike_spec, read_log_spec, payloads_spec
]
