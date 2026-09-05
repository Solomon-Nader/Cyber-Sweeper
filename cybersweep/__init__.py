"""CyberSweep - a Python network inspector.

CyberSweep discovers live hosts on a network, scans their ports, identifies the
services running on those ports, looks up known vulnerabilities (CVEs) and
produces filterable reports. It exposes the same engine through a command line
interface and a Tkinter graphical interface.

Only scan networks and hosts that you own or have explicit written permission
to test.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
