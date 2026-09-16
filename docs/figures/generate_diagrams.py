#!/usr/bin/env python3
"""
Generate architecture diagrams from Mermaid files.
Requires: pip install mermaid-cli mmdc
Or use online editor: https://mermaid.live
"""

import subprocess
import os
from pathlib import Path

DIAGRAM_DIR = Path(__file__).parent

DIAGRAMS = {
    "architecture_overview": "AEGIS-AES Architecture Overview",
    "fsm_state_diagram": "AES Top FSM State Diagram",
    "datapath_detail": "Datapath Detail",
    "security_monitors": "Security Monitors Detail",
    "uart_protocol": "UART Protocol",
}


def render_mermaid(mmd_file: Path, output_file: Path, format: str = "png"):
    """Render a Mermaid diagram using mmdc CLI tool."""
    cmd = [
        "mmdc",
        "-i", str(mmd_file),
        "-o", str(output_file),
        "-b", "white",
        "-w", "1600",
        "-H", "1200",
        "-f", format,
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"✓ Generated: {output_file}")
        return True
    except FileNotFoundError:
        print("⚠ mmdc not found. Install: npm install -g @mermaid-js/mermaid-cli")
        return False
    except subprocess.CalledProcessError as e:
        print(f"✗ Error rendering {mmd_file}: {e.stderr.decode()}")
        return False


def main():
    print("AEGIS-AES Architecture Diagrams")
    print("=" * 50)

    # Check for mmdc
    try:
        subprocess.run(["mmdc", "--version"], check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("⚠ Mermaid CLI not installed.")
        print("  Install with: npm install -g @mermaid-js/mermaid-cli")
        print()
        print("  Or paste the .mmd files at https://mermaid.live")
        print()

    # Generate diagrams
    for name, title in DIAGRAMS.items():
        mmd_file = DIAGRAM_DIR / f"{name}.mmd"
        if mmd_file.exists():
            print(f"\n{title}")
            print("-" * len(title))

            # Try PNG
            png_file = DIAGRAM_DIR / f"{name}.png"
            render_mermaid(mmd_file, png_file, "png")

            # Try SVG
            svg_file = DIAGRAM_DIR / f"{name}.svg"
            render_mermaid(mmd_file, svg_file, "svg")
        else:
            print(f"✗ {mmd_file} not found")

    print("\nDone!")


if __name__ == "__main__":
    main()
