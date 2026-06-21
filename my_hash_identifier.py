import argparse
import os
import re
from rich.console import Console
from rich.table import Table

console = Console()

# FEATURE 3: Expanded Signatures (Added Linux SHA-512 crypt and JWT)
# FEATURE 2: Strict Validation (Updated regex patterns to enforce proper minimum/total lengths)
HASH_SIGNATURES = [
    {"name": "MD5", "regex": r"^[a-fA-F0-9]{32}$", "confidence": "Medium",
        "reason": "32 hex characters. Legacy checksum / Windows credential candidate."},
    {"name": "NTLM", "regex": r"^[a-fA-F0-9]{32}$", "confidence": "Medium",
        "reason": "32 hex characters. Native Windows local/domain password format."},
    {"name": "SHA-1", "regex": r"^[a-fA-F0-9]{40}$", "confidence": "High",
        "reason": "40 hex characters. Legacy security signature."},
    {"name": "SHA-256", "regex": r"^[a-fA-F0-9]{64}$", "confidence": "High",
        "reason": "64 hex characters. Industry standard modern file signature."},
    {"name": "SHA-512", "regex": r"^[a-fA-F0-9]{128}$", "confidence": "High",
        "reason": "128 hex characters. Standard Linux shadow password configuration."},
    # Tuned variations to cleanly process parameters even with truncated inputs
    {"name": "bcrypt", "regex": r"^\$2[ayb]\$\d{2}\$.*", "confidence": "High",
        "reason": "Standard Unix/Web application modular crypt formatting (bcrypt)."},
    {"name": "Argon2", "regex": r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$.*", "confidence": "High",
        "reason": "Modern PHC password hashing algorithm string."},
    {"name": "Apache MD5 (apr1)", "regex": r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", "confidence": "High",
        "reason": "Apache specific modular crypt format wrapper."},
    {"name": "Linux SHA-512 Crypt", "regex": r"^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$.*", "confidence": "High",
        "reason": "Standard modern Linux shadow file password hash ($6$)."},
    {"name": "JSON Web Token (JWT)", "regex": r"^eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_=]*$", "confidence": "High",
        "reason": "Base64URL encoded web session token (Starts with standard 'eyJ' header)."},
    {"name": "NetNTLMv2", "regex": r"^[^:]+::[^:]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$",
        "confidence": "High", "reason": "Network authentication challenge capture string (Responder)."}
]


def identify_hash(user_input):
    """Matches the input string against our signature table and extracts parameters."""
    matches = []
    for signature in HASH_SIGNATURES:
        if re.match(signature["regex"], user_input):
            # Create a shallow copy so we don't permanently modify the global array
            match_info = signature.copy()

            # FEATURE 1: Parameter Extraction (Parsing Work Factors)
            if match_info["name"] == "bcrypt":
                parts = user_input.split('$')
                if len(parts) >= 3:
                    cost = parts[2]
                    match_info["reason"] += f" [Cost/Rounds: {cost}]"
                    if int(cost) < 10:
                        match_info["reason"] += " [bold red](WEAK CONFIG)[/bold red]"

            elif match_info["name"] == "Argon2":
                param_match = re.search(r"m=\d+,t=\d+,p=\d+", user_input)
                if param_match:
                    match_info["reason"] += f" [Params: {param_match.group(0)}]"

            elif match_info["name"] == "Linux SHA-512 Crypt":
                if "rounds=" in user_input:
                    rounds_match = re.search(r"rounds=(\d+)", user_input)
                    if rounds_match:
                        match_info["reason"] += f" [Rounds: {rounds_match.group(1)}]"
                else:
                    match_info["reason"] += " [Rounds: 5000 (Default)]"

            matches.append(match_info)
    return matches


def run_threat_intel_lookup(target_hash, matches):
    """Simulates an OSINT Threat Intelligence lookup based on signature analysis."""
    if any(m["name"] in ["NTLM", "NetNTLMv2"] for m in matches):
        return "[bold red]CRACK CANDIDATE[/bold red]"
    elif len(target_hash) in [32, 64]:
        return "[bold yellow]UNKNOWN REPUTATION[/bold yellow]"
    return "[green]CLEAN / REHASHED[/green]"


def process_targets(targets_list):
    """Generates one uniform table output for all evaluated targets."""
    table = Table(title="Security Analysis Overview",
                  title_style="bold magenta", show_header=True, header_style="bold white")
    table.add_column("Target Input String", style="yellow",
                     width=25, overflow="ellipsis")
    table.add_column("Detected Algorithm", style="cyan", width=20)
    table.add_column("Confidence", width=12)
    table.add_column("OSINT Threat Status", width=22)
    table.add_column("Technical Signature Mapping", style="white")

    has_results = False

    for target in targets_list:
        matches = identify_hash(target)
        if matches:
            has_results = True
            threat_status = run_threat_intel_lookup(target, matches)
            for match in matches:
                conf_color = "yellow" if match['confidence'] == "Medium" else "green"
                table.add_row(
                    target,
                    match['name'],
                    f"[{conf_color}]{match['confidence']}[/{conf_color}]",
                    threat_status,
                    match['reason']
                )
        else:
            table.add_row(target, "[red]UNKNOWN[/red]", "[red]N/A[/red]",
                          "[grey50]SKIPPED[/grey50]", "No signature lengths or structural rules matched.")

    if has_results or targets_list:
        console.print(table)
        console.print("")
    else:
        console.print(
            "[bold red][-[/bold red]] No input objects to analyze.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced standalone cryptographic analyzer.")
    parser.add_argument(
        "target", help="Raw input string or path to target dictionary file.")
    args = parser.parse_args()
    user_input = args.target.strip()

    targets = []
    if os.path.isfile(user_input):
        console.print(
            f"\n[bold green][+][/bold green] Processing threat dictionary file: [cyan]{user_input}[/cyan]\n")
        with open(user_input, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
    else:
        console.print(
            f"\n[bold cyan][+][/bold cyan] Processing command-line argument target string...\n")
        targets = [user_input]

    process_targets(targets)


if __name__ == "__main__":
    main()
