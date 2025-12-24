#!/usr/bin/env python3
import os
import sys
import subprocess
import plistlib
import stat
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# ==============================
# Utility helpers
# ==============================

def run_cmd(cmd: List[str], capture_output: bool = True) -> subprocess.CompletedProcess:
    try:
        if capture_output:
            return subprocess.run(cmd, text=True, capture_output=True, check=False)
        else:
            return subprocess.run(cmd, text=True, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"Command not found: {cmd[0]}")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", f"{e}")

def require_root():
    if os.geteuid() != 0:
        print("[-] Please run this script with sudo, for example:")
        print(f"    sudo {sys.executable} {sys.argv[0]}")
        sys.exit(1)

def prompt_yes_no(prompt: str, default: str = "Y") -> bool:
    default = default.upper()
    while True:
        if default == "Y":
            ans = input(f"{prompt} [Y/n]: ").strip()
            if ans == "":
                ans = "Y"
        else:
            ans = input(f"{prompt} [y/N]: ").strip()
            if ans == "":
                ans = "N"

        if ans.lower() in ("y", "yes"):
            return True
        if ans.lower() in ("n", "no"):
            return False
        print("Please answer y or n.")

class UndoRecorder:
    def __init__(self, path: Path):
        self.path = path
        self.path.write_text("#!/bin/zsh\n# Undo commands for macOS hardening script\n"
                             f"# Generated on {datetime.now()}\n", encoding="utf-8")
        self.path.chmod(0o700)

    def add(self, cmd: str):
        with self.path.open("a", encoding="utf-8") as f:
            f.write(cmd + "\n")

def recommend_change(title: str,
                     current: str,
                     recommended: str,
                     apply_cmd: str,
                     undo_cmd: str,
                     undo_recorder: UndoRecorder):
    print()
    print(f"=== {title} ===")
    print(f"Current setting   : {current}")
    print(f"Recommended       : {recommended}")
    if prompt_yes_no("Apply this hardening change now?"):
        print(f"-> Running: {apply_cmd}")
        cp = run_cmd(["/bin/zsh", "-c", apply_cmd])
        if cp.returncode == 0:
            print("[+] Change applied.")
            if undo_cmd:
                print("   To undo manually later, run:")
                print(f"      {undo_cmd}")
                undo_recorder.add(undo_cmd)
        else:
            print("[-] Command failed; output:")
            print(cp.stdout)
            print(cp.stderr)
    else:
        print("[-] Skipping change.")

# ==============================
# Baseline / Hardening checks
# ==============================

def check_system_info():
    print("--- System information ---")
    chip = ""
    cp = run_cmd(["/usr/sbin/system_profiler", "SPHardwareDataType"])
    if cp.stdout:
        for line in cp.stdout.splitlines():
            if "Chip" in line:
                chip = line.split(":", 1)[1].strip()
                break

    cpu_cp = run_cmd(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"])
    cpu_brand = cpu_cp.stdout.strip() or "Unknown"

    ver_cp = run_cmd(["/usr/bin/sw_vers", "-productVersion"])
    os_ver = ver_cp.stdout.strip() or "Unknown"

    print(f"Chip    : {chip or 'Unknown'}")
    print(f"CPU     : {cpu_brand}")
    print(f"macOS   : {os_ver}")
    print()

def check_updates(undo: UndoRecorder):
    print("--- Checking for macOS updates (this may take a minute) ---")
    cp = run_cmd(["/usr/sbin/softwareupdate", "-l"])
    out = cp.stdout + cp.stderr

    if "No new software available." in out:
        print("[OK] macOS appears up to date. (This is key for latest security fixes.)")
    else:
        print("[WARN] Updates are available. Keeping macOS patched is critical for new CVEs.")
        print()
        print(out)
        print()
        print("You can install all recommended updates with:")
        print("  sudo softwareupdate -ia --verbose")
        undo.add("# OS updates are not trivially reversible; use Time Machine or full backups for rollback.")
    print()

def check_auto_updates(undo: UndoRecorder):
    print("--- Automatic update checks ---")
    cp = run_cmd(["/usr/sbin/softwareupdate", "--schedule"])
    sched = cp.stdout.strip().split()[-1] if cp.stdout.strip() else "off"
    if sched.lower() == "on":
        print("[OK] Automatic update checks are enabled.")
    else:
        recommend_change(
            "Enable automatic macOS update checks",
            "Disabled",
            "Enabled (system will regularly check & notify about updates)",
            "/usr/sbin/softwareupdate --schedule on",
            "/usr/sbin/softwareupdate --schedule off",
            undo,
        )

def check_filevault(undo: UndoRecorder):
    print()
    print("--- FileVault full-disk encryption ---")
    cp = run_cmd(["/usr/bin/fdesetup", "status"])
    print(cp.stdout.strip())
    status = cp.stdout.strip().lower()
    if "filevault is off" in status:
        recommend_change(
            "Enable FileVault full-disk encryption",
            "Off",
            "On (protects data at rest if device is lost or stolen)",
            "/usr/bin/fdesetup enable",
            "# To turn FileVault off later, use: sudo fdesetup disable   (WARNING: decrypts disk and may take a long time)",
            undo,
        )

def check_firewall(undo: UndoRecorder):
    print()
    print("--- Application firewall ---")
    cp = run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    print(cp.stdout.strip())
    parts = cp.stdout.strip().split()
    fw_state = parts[-1].lower() if parts else ""
    if fw_state != "enabled":
        recommend_change(
            "Enable the built-in application firewall",
            "Disabled",
            "Enabled (blocks unwanted incoming connections)",
            "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
            "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off",
            undo,
        )

def check_gatekeeper(undo: UndoRecorder):
    print()
    print("--- Gatekeeper (app download restrictions) ---")
    cp = run_cmd(["/usr/sbin/spctl", "--status"])
    gk_status = cp.stdout.strip() or cp.stderr.strip()
    print(f"Gatekeeper status: {gk_status}")
    if "assessments disabled" in gk_status.lower():
        recommend_change(
            "Enable Gatekeeper (block untrusted apps by default)",
            "Disabled",
            "Enabled (only allow App Store & identified developers by default)",
            "/usr/sbin/spctl --master-enable",
            "/usr/sbin/spctl --master-disable",
            undo,
        )

def check_ssh(undo: UndoRecorder):
    print()
    print("--- Remote Login (SSH) ---")
    cp = run_cmd(["/usr/sbin/systemsetup", "-getremotelogin"])
    print(cp.stdout.strip())
    parts = cp.stdout.strip().split()
    rl_state = parts[-1] if parts else "Off"
    if rl_state == "On":
        recommend_change(
            "Disable Remote Login (SSH) if you don't need it",
            "On",
            "Off (reduces remote attack surface)",
            "/usr/sbin/systemsetup -setremotelogin off",
            "/usr/sbin/systemsetup -setremotelogin on",
            undo,
        )

def check_screenlock(undo: UndoRecorder):
    print()
    print("--- Screen lock & password on wake ---")
    # idleTime is per-host
    cp_idle = run_cmd(["/usr/bin/defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"])
    try:
        idle_time = int((cp_idle.stdout or "0").strip())
    except ValueError:
        idle_time = 0

    cp_pw = run_cmd(["/usr/bin/defaults", "read", "com.apple.screensaver", "askForPassword"])
    try:
        ask_pw = int((cp_pw.stdout or "0").strip())
    except ValueError:
        ask_pw = 0

    cp_delay = run_cmd(["/usr/bin/defaults", "read", "com.apple.screensaver", "askForPasswordDelay"])
    try:
        ask_pw_delay = int((cp_delay.stdout or "0").strip())
    except ValueError:
        ask_pw_delay = 0

    print(f"Current idleTime (seconds): {idle_time}")
    print(f"Password required after sleep/screensaver?: {ask_pw} (1=yes, 0=no)")
    print(f"Password delay (seconds): {ask_pw_delay}")

    if idle_time == 0 or idle_time > 900:
        recommend_change(
            "Set screen lock to 5 minutes of inactivity",
            f"{idle_time} seconds",
            "300 seconds (5 minutes)",
            "/usr/bin/defaults -currentHost write com.apple.screensaver idleTime -int 300",
            f"/usr/bin/defaults -currentHost write com.apple.screensaver idleTime -int {idle_time}",
            undo,
        )

    if ask_pw == 0:
        recommend_change(
            "Require password after sleep/screensaver",
            "Disabled",
            "Enabled",
            "/usr/bin/defaults write com.apple.screensaver askForPassword -int 1",
            "/usr/bin/defaults write com.apple.screensaver askForPassword -int 0",
            undo,
        )

    if ask_pw_delay > 5:
        recommend_change(
            "Require password quickly on wake",
            f"{ask_pw_delay} seconds",
            "5 seconds",
            "/usr/bin/defaults write com.apple.screensaver askForPasswordDelay -int 5",
            f"/usr/bin/defaults write com.apple.screensaver askForPasswordDelay -int {ask_pw_delay}",
            undo,
        )

def note_sharing_services():
    print()
    print("--- Sharing services ---")
    print("The following services increase attack surface if enabled:")
    print("  - Screen Sharing")
    print("  - Remote Management")
    print("  - Printer & File Sharing")
    print("Review these in: System Settings -> General -> Sharing")
    print()
    print("Basic command-line check for Screen Sharing:")
    cp = run_cmd(["/bin/launchctl", "print", "system/com.apple.screensharing"])
    if cp.returncode == 0:
        print("  Screen Sharing launchd service present (may be enabled).")
    else:
        print("  Screen Sharing launchd service not active (or not found).")

# ==============================
# IOC / Compromise checks
# ==============================

def scan_launch_items() -> List[Dict[str, Any]]:
    suspicious_items = []
    dirs = [
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path.home() / "Library/LaunchAgents",
    ]
    safe_prefixes = (
        "/System/Library",
        "/usr/",
        "/bin/",
        "/sbin/",
        "/Applications",
        "/Library",
    )

    for d in dirs:
        if not d.is_dir():
            continue

        for plist_path in d.glob("*.plist"):
            reasons = []
            label = plist_path.name
            exe = None

            try:
                with plist_path.open("rb") as f:
                    data = plistlib.load(f)
                label = data.get("Label", label)
                prog = data.get("Program")
                args = data.get("ProgramArguments")
                if args and isinstance(args, list) and args:
                    exe = args[0]
                elif prog:
                    exe = prog
            except Exception as e:
                reasons.append(f"Failed to parse plist: {e}")

            # Check permissions
            try:
                st = plist_path.stat()
                if st.st_mode & stat.S_IWOTH:
                    reasons.append("plist file is world-writable (bad practice)")
            except Exception:
                pass

            # Heuristics on executable path
            if exe:
                exe = str(exe)
                exe_lower = exe.lower()
                if exe_lower.startswith("/tmp") or exe_lower.startswith("/private/tmp"):
                    reasons.append("Executable launched from /tmp (suspicious persistence)")
                if exe_lower.startswith("/users/shared"):
                    reasons.append("Executable launched from /Users/Shared (often abused by malware)")
                if not exe_lower.startswith(safe_prefixes):
                    reasons.append("Executable path outside standard system/app paths")

            if reasons:
                suspicious_items.append({
                    "plist": str(plist_path),
                    "label": label,
                    "exe": exe,
                    "reasons": reasons,
                })

    return suspicious_items

def scan_processes() -> List[Dict[str, Any]]:
    """
    Very simple heuristic: look for processes
    - with names commonly used for hacking/crypto tools, or
    - running directly from /tmp, /Users/Shared, or home dot-directories.
    """
    suspicious = []

    # These can be legit admin tools, so treat as "review carefully"
    suspicious_names = [
        "nmap", "masscan", "hydra", "john", "sqlmap",
        "nc", "ncat", "netcat", "socat",
        "xmrig", "minerd", "cpuminer",
    ]

    cp = run_cmd(["/bin/ps", "aux"])
    for line in cp.stdout.splitlines()[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        user, pid, cpu, mem, vsz, rss, tty, stat_, start, time_, command = parts
        cmd_lower = command.lower()
        reasons = []

        # Name-based heuristic
        for name in suspicious_names:
            if f" {name} " in f" {cmd_lower} ":
                reasons.append(f"Process name contains '{name}' (often used for security/hacking tasks)")

        # Path-based heuristic
        if cmd_lower.startswith(("/tmp", "/private/tmp")):
            reasons.append("Process running from /tmp (often abused by malware)")
        if cmd_lower.startswith("/users/shared"):
            reasons.append("Process running from /Users/Shared (often abused by malware)")
        home = str(Path.home()).lower()
        if cmd_lower.startswith(home + "/.") and "google" not in cmd_lower:
            reasons.append("Process running from hidden directory in home folder")

        if reasons:
            suspicious.append({
                "pid": pid,
                "user": user,
                "command": command,
                "reasons": reasons,
            })

    return suspicious

def scan_admin_group() -> Dict[str, Any]:
    """
    Show admin group membership for manual review.
    """
    cp = run_cmd(["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    users = []
    if cp.stdout:
        for line in cp.stdout.splitlines():
            if line.startswith("GroupMembership:"):
                users = line.split()[1:]
                break
    return {"admin_users": users, "raw": cp.stdout + cp.stderr}

def scan_ssh_authorized_keys() -> List[Dict[str, Any]]:
    """
    Look for authorized_keys files that may allow passwordless SSH access.
    """
    findings = []
    home = Path.home()
    # Current user
    paths = [
        home / ".ssh" / "authorized_keys",
        home / ".ssh" / "authorized_keys2",
    ]

    # System-wide / other users (best-effort)
    users_dir = Path("/Users")
    if users_dir.is_dir():
        for u in users_dir.iterdir():
            ssh_dir = u / ".ssh"
            if ssh_dir.is_dir():
                for fname in ["authorized_keys", "authorized_keys2"]:
                    p = ssh_dir / fname
                    if p.is_file() and p not in paths:
                        paths.append(p)

    for p in paths:
        if not p.exists():
            continue
        try:
            contents = p.read_text(encoding="utf-8", errors="ignore")
            if contents.strip():
                findings.append({
                    "path": str(p),
                    "line_count": len(contents.splitlines()),
                })
        except Exception:
            continue
    return findings

def print_ioc_section():
    print()
    print("========================================")
    print(" IOC / Compromise Checks (Heuristics)")
    print("========================================")
    print("Note: These checks are heuristic and not exhaustive.")
    print("      Anything flagged here should be reviewed, not blindly removed.")
    print()

def run_ioc_checks():
    print_ioc_section()

    # 1) LaunchAgents / LaunchDaemons
    suspicious_launch = scan_launch_items()
    if suspicious_launch:
        print("[!] Suspicious LaunchAgents/LaunchDaemons identified:")
        for item in suspicious_launch:
            print(f"  - Plist : {item['plist']}")
            print(f"    Label : {item['label']}")
            print(f"    Exec  : {item['exe']}")
            for r in item["reasons"]:
                print(f"    Reason: {r}")
        print()
        print("Remediation guidance:")
        print("  • If you do NOT recognize a launch item:")
        print("      1) Backup the plist somewhere safe (e.g., ~/quarantine/).")
        print("      2) Unload it, for example:")
        print("           sudo launchctl bootout system /Library/LaunchDaemons/NAME.plist")
        print("         or for user agents:")
        print("           sudo launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/NAME.plist")
        print("      3) Then remove or keep quarantined the plist.")
        print("  • When in doubt, search the label/executable name before deleting.")
        print()
    else:
        print("[OK] No obviously suspicious LaunchAgents/LaunchDaemons detected by simple heuristics.")
        print()

    # 2) Suspicious processes
    suspicious_procs = scan_processes()
    if suspicious_procs:
        print("[!] Processes that warrant review:")
        for p in suspicious_procs:
            print(f"  - PID    : {p['pid']}")
            print(f"    User   : {p['user']}")
            print(f"    Command: {p['command']}")
            for r in p["reasons"]:
                print(f"    Reason : {r}")
        print()
        print("Remediation guidance:")
        print("  • Verify if these are tools you installed intentionally.")
        print("  • If not, consider:")
        print("       sudo kill -9 <PID>")
        print("    and then investigate where the binary resides (e.g. `which`, `ls -l`, `codesign`).")
        print("  • If malware is suspected, collect forensic data before deleting files.")
        print()
    else:
        print("[OK] No suspicious processes matched the simple heuristics.")
        print()

    # 3) Admin group review
    admin_info = scan_admin_group()
    admin_users = admin_info["admin_users"]
    print("--- Admin group membership ---")
    if admin_users:
        print("Admin users:")
        for u in admin_users:
            print(f"  - {u}")
    else:
        print("Could not determine admin users from dscl output.")
    print()
    print("Remediation guidance:")
    print("  • Verify every account listed above should have admin rights.")
    print("  • To remove an unexpected user from the admin group:")
    print("       sudo dseditgroup -o edit -d <username> -t user admin")
    print()

    # 4) SSH authorized_keys
    ssh_keys = scan_ssh_authorized_keys()
    print("--- SSH authorized_keys files ---")
    if ssh_keys:
        for item in ssh_keys:
            print(f"  - {item['path']} (approx. {item['line_count']} keys)")
        print()
        print("Remediation guidance:")
        print("  • Each key in authorized_keys allows passwordless access as that user.")
        print("  • Review keys; remove any you do not recognize.")
        print("  • Always keep a backup before editing.")
        print()
    else:
        print("No authorized_keys files with content found (or not readable).")
        print()

# ==============================
# Main
# ==============================

def main():
    require_root()

    undo_path = Path.home() / f"macos_hardening_undo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh"
    undo = UndoRecorder(undo_path)

    print("========================================")
    print(" macOS Security Audit, Hardening & IOC")
    print("========================================")
    print()
    print(f"An undo script for hardening changes will be saved as:")
    print(f"  {undo_path}")
    print()

    # Baseline / hardening
    check_system_info()
    check_updates(undo)
    check_auto_updates(undo)
    check_filevault(undo)
    check_firewall(undo)
    check_gatekeeper(undo)
    check_ssh(undo)
    check_screenlock(undo)
    note_sharing_services()

    # IOC checks
    run_ioc_checks()

    print("========================================")
    print(" Audit complete.")
    print(f" Undo commands for any hardening changes you accepted are saved in:")
    print(f"   {undo_path}")
    print()
    print("To review and undo changes later, you can run:")
    print(f"   sudo {undo_path}")
    print("========================================")
    print()

if __name__ == "__main__":
    main()