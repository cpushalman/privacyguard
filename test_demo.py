"""
Privacy Guard Demo Script
Simulates scanning and protection for hackathon demo
"""
import requests
import time
from typing import Optional, Any, Dict
from colorama import init, Fore, Back, Style

# Initialize colorama for colored output
init(autoreset=True)

API_BASE = "http://localhost:5000/api"
REQUEST_TIMEOUT = 3  # seconds


def safe_parse_json(response: requests.Response) -> Optional[Dict[str, Any]]:
    """Safely parse a requests.Response to JSON.

    Returns the parsed object on success, or None if the body is empty or not JSON.
    Prints a compact warning when parsing fails so the demo user sees what's wrong.
    """
    try:
        return response.json()
    except Exception:
        text = getattr(response, "text", "") or ""
        if not text.strip():
            print(f"{Fore.YELLOW}Warning: API returned empty body (HTTP {getattr(response, 'status_code', 'N/A')}){Style.RESET_ALL}")
        else:
            snippet = text[:200].replace("\n", " ")
            print(f"{Fore.RED}Warning: API returned non-JSON response (HTTP {getattr(response, 'status_code', 'N/A')}): {snippet}{Style.RESET_ALL}")
        return None


def print_banner() -> None:
    """Print Privacy Guard banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  {Fore.GREEN}██████╗ ██████╗ ██╗██╗   ██╗ █████╗  ██████╗██╗   ██╗{Fore.CYAN}  ║
║  {Fore.GREEN}██╔══██╗██╔══██╗██║██║   ██║██╔══██╗██╔════╝╚██╗ ██╔╝{Fore.CYAN}  ║
║  {Fore.GREEN}██████╔╝██████╔╝██║██║   ██║███████║██║      ╚████╔╝ {Fore.CYAN}  ║
║  {Fore.GREEN}██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║██║       ╚██╔╝  {Fore.CYAN}  ║
║  {Fore.GREEN}██║     ██║  ██║██║ ╚████╔╝ ██║  ██║╚██████╗   ██║   {Fore.CYAN}  ║
║  {Fore.GREEN}╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝   ╚═╝   {Fore.CYAN}  ║
║                                                           ║
║  {Fore.YELLOW}         GUARD - AI Network Security Scanner       {Fore.CYAN}  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def print_step(step_num: int, title: str) -> None:
    """Print step header"""
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"{Fore.YELLOW}STEP {step_num}: {title}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")


def check_api_health() -> bool:
    """Check if API is running"""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            print(f"{Fore.GREEN}Check: API Server is running{Style.RESET_ALL}")
            return True
        print(f"{Fore.RED}Error: API returned status {response.status_code}{Style.RESET_ALL}")
        return False
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}Error: Cannot connect to API. Is the server running?{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Run: python main.py{Style.RESET_ALL}")
        return False


def start_network_scan() -> bool:
    """Start network scan"""
    print(f"{Fore.CYAN}Starting network scan...{Style.RESET_ALL}")
    try:
        response = requests.post(
            f"{API_BASE}/scan/start",
            json={},  # sends an empty JSON object
            timeout=REQUEST_TIMEOUT
        )
        data = safe_parse_json(response) or {}
        if data.get("message"):
            print(f"{Fore.GREEN}Check: {data['message']}{Style.RESET_ALL}")

        # Simulated wait animation (demo)
            print(f"{Fore.GREEN}Check: Scan started — waiting for results...{Style.RESET_ALL}")

        return True
    except Exception as e:
        print(f"{Fore.RED}Error: Scan failed: {e}{Style.RESET_ALL}")
        return False


def get_scan_status() -> Optional[Dict[str, Any]]:
    """Get current scan status"""
    try:
        response = requests.get(f"{API_BASE}/scan/status", timeout=REQUEST_TIMEOUT)
        data = safe_parse_json(response) or {}
        print(f"{Fore.CYAN}Scan Status:{Style.RESET_ALL}")
        print(f"  Scanning: {data.get('scanning', False)}")
        print(f"  Last Scan: {data.get('last_scan', 'Never')}")
        protection_active = data.get("protection_active", False)
        color = Fore.GREEN if protection_active else Fore.RED
        print(f"  Protection: {color}{protection_active}{Style.RESET_ALL}")
        return data
    except Exception as e:
        print(f"{Fore.RED}Error: Failed to get status: {e}{Style.RESET_ALL}")
        return None


# ==============================================
# ONLY THIS FUNCTION IS UPDATED
# ==============================================
def display_network_risk() -> Optional[Dict[str, Any]]:
    """Wait for scan to finish, then show risk"""
    print(f"{Fore.CYAN}Waiting for scan to complete", end="", flush=True)

    for _ in range(30):  # Max 30 seconds
        try:
            response = requests.get(f"{API_BASE}/scan/status", timeout=REQUEST_TIMEOUT)
            data = safe_parse_json(response) or {}
            
            if not data.get('scanning') and data.get('current_network'):
                network = data['current_network']
                print(f" {Fore.GREEN}Done!{Style.RESET_ALL}")
                break
        except:
            pass
        print(".", end="", flush=True)
        time.sleep(1)
    else:
        print(f"\n{Fore.YELLOW}Warning: Scan took too long{Style.RESET_ALL}")
        return None

    # === SHOW RESULT ===
    risk_level = (network.get("level") or "UNKNOWN").upper()
    risk_score = int(network.get("score", 0) or 0)

    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║  NETWORK RISK ASSESSMENT                     ║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════╝{Style.RESET_ALL}")

    print(f"\n{Fore.WHITE}Network Information:{Style.RESET_ALL}")
    print(f"  SSID: {Fore.CYAN}{network.get('ssid', 'Unknown')}{Style.RESET_ALL}")
    print(f"  BSSID: {network.get('bssid', 'Unknown')}")
    print(f"  Encryption: {network.get('encryption_type', 'Unknown')}")
    print(f"  Signal: {network.get('signal_strength', 0)} dBm")

    bar_len = max(0, min(20, (risk_score // 5)))
    score_bar = "█" * bar_len + "░" * (20 - bar_len)
    color = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED + Style.BRIGHT,
        "MEDIUM": Fore.YELLOW + Style.BRIGHT,
        "LOW": Fore.BLUE,
        "SAFE": Fore.GREEN + Style.BRIGHT,
    }.get(risk_level, Fore.WHITE)

    print(f"\n{Fore.WHITE}Risk Assessment:{Style.RESET_ALL}")
    print(f"  Score: {color}{risk_score}/100 {Style.RESET_ALL}[{score_bar}]")
    print(f"  Level: {color}{risk_level}{Style.RESET_ALL}")

    threats = network.get("threats", []) or []
    if threats:
        print(f"\n{Fore.RED}Warning: THREATS DETECTED: {len(threats)}{Style.RESET_ALL}")
        for i, t in enumerate(threats, 1):
            sev = t.get("severity", "UNKNOWN").upper()
            sev_color = {"CRITICAL": Fore.RED + Style.BRIGHT, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.BLUE}.get(sev, Fore.WHITE)
            print(f"  {i}. [{sev_color}{sev}{Style.RESET_ALL}] {t.get('type')}")
            print(f"     {t.get('description')}")
    else:
        print(f"\n{Fore.GREEN}Check: No threats detected{Style.RESET_ALL}")

    reasons = network.get("reasons", []) or []
    if reasons:
        print(f"\n{Fore.WHITE}Risk Factors:{Style.RESET_ALL}")
        for reason in reasons:
            print(f"  • {reason}")

    recommendations = network.get("recommendations", []) or []
    if recommendations:
        print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

    return network
# ==============================================


def enable_protection() -> bool:
    """Enable VPN protection"""
    print(f"\n{Fore.CYAN}Enabling protection...{Style.RESET_ALL}")
    try:
        response = requests.post(
            f"{API_BASE}/protection/enable",
            json={"method": "ssh_proxy"},
            headers={"Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        data = safe_parse_json(response) or {}
        if data.get("status") == "protected":
            print(f"{Fore.GREEN}Check: Protection enabled via {data.get('method', 'unknown')}{Style.RESET_ALL}")
            if data.get("message"):
                print(f"  {data.get('message')}")
            return True
        print(f"{Fore.RED}Error: Protection failed{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}Error: Failed to enable protection: {e}{Style.RESET_ALL}")
        return False


def get_statistics() -> Optional[Dict[str, Any]]:
    """Display usage statistics"""
    try:
        response = requests.get(f"{API_BASE}/stats", timeout=REQUEST_TIMEOUT)
        stats = safe_parse_json(response) or {}

        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║  USAGE STATISTICS                            ║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════╝{Style.RESET_ALL}")

        print(f"\n  Total Networks Scanned: {Fore.CYAN}{stats.get('total_networks_scanned', 0)}{Style.RESET_ALL}")
        print(f"  High-Risk Networks: {Fore.RED}{stats.get('high_risk_networks', 0)}{Style.RESET_ALL}")
        print(f"  Total Threats Detected: {Fore.YELLOW}{stats.get('total_threats_detected', 0)}{Style.RESET_ALL}")
        print(f"  Protection Sessions: {Fore.GREEN}{stats.get('protection_sessions', 0)}{Style.RESET_ALL}")
        avg = stats.get("average_risk_score", 0) or 0
        print(f"  Average Risk Score: {avg:.1f}/100")

        return stats
    except Exception as e:
        print(f"{Fore.RED}Error: Failed to get statistics: {e}{Style.RESET_ALL}")
        return None


def get_recent_threats(limit: int = 5) -> Optional[list]:
    """Display recent threats"""
    try:
        response = requests.get(f"{API_BASE}/threats", params={"limit": limit}, timeout=REQUEST_TIMEOUT)
        data = safe_parse_json(response) or {}
        threats = data.get("threats", []) or []

        if threats:
            print(f"\n{Fore.RED}Recent Threats:{Style.RESET_ALL}")
            for threat in threats:
                print(f"  • [{threat.get('severity', 'N/A')}] {threat.get('type', 'unknown')} on {threat.get('network_ssid', 'N/A')}")
                print(f"    {threat.get('description', '')}")
                print(f"    Detected: {threat.get('detected_at', 'unknown')}")
        else:
            print(f"\n{Fore.GREEN}No recent threats{Style.RESET_ALL}")

        return threats
    except Exception as e:
        print(f"{Fore.RED}Error: Failed to get threats: {e}{Style.RESET_ALL}")
        return None


def run_demo() -> None:
    """Run complete demo sequence"""
    print_banner()

    # Step 1: Check API
    print_step(1, "API Health Check")
    if not check_api_health():
        return
    time.sleep(1)

    # Step 2: Start scan
    print_step(2, "Network Scanning")
    if not start_network_scan():
        return
    time.sleep(1)

    # Step 3: Display risk
    print_step(3, "Risk Assessment")
    network = display_network_risk()
    time.sleep(2)

    # Step 4: Enable protection if risky
    if network and int(network.get("score", 0) or 0) >= 30:
        print_step(4, "Auto-Protection")
        print(f"{Fore.YELLOW}Warning: Network risk is {network.get('level', 'UNKNOWN')}. Enabling protection...{Style.RESET_ALL}")
        time.sleep(1)
        enable_protection()
        time.sleep(1)

    # Step 5: Statistics
    print_step(5, "Analytics Dashboard")
    get_statistics()
    time.sleep(1)

    # Step 6: Recent threats
    print_step(6, "Threat History")
    get_recent_threats()

    # Final message
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.GREEN}Demo completed successfully!")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}Next steps:{Style.RESET_ALL}")
    print(f"  1. Integrate with frontend UI")
    print(f"  2. Test on different networks")
    print(f"  3. Configure real VPN credentials")
    print(f"  4. Deploy to production")


if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Demo interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Demo error: {e}{Style.RESET_ALL}")