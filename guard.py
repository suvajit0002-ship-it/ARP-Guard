import sys
import subprocess
from scapy.all import ARP, sniff, getmacbyip

INTERFACE_NAME = "Wi-Fi"
GATEWAY_IP = input("Input the Getway IP: ")

def get_trusted_mac(ip):
    print(f"[*] Scanning network to find legitimate MAC for {ip}...")
    mac = getmacbyip(ip)
    if not mac:
        print("[!] FATAL: Could not find Gateway. Check your IP/Connection.")
        sys.exit(1)
    return mac.lower()

def kill_connection():
    """Triggers the Windows Killswitch via PowerShell."""
    print("\n[!!!] ARP SPOOFING DETECTED!")
    print(f"[***] EMERGENCY: DISCONNECTING {INTERFACE_NAME} NOW...")
    
    # PowerShell command to disable the adapter
    cmd = f"PowerShell -Command \"Disable-NetAdapter -Name '{INTERFACE_NAME}' -Confirm:$false\""
    
    try:
        subprocess.run(cmd, shell=True, check=True)
        print("[+] Success: Network interface disabled. You are now safe.")
    except Exception as e:
        print(f"[!] Error: Could not disable adapter. Are you running as Admin? {e}")
    
    sys.exit(0)

def monitor_callback(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        source_ip = pkt[ARP].psrc
        source_mac = pkt[ARP].hwsrc.lower()
        
        if source_ip == GATEWAY_IP:
            if source_mac != TRUSTED_MAC:
                print(f"\n[!] ALERT: MAC MISMATCH!")
                print(f"    Target IP: {source_ip}")
                print(f"    Trusted MAC: {TRUSTED_MAC}")
                print(f"    Attacker MAC: {source_mac}")
                kill_connection()

if __name__ == "__main__":
    print("--- WINDOWS ARP-GUARD ACTIVE ---")
    TRUSTED_MAC = get_trusted_mac(GATEWAY_IP)
    print(f"[*] Trusted Gateway MAC is: {TRUSTED_MAC}")
    print(f"[*] Now guarding {INTERFACE_NAME}. Press Ctrl+C to stop.")

    try:
        sniff(iface=INTERFACE_NAME, filter="arp", prn=monitor_callback, store=0)
    except PermissionError:
        print("[!] Error: You MUST run this as Administrator.")
    except KeyboardInterrupt:
        print("\n[*] Guard deactivated by user.")