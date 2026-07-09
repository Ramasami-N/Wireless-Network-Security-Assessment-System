import subprocess


# ---------------------------
# WIFI SCAN FUNCTION (TUPLE FORMAT - FIXED)
# ---------------------------
def scan_wifi():
    command = "netsh wlan show networks mode=bssid"
    output = subprocess.check_output(command, shell=True).decode(errors="ignore")

    networks = []
    ssid = ""
    authentication = ""
    bssid = ""
    signal = ""

    for line in output.split("\n"):
        line = line.strip()

        if line.startswith("SSID"):
            ssid = line.split(":", 1)[1].strip()

        elif line.startswith("Authentication"):
            authentication = line.split(":", 1)[1].strip()

        elif line.startswith("BSSID"):
            bssid = line.split(":", 1)[1].strip()

        elif line.startswith("Signal"):
            signal = line.split(":", 1)[1].strip()

            # ✅ RETURN AS TUPLE (matches your UI)
            networks.append((
                ssid,            # net[0]
                authentication,  # net[1]
                bssid,           # net[2]
                signal           # net[3]
            ))

    return networks


# ---------------------------
# FIXED EVIL TWIN DETECTION
# ---------------------------
def detect_fake_wifi(networks):
    """
    Detect possible Evil Twin networks.
    Works with tuple format:
    (SSID, Authentication, BSSID, Signal)
    """

    suspicious_networks = []

    for i in range(len(networks)):
        for j in range(i + 1, len(networks)):

            ssid1, auth1, bssid1, signal1 = networks[i]
            ssid2, auth2, bssid2, signal2 = networks[j]

            # Same SSID but different BSSID
            if ssid1 == ssid2 and bssid1 != bssid2:

                # Convert signal "75%" → 75
                try:
                    signal_val1 = int(signal1.replace("%", "").strip())
                    signal_val2 = int(signal2.replace("%", "").strip())
                except:
                    continue

                # 🚨 Case 1: Different Encryption → weaker one is evil
                if auth1 != auth2:

                    if "Open" in auth1 or "WEP" in auth1:
                        if networks[i] not in suspicious_networks:
                            suspicious_networks.append(networks[i])
                    elif "Open" in auth2 or "WEP" in auth2:
                        if networks[j] not in suspicious_networks:
                            suspicious_networks.append(networks[j])

                # 🚨 Case 2: Same encryption but huge signal difference
                elif abs(signal_val1 - signal_val2) > 40:

                    # Stronger signal marked suspicious
                    if signal_val1 > signal_val2:
                        if networks[i] not in suspicious_networks:
                            suspicious_networks.append(networks[i])
                    else:
                        if networks[j] not in suspicious_networks:
                            suspicious_networks.append(networks[j])

    return suspicious_networks


# ---------------------------
# SECURITY CLASSIFICATION
# ---------------------------
def classify_network(auth, suspicious=False):

    if suspicious:
        return "Suspicious", "Possible Evil Twin"

    if "Open" in auth:
        return "Insecure", "High Risk"

    elif "WEP" in auth:
        return "Insecure", "High Risk"

    elif "WPA3" in auth:
        return "Secure", "Low Risk"

    elif "WPA2" in auth:
        return "Secure", "Low Risk"

    elif "WPA" in auth:
        return "Secure", "Medium Risk"

    else:
        return "Unknown", "Unknown"


# ---------------------------
# TRAFFIC ANALYSIS USING TSHARK
# ---------------------------
def analyze_traffic():

    try:
        command = [
            r"C:\Program Files\Wireshark\tshark.exe",
            "-i", "1",
            "-a", "duration:8",
            "-Y", "tcp.port == 80"
        ]

        output = subprocess.check_output(
            command,
            stderr=subprocess.DEVNULL
        )

        if output:
            return "⚠ Port 80 (HTTP) Traffic Detected!"
        else:
            return "No Unencrypted HTTP Traffic Found."

    except subprocess.CalledProcessError:
        return "No HTTP Traffic Found (Capture Successful)."

    except Exception as e:
        return f"Traffic Analysis Failed: {str(e)}"