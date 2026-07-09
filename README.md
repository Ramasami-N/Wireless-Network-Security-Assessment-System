# Wireless Network Security Assessment System

A Windows-based Python desktop application for scanning nearby Wi-Fi networks and assessing basic wireless security risks. The tool displays detected networks in a Tkinter dashboard, classifies encryption strength, flags possible Evil Twin access points, and can run a short HTTP traffic check with Wireshark's `tshark`.

## Features

- Scan nearby Wi-Fi networks using Windows `netsh`
- Display SSID, authentication type, BSSID, signal strength, status, and risk level
- Classify networks as secure, insecure, suspicious, or unknown
- Detect possible Evil Twin networks by comparing duplicate SSIDs, BSSIDs, encryption, and signal strength
- Suggest the best network based on security, signal strength, and suspicious-network penalties
- Optional traffic analysis for unencrypted HTTP traffic using `tshark`
- Tkinter-based graphical interface

## Requirements

- Windows
- Python 3.x
- Wi-Fi adapter enabled
- Optional: Wireshark installed at `C:\Program Files\Wireshark\tshark.exe` for traffic analysis

## How to Run

Clone the repository and run the GUI:

```powershell
python wifi_gui.py
```

The scanner uses:

```powershell
netsh wlan show networks mode=bssid
```

Traffic analysis uses `tshark` and may require administrator permissions depending on your system configuration.

## Project Files

- `wifi_gui.py` - Tkinter desktop interface and dashboard controls
- `wifi_scanner.py` - Wi-Fi scanning, network classification, Evil Twin detection, and traffic analysis logic

## Notes

This project is intended for educational and authorized security assessment use only. Only scan and analyze networks where you have permission to perform security checks.
