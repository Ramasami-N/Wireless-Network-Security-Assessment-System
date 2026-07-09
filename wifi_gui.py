import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from wifi_scanner import scan_wifi, classify_network, detect_fake_wifi, analyze_traffic


class ProfessionalWifiSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wireless Security Monitoring System")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1a1a2e")
        
        # Color scheme
        self.colors = {
            "bg_primary": "#1a1a2e",
            "bg_secondary": "#16213e",
            "bg_tertiary": "#0f3460",
            "accent_cyan": "#00d9ff",
            "accent_green": "#00ff88",
            "accent_red": "#ff4757",
            "accent_orange": "#ffa502",
            "accent_purple": "#a55eea",
            "text_primary": "#ffffff",
            "text_secondary": "#a0a0a0",
            "border": "#2a2a4e"
        }
        
        self.setup_styles()
        self.create_ui()
        self.current_networks = []
        self.current_suspicious = []
        
    def setup_styles(self):
        """Configure custom ttk styles for professional appearance"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure Treeview style
        style.configure("Treeview",
                       background="#16213e",
                       foreground="#ffffff",
                       fieldbackground="#16213e",
                       font=("Segoe UI", 10),
                       rowheight=35)
        
        style.configure("Treeview.Heading",
                       background="#0f3460",
                       foreground="#00d9ff",
                       font=("Segoe UI", 11, "bold"),
                       relief="flat")
        
        style.map("Treeview.Heading",
                 background=[('active', '#0f3460')])
        
        style.configure("Treeview",
                       borderwidth=0,
                       highlightthickness=0)
    
    def create_ui(self):
        """Create the main UI components"""
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors["bg_primary"])
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header section
        self.create_header(main_container)
        
        # Dashboard content
        dashboard_frame = tk.Frame(main_container, bg=self.colors["bg_primary"])
        dashboard_frame.pack(fill="both", expand=True, pady=20)
        
        # Left panel - Statistics and Controls
        left_panel = tk.Frame(dashboard_frame, bg=self.colors["bg_primary"])
        left_panel.pack(side="left", fill="y", padx=(0, 20))
        
        self.create_stats_panel(left_panel)
        self.create_control_panel(left_panel)
        
        # Right panel - Network List
        right_panel = tk.Frame(dashboard_frame, bg=self.colors["bg_primary"])
        right_panel.pack(side="right", fill="both", expand=True)
        
        self.create_network_table(right_panel)
        self.create_status_bar(main_container)
    
    def create_header(self, parent):
        """Create the header with title and logo"""
        header_frame = tk.Frame(parent, bg=self.colors["bg_primary"])
        header_frame.pack(fill="x", pady=(0, 20))
        
        # Logo section
        logo_frame = tk.Frame(header_frame, bg=self.colors["bg_primary"])
        logo_frame.pack(side="left")
        
        # Shield icon
        shield_label = tk.Label(logo_frame, text="🛡️",
                               font=("Arial", 32),
                               bg=self.colors["bg_primary"],
                               fg=self.colors["accent_cyan"])
        shield_label.pack(side="left", padx=(0, 10))
        
        # Title section
        title_frame = tk.Frame(header_frame, bg=self.colors["bg_primary"])
        title_frame.pack(side="left")
        
        title_label = tk.Label(title_frame,
                              text="Wireless Security Monitoring System",
                              font=("Segoe UI", 24, "bold"),
                              bg=self.colors["bg_primary"],
                              fg=self.colors["text_primary"])
        title_label.pack(anchor="w")
        
        subtitle_label = tk.Label(title_frame,
                                 text="Advanced Network Security Analysis & Threat Detection",
                                 font=("Segoe UI", 12),
                                 bg=self.colors["bg_primary"],
                                 fg=self.colors["text_secondary"])
        subtitle_label.pack(anchor="w")
        
        # System status indicator
        status_frame = tk.Frame(header_frame, bg=self.colors["bg_primary"])
        status_frame.pack(side="right")
        
        self.status_indicator = tk.Canvas(status_frame, width=15, height=15,
                                         bg=self.colors["bg_primary"],
                                         highlightthickness=0)
        self.status_indicator.pack(side="right", padx=(0, 10))
        self.draw_status_indicator("active")
        
        self.status_label = tk.Label(status_frame,
                                    text="System Active",
                                    font=("Segoe UI", 11, "bold"),
                                    bg=self.colors["bg_primary"],
                                    fg=self.colors["accent_green"])
        self.status_label.pack(side="right", padx=(0, 15))
        
        # Time display
        self.time_label = tk.Label(status_frame,
                                  text="00:00:00",
                                  font=("Consolas", 12),
                                  bg=self.colors["bg_primary"],
                                  fg=self.colors["accent_cyan"])
        self.time_label.pack(side="right", padx=(0, 20))
        
        self.update_time()
    
    def draw_status_indicator(self, status):
        """Draw animated status indicator"""
        self.status_indicator.delete("all")
        
        if status == "active":
            color = self.colors["accent_green"]
        elif status == "scanning":
            color = self.colors["accent_orange"]
        else:
            color = self.colors["accent_red"]
            
        for i in range(3, 0, -1):
            opacity = i * 0.3
            radius = 7 + (4-i)
            self.status_indicator.create_oval(7-radius, 7-radius,
                                            7+radius, 7+radius,
                                            fill=color, outline="")
        
        self.status_indicator.create_oval(3, 3, 11, 11,
                                        fill=color, outline=color)
    
    def update_time(self):
        """Update the time display"""
        current_time = datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def create_stats_panel(self, parent):
        """Create statistics panel with network information"""
        stats_frame = tk.Frame(parent, bg=self.colors["bg_primary"])
        stats_frame.pack(fill="x", pady=(0, 20))
        
        # Stats container with border
        stats_container = tk.Frame(stats_frame,
                                  bg=self.colors["bg_secondary"],
                                  bd=2,
                                  relief="solid",
                                  highlightbackground=self.colors["border"],
                                  highlightthickness=1)
        stats_container.pack(fill="x")
        
        # Title
        stats_title = tk.Label(stats_container,
                              text="📊 Network Statistics",
                              font=("Segoe UI", 14, "bold"),
                              bg=self.colors["bg_secondary"],
                              fg=self.colors["accent_cyan"],
                              padx=15, pady=10)
        stats_title.pack(anchor="w")
        
        # Stats grid
        stats_grid = tk.Frame(stats_container, bg=self.colors["bg_secondary"])
        stats_grid.pack(fill="x", padx=15, pady=(0, 15))
        
        # Total networks
        self.total_networks_frame = self.create_stat_item(
            stats_grid, "Total Networks", "0", self.colors["accent_cyan"], 0, 0
        )
        
        # Secure networks
        self.secure_networks_frame = self.create_stat_item(
            stats_grid, "Secure Networks", "0", self.colors["accent_green"], 0, 1
        )
        
        # Insecure networks
        self.insecure_networks_frame = self.create_stat_item(
            stats_grid, "Insecure Networks", "0", self.colors["accent_red"], 1, 0
        )
        
        # Suspicious networks
        self.suspicious_networks_frame = self.create_stat_item(
            stats_grid, "Suspicious Networks", "0", self.colors["accent_purple"], 1, 1
        )
    
    def create_stat_item(self, parent, label, value, color, row, col):
        """Create a statistics item"""
        frame = tk.Frame(parent, bg=self.colors["bg_secondary"],
                        padx=10, pady=10)
        frame.grid(row=row, column=col, sticky="ew", padx=5, pady=5)
        
        parent.grid_columnconfigure(col, weight=1)
        
        value_label = tk.Label(frame, text=value,
                              font=("Segoe UI", 28, "bold"),
                              bg=self.colors["bg_secondary"],
                              fg=color)
        value_label.pack()
        
        label_widget = tk.Label(frame, text=label,
                               font=("Segoe UI", 10),
                               bg=self.colors["bg_secondary"],
                               fg=self.colors["text_secondary"])
        label_widget.pack()
        
        # Decorative line
        line = tk.Frame(frame, height=3, bg=color, width=60)
        line.pack(pady=(5, 0))
        
        return frame
    
    def update_stats(self, networks, suspicious):
        """Update statistics display"""
        total = len(networks)
        secure = 0
        insecure = 0
        susp = len(suspicious)
        
        for net in networks:
            is_suspicious = net in suspicious
            status, _ = classify_network(net[1], is_suspicious)
            
            if status == "Secure":
                secure += 1
            elif status == "Insecure" or status == "Suspicious":
                insecure += 1
        
        # Update labels
        self.total_networks_frame.winfo_children()[0].config(text=str(total))
        self.secure_networks_frame.winfo_children()[0].config(text=str(secure))
        self.insecure_networks_frame.winfo_children()[0].config(text=str(insecure))
        self.suspicious_networks_frame.winfo_children()[0].config(text=str(susp))
    
    def create_control_panel(self, parent):
        """Create control panel with buttons"""
        control_frame = tk.Frame(parent, bg=self.colors["bg_primary"])
        control_frame.pack(fill="x")
        
        # Control container with border
        control_container = tk.Frame(control_frame,
                                    bg=self.colors["bg_secondary"],
                                    bd=2,
                                    relief="solid",
                                    highlightbackground=self.colors["border"],
                                    highlightthickness=1)
        control_container.pack(fill="x")
        
        # Title
        control_title = tk.Label(control_container,
                                text="🎛️ Control Panel",
                                font=("Segoe UI", 14, "bold"),
                                bg=self.colors["bg_secondary"],
                                fg=self.colors["accent_cyan"],
                                padx=15, pady=10)
        control_title.pack(anchor="w")
        
        # Buttons frame
        buttons_frame = tk.Frame(control_container, bg=self.colors["bg_secondary"])
        buttons_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # Scan button with icon
        scan_btn = tk.Button(buttons_frame,
                            text="🔍 Scan Networks",
                            font=("Segoe UI", 12, "bold"),
                            bg=self.colors["accent_cyan"],
                            fg=self.colors["bg_primary"],
                            activebackground="#00b8d9",
                            activeforeground=self.colors["bg_primary"],
                            relief="flat",
                            padx=20, pady=12,
                            command=self.refresh_networks)
        scan_btn.pack(fill="x", pady=(0, 10))
        
        # Traffic analysis button
        traffic_btn = tk.Button(buttons_frame,
                               text="📡 Analyze Traffic",
                               font=("Segoe UI", 12, "bold"),
                               bg=self.colors["accent_orange"],
                               fg=self.colors["bg_primary"],
                               activebackground="#e69500",
                               activeforeground=self.colors["bg_primary"],
                               relief="flat",
                               padx=20, pady=12,
                               command=self.run_traffic_analysis)
        traffic_btn.pack(fill="x", pady=(0, 10))
        
        # Suggest Best Network button
        suggest_btn = tk.Button(buttons_frame,
                        text="🏆 Suggest Best Network",
                        font=("Segoe UI", 12, "bold"),
                        bg=self.colors["accent_green"],
                        fg=self.colors["bg_primary"],
                        activebackground="#00cc6a",
                        activeforeground=self.colors["bg_primary"],
                        relief="flat",
                        padx=20, pady=12,
                        command=self.suggest_best_network)
        suggest_btn.pack(fill="x", pady=(0, 10))
        # Legend section
        legend_frame = tk.Frame(control_container,
                               bg=self.colors["bg_secondary"],
                               padx=15, pady=15)
        legend_frame.pack(fill="x")
        
        legend_title = tk.Label(legend_frame,
                               text="📋 Status Legend",
                               font=("Segoe UI", 12, "bold"),
                               bg=self.colors["bg_secondary"],
                               fg=self.colors["text_primary"])
        legend_title.pack(anchor="w", pady=(0, 10))
        
        # Legend items
        self.create_legend_item(legend_frame, "🟢 Secure", self.colors["accent_green"])
        self.create_legend_item(legend_frame, "🔴 Insecure", self.colors["accent_red"])
        self.create_legend_item(legend_frame, "🟣 Suspicious", self.colors["accent_purple"])
        self.create_legend_item(legend_frame, "🟠 Unknown", self.colors["accent_orange"])
    
    def create_legend_item(self, parent, text, color):
        """Create a legend item"""
        frame = tk.Frame(parent, bg=self.colors["bg_secondary"])
        frame.pack(fill="x", pady=3)
        
        indicator = tk.Label(frame, text="●",
                            font=("Arial", 12),
                            bg=self.colors["bg_secondary"],
                            fg=color)
        indicator.pack(side="left", padx=(0, 10))
        
        label = tk.Label(frame, text=text,
                        font=("Segoe UI", 10),
                        bg=self.colors["bg_secondary"],
                        fg=self.colors["text_secondary"])
        label.pack(side="left")
    
    def create_network_table(self, parent):
        """Create the network table with professional styling"""
        table_frame = tk.Frame(parent, bg=self.colors["bg_primary"])
        table_frame.pack(fill="both", expand=True)
        
        # Table header with border
        table_header = tk.Frame(table_frame,
                               bg=self.colors["bg_secondary"],
                               bd=2,
                               relief="solid",
                               highlightbackground=self.colors["border"],
                               highlightthickness=1)
        table_header.pack(fill="x")
        
        table_title = tk.Label(table_header,
                              text="📶 Detected Networks",
                              font=("Segoe UI", 14, "bold"),
                              bg=self.colors["bg_secondary"],
                              fg=self.colors["accent_cyan"],
                              padx=15, pady=10)
        table_title.pack(anchor="w")
        
        # Table container
        table_container = tk.Frame(table_frame,
                                  bg=self.colors["bg_secondary"],
                                  bd=2,
                                  relief="solid",
                                  highlightbackground=self.colors["border"],
                                  highlightthickness=1)
        table_container.pack(fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(table_container, orient="vertical")
        scrollbar.pack(side="right", fill="y")
        
        # Treeview
        columns = ("SSID", "Authentication", "BSSID", "Signal", "Status", "Risk Level")
        
        self.tree = ttk.Treeview(table_container,
                                columns=columns,
                                show="headings",
                                yscrollcommand=scrollbar.set,
                                style="Treeview")
        
        scrollbar.config(command=self.tree.yview)
        
        # Configure columns
        col_widths = {"SSID": 180, "Authentication": 150, "BSSID": 160,
                     "Signal": 100, "Status": 120, "Risk Level": 100}
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths.get(col, 100),
                           minwidth=80, anchor="center")
        
        self.tree.pack(side="left", fill="both", expand=True)
        
        # Configure tags for different statuses
        self.tree.tag_configure("secure", foreground=self.colors["accent_green"])
        self.tree.tag_configure("insecure", foreground=self.colors["accent_red"])
        self.tree.tag_configure("suspicious", foreground=self.colors["accent_purple"])
        self.tree.tag_configure("unknown", foreground=self.colors["accent_orange"])
        self.tree.tag_configure("evil",background="#3a0d0d",foreground="#ff1e1e")
    def create_status_bar(self, parent):
        """Create status bar at bottom"""
        status_bar = tk.Frame(parent, bg=self.colors["bg_secondary"], height=30)
        status_bar.pack(fill="x", side="bottom")
        
        # Status message
        self.status_msg = tk.Label(status_bar,
                                   text="Ready to scan networks...",
                                   font=("Segoe UI", 10),
                                   bg=self.colors["bg_secondary"],
                                   fg=self.colors["text_secondary"],
                                   padx=15, anchor="w")
        self.status_msg.pack(side="left", fill="x", expand=True)
        
        # Version info
        version_label = tk.Label(status_bar,
                                text="v1.0.0 | Security Monitor",
                                font=("Segoe UI", 9),
                                bg=self.colors["bg_secondary"],
                                fg=self.colors["text_secondary"],
                                padx=15)
        version_label.pack(side="right")
    
    def refresh_networks(self):
        """Scan and display networks"""
        # Update UI to scanning state
        self.draw_status_indicator("scanning")
        self.status_label.config(text="Scanning...", fg=self.colors["accent_orange"])
        self.status_msg.config(text="Scanning for wireless networks...")
        
        self.root.update()
        
        try:
            # Clear existing entries
            for row in self.tree.get_children():
                self.tree.delete(row)
            
            # Scan networks
            networks = scan_wifi()
            suspicious = detect_fake_wifi(networks)
            self.current_networks = networks
            self.current_suspicious = suspicious
            # Add networks to table
            for net in networks:
                is_suspicious = net in suspicious
                status, risk = classify_network(net[1], is_suspicious)

                if is_suspicious:
                    status = "🚨 Evil Twin"
                    risk = "Critical"
                
                # Determine tag based on status
                if status == "Secure":
                    tag = "secure"
                elif status == "Insecure":
                    tag = "insecure"
                elif status == "🚨 Evil Twin":
                    tag = "evil"
                else:
                    tag = "unknown"
                
                # Insert into treeview
                self.tree.insert("", tk.END, values=(
                    net[0],  # SSID
                    net[1],  # Authentication
                    net[2],  # BSSID
                    net[3],  # Signal
                    status,  # Status
                    risk     # Risk Level
                ), tags=(tag,))
            
            # Update statistics
            self.update_stats(networks, suspicious)
            
            # Update UI to active state
            self.draw_status_indicator("active")
            self.status_label.config(text="System Active", fg=self.colors["accent_green"])
            
            if networks:
                self.status_msg.config(text=f"Scan complete. Found {len(networks)} networks, {len(suspicious)} suspicious.")
            else:
                self.status_msg.config(text="Scan complete. No networks found.")
                
        except Exception as e:
            # Handle errors
            self.draw_status_indicator("error")
            self.status_label.config(text="Error", fg=self.colors["accent_red"])
            self.status_msg.config(text=f"Error scanning networks: {str(e)}")
            messagebox.showerror("Scan Error", f"Failed to scan networks:\n{str(e)}")
    
    def run_traffic_analysis(self):
        """Run traffic analysis and display results"""
        # Update UI to analyzing state
        self.draw_status_indicator("scanning")
        self.status_label.config(text="Analyzing...", fg=self.colors["accent_orange"])
        self.status_msg.config(text="Analyzing network traffic...")
        
        self.root.update()
        
        try:
            # Run traffic analysis
            result = analyze_traffic()
            
            # Update UI to active state
            self.draw_status_indicator("active")
            self.status_label.config(text="System Active", fg=self.colors["accent_green"])
            self.status_msg.config(text="Traffic analysis complete.")
            
            # Show results
            messagebox.showinfo("Traffic Analysis Result", result)
            
        except Exception as e:
            # Handle errors
            self.draw_status_indicator("error")
            self.status_label.config(text="Error", fg=self.colors["accent_red"])
            self.status_msg.config(text=f"Error analyzing traffic: {str(e)}")
            messagebox.showerror("Analysis Error", f"Failed to analyze traffic:\n{str(e)}")
    def suggest_best_network(self):
        if not self.current_networks:
            messagebox.showinfo("Suggestion", "Please scan networks first.")
            return

        best_network = None
        highest_score = -9999

        for net in self.current_networks:
            ssid, auth, bssid, signal = net
            signal_value = int(signal.replace("%", "").strip())

            is_suspicious = net in self.current_suspicious
            status, _ = classify_network(auth, is_suspicious)

            score = 0

            # Security scoring
            if "WPA3" in auth:
                score += 50
            elif "WPA2" in auth:
                score += 40
            elif "WPA" in auth:
                score += 30
            elif "WEP" in auth or "Open" in auth:
                score -= 100

            # Signal strength scoring
            score += (100 + signal_value)

            # Penalize suspicious
            if is_suspicious:
                score -= 200

            if score > highest_score:
                highest_score = score
                best_network = net

        # Highlight best network
        for item in self.tree.get_children():
            self.tree.item(item, tags=())

        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            if values[0] == best_network[0] and values[2] == best_network[2]:
                self.tree.item(item, tags=("recommended",))

        self.tree.tag_configure("recommended",
                                background="#1f3d2b",
                                foreground=self.colors["accent_green"])

        messagebox.showinfo("Recommended Network",
                            f"🏆 Best Network to Connect:\n\nSSID: {best_network[0]}")

def main():
    """Main function to start the application"""
    root = tk.Tk()
    
    # Set window icon (optional - comment out if no icon available)
    # try:
    #     root.iconbitmap("shield_icon.ico")
    # except:
    #     pass  # Skip if icon file not found
    
    # Create application instance
    app = ProfessionalWifiSecurityApp(root)
    
    # Start the main event loop
    root.mainloop()


if __name__ == "__main__":
    main()