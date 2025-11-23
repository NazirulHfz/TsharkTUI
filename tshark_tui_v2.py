import asyncio
import psutil
import pyshark
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, DataTable, Button, Input, Select, Static, Label
from textual import work

class TsharkApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #controls_container {
        height: auto;
        dock: top;
        padding: 1;
        background: $panel;
        border-bottom: solid green;
    }
    .input-group {
        width: 1fr;
        padding-right: 1;
    }
    Select {
        width: 100%;
    }
    #btn_toggle {
        width: 100%;
        margin-top: 1;
    }
    DataTable {
        height: 1fr;
    }
    """

    BINDINGS = [("q", "quit", "Quit"), ("c", "clear_table", "Clear")]

    def __init__(self):
        super().__init__()
        self.capturing = False
        self.capture_task = None
        # Get list of system interfaces
        self.interfaces = list(psutil.net_if_addrs().keys())
        # Create a list of tuples for the Select widget [(Label, Value), ...]
        self.interface_options = [(iface, iface) for iface in self.interfaces]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        # Control Panel
        with Container(id="controls_container"):
            with Horizontal():
                # Column 1: Interface Selection
                with Vertical(classes="input-group"):
                    yield Label("Interface:")
                    yield Select(self.interface_options, prompt="Select Interface", id="iface_select")
                
                # Column 2: Target IP
                with Vertical(classes="input-group"):
                    yield Label("Target Dest IP (Optional):")
                    yield Input(placeholder="e.g. 8.8.8.8", id="target_input")

                # Column 3: Manual BPF Filter
                with Vertical(classes="input-group"):
                    yield Label("Additional BPF Filter:")
                    yield Input(placeholder="e.g. tcp port 443", id="filter_input")

            # Row 2: Action Buttons
            with Horizontal():
                yield Button("START CAPTURE", id="btn_toggle", variant="success")
                yield Button("CLEAR TABLE", id="btn_clear", variant="primary", classes="input-group")

        yield DataTable()
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("Time", "Src", "Dst", "Proto", "Len", "Info")
        
        # Select the first interface by default if available
        if self.interface_options:
             self.query_one(Select).value = self.interface_options[0][1]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_toggle":
            self.toggle_capture()
        elif event.button.id == "btn_clear":
            self.query_one(DataTable).clear()

    def toggle_capture(self):
        btn = self.query_one("#btn_toggle", Button)
        
        if self.capturing:
            # STOPPING
            self.capturing = False
            btn.label = "START CAPTURE"
            btn.variant = "success"
            # Re-enable inputs
            self.query_one("#iface_select").disabled = False
            self.query_one("#target_input").disabled = False
            self.query_one("#filter_input").disabled = False
        else:
            # STARTING
            iface = self.query_one("#iface_select").value
            if not iface:
                self.notify("Please select an interface!", severity="error")
                return

            self.capturing = True
            btn.label = "STOP CAPTURE"
            btn.variant = "error"
            
            # Disable inputs while running
            self.query_one("#iface_select").disabled = True
            self.query_one("#target_input").disabled = True
            self.query_one("#filter_input").disabled = True
            
            # Construct Filter
            target_ip = self.query_one("#target_input").value.strip()
            manual_filter = self.query_one("#filter_input").value.strip()
            
            final_filter = []
            if target_ip:
                final_filter.append(f"dst host {target_ip}")
            if manual_filter:
                final_filter.append(f"({manual_filter})")
            
            bpf_string = " and ".join(final_filter) if final_filter else None
            
            self.start_capture_loop(iface, bpf_string)

    @work(exclusive=True, thread=True)
    def start_capture_loop(self, interface, bpf_filter):
        try:
            capture = pyshark.LiveCapture(
                interface=interface,
                bpf_filter=bpf_filter
            )
            
            for packet in capture.sniff_continuously():
                if not self.capturing:
                    break
                
                try:
                    timestamp = packet.sniff_time.strftime("%H:%M:%S")
                    src = packet.ip.src if hasattr(packet, 'ip') else "Unknown"
                    dst = packet.ip.dst if hasattr(packet, 'ip') else "Unknown"
                    proto = packet.highest_layer
                    length = packet.length
                    info = f"{proto} Packet"

                    self.call_from_thread(self.add_packet, timestamp, src, dst, proto, length, info)
                except Exception:
                    pass
        except Exception as e:
            self.app.notify(f"Capture Error: {e}", severity="error")
            self.call_from_thread(self.toggle_capture) # Reset button state

    def add_packet(self, time, src, dst, proto, length, info):
        table = self.query_one(DataTable)
        table.add_row(time, src, dst, proto, length, info)
        table.scroll_end(animate=False)

if __name__ == "__main__":
    app = TsharkApp()
    app.run()