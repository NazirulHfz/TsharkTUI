import asyncio
import pyshark
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Header, Footer, DataTable, Button, Input, Static
from textual import work

class TsharkApp(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    #controls {
        height: 3;
        dock: top;
        padding: 1;
        background: $panel;
    }
    Input {
        width: 70%;
    }
    Button {
        width: 15%;
        margin-left: 1;
    }
    DataTable {
        height: 1fr;
        border: solid green;
    }
    """

    BINDINGS = [("q", "quit", "Quit"), ("c", "clear_table", "Clear")]

    def __init__(self):
        super().__init__()
        self.capturing = False
        self.capture_task = None
        self.interface = "any"  # Change this to 'eth0' etc if needed

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="controls"):
            with Horizontal():
                yield Input(placeholder="BPF Filter (e.g., 'tcp port 80')", id="filter_input")
                yield Button("Start Capture", id="btn_toggle", variant="success")
                yield Button("Clear", id="btn_clear", variant="primary")
        yield DataTable()
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        # Define columns
        table.add_columns("Time", "Source", "Destination", "Protocol", "Length", "Info")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_toggle":
            self.toggle_capture()
        elif event.button.id == "btn_clear":
            self.action_clear_table()

    def action_clear_table(self) -> None:
        table = self.query_one(DataTable)
        table.clear()

    def toggle_capture(self):
        btn = self.query_one("#btn_toggle", Button)
        if self.capturing:
            self.capturing = False
            btn.label = "Start Capture"
            btn.variant = "success"
            self.query_one("#filter_input").disabled = False
        else:
            self.capturing = True
            btn.label = "Stop Capture"
            btn.variant = "error"
            bpf_filter = self.query_one("#filter_input").value
            self.query_one("#filter_input").disabled = True
            self.start_capture_loop(bpf_filter)

    @work(exclusive=True, thread=True)
    def start_capture_loop(self, bpf_filter):
        # Initialize Pyshark LiveCapture
        # We set a timeout so the loop yields and checks self.capturing
        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=bpf_filter if bpf_filter else None
        )
        
        # Sniff packets continuously
        for packet in capture.sniff_continuously():
            if not self.capturing:
                break
            
            try:
                # Extract basic info safely
                timestamp = packet.sniff_time.strftime("%H:%M:%S")
                src = packet.ip.src if hasattr(packet, 'ip') else "Unknown"
                dst = packet.ip.dst if hasattr(packet, 'ip') else "Unknown"
                proto = packet.highest_layer
                length = packet.length
                # Info is harder to get generically in pyshark, usually requires specific layer access
                # We'll use the highest layer name for now
                info = f"{proto} Packet" 

                # Update UI (must be done on main thread)
                self.call_from_thread(self.add_packet_to_table, timestamp, src, dst, proto, length, info)
            except Exception:
                # Ignore malformed packets for UI stability
                pass

    def add_packet_to_table(self, time, src, dst, proto, length, info):
        table = self.query_one(DataTable)
        table.add_row(time, src, dst, proto, length, info)
        # Auto-scroll to bottom
        table.scroll_end(animate=False)

if __name__ == "__main__":
    app = TsharkApp()
    app.run()