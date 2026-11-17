# ip_traffic_monitor.py
# Windows向け: 送信元IPアドレスの出現回数をリアルタイムに可視化するGUI
# 必要: Npcap(WinPcap互換), 管理者権限で実行, pip install scapy matplotlib

import threading
import queue
import time
from collections import Counter, defaultdict

import sys
import tkinter as tk
from tkinter import ttk, messagebox

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

import csv
import os

# ---- scapy imports (Windows) ----
try:
    from scapy.all import sniff, conf
    from scapy.layers.inet import IP
    # Windowsのインターフェース一覧取得
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        get_windows_if_list = None
except Exception as e:
    print("Scapyの読み込みに失敗しました。`pip install scapy` 済みか確認してください。")
    print(e)
    sys.exit(1)


class PacketSniffer(threading.Thread):
    """
    別スレッドでscapy.sniffを実行し、送信元IPをQueueに流す
    """
    def __init__(self, iface_name: str, out_queue: queue.Queue, stop_event: threading.Event, bpf_filter: str = ""):
        super().__init__(daemon=True)
        self.iface_name = iface_name
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.bpf_filter = bpf_filter

    def _packet_handler(self, pkt):
        # MACアドレス取得（Ethernetレイヤがある場合）
        src_mac = getattr(pkt, "src", "")
        dst_mac = getattr(pkt, "dst", "")

        src_ip, dst_ip = "", ""
        src_port, dst_port = "", ""
        proto = ""

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto  # 数値形式（6:TCP, 17:UDPなど）

            # TCP/UDPポート取得
            if pkt.haslayer("TCP"):
                src_port = pkt["TCP"].sport
                dst_port = pkt["TCP"].dport
                proto = "TCP"
            elif pkt.haslayer("UDP"):
                src_port = pkt["UDP"].sport
                dst_port = pkt["UDP"].dport
                proto = "UDP"
            else:
                # ICMPなどの場合
                proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(pkt[IP].proto, str(pkt[IP].proto))

            # カウント用（送信元IP）
            self.out_queue.put(src_ip)

            # ログ用（詳細情報）
            log_entry = (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                src_ip, dst_ip,
                src_mac, dst_mac,
                src_port, dst_port,
                proto
            )
            self.out_queue.put(("__LOG__", log_entry))

    def run(self):
        # store=Falseでメモリ使用を抑制
        try:
            sniff(
                iface=self.iface_name,
                prn=self._packet_handler,
                store=False,
                filter=self.bpf_filter if self.bpf_filter else None,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            # 典型: 権限不足/Npcap未導入/インターフェース名不一致/フィルタ構文エラー
            self.out_queue.put(("__ERROR__", str(e)))


class App(tk.Tk):
    REFRESH_MS = 1000  # グラフ更新間隔(ms)
    TOP_N = 10        # 上位N件の送信元IPを表示

    def __init__(self):
        super().__init__()
        self.title("IP Traffic Monitor (Windows + Npcap)")
        self.geometry("900x600")

        self.log_file = "packet_log.csv"
        self._init_csv_log()

        self.sniffer_thread = None
        self.stop_event = threading.Event()
        self.q = queue.Queue()
        self.counter = Counter()
        self.total_packets = 0
        self.iface_map = {}
        self._build_ui()
        self._load_interfaces()
        self.after(self.REFRESH_MS, self._refresh_plot)

    def _init_csv_log(self):
        # CSVログ初期化（ヘッダ行）
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "src_ip", "dst_ip", "src_mac", "dst_mac", "src_port", "dst_port", "protocol"])


    # ---------------- UI ----------------
    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        ttk.Label(top, text="インターフェース:").pack(side=tk.LEFT, padx=(0, 6))
        self.iface_combo = ttk.Combobox(top, state="readonly", width=60)
        self.iface_combo.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(top, text="BPFフィルタ(任意):").pack(side=tk.LEFT, padx=(0, 6))
        self.filter_entry = ttk.Entry(top, width=25)
        self.filter_entry.insert(0, "ip")  # 例: "tcp", "udp", "port 80" など
        self.filter_entry.pack(side=tk.LEFT, padx=(0, 10))

        self.start_btn = ttk.Button(top, text="Start", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.reset_btn = ttk.Button(top, text="Reset Counts", command=self.reset_counts)
        self.reset_btn.pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar(value="準備完了")
        self.status_label = ttk.Label(self, textvariable=self.status_var)
        self.status_label.pack(side=tk.TOP, anchor="w", padx=12, pady=(0, 6))

        # matplotlib Figure
        self.fig = Figure(figsize=(8, 4.5), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Source IP counts (Top 10)")
        self.ax.set_xlabel("Source IP")
        self.ax.set_ylabel("Packets")
        self.ax.grid(True, axis='y')

        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 下部: 合計/ユニーク数
        bottom = ttk.Frame(self)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        self.total_var = tk.StringVar(value="Total packets: 0 | Unique IPs: 0")
        ttk.Label(bottom, textvariable=self.total_var).pack(side=tk.LEFT)

    def _load_interfaces(self):
        try:
            if get_windows_if_list is None:
                raise RuntimeError("get_windows_if_listが利用できません。ScapyのWindows向け機能が見つかりません。")

            win_ifs = get_windows_if_list()
            # 表示名は「Name (Description)」にして、内部的には scapy.conf.ifaces のインデックス化名を使う
            # ただしscapyのsniffには「Description」または「Name」で通ることが多いのでDescription優先で渡す
            self.iface_combo_values = []
            for d in win_ifs:
                name = d.get("name", "")
                desc = d.get("description", "")
                guid = d.get("guid", "")
                display = f"{name} ({desc})"
                # sniffのiface引数にdescを渡す方が成功しやすい
                iface_for_scapy = desc or name or guid
                self.iface_map[display] = iface_for_scapy
                self.iface_combo_values.append(display)

            if not self.iface_combo_values:
                raise RuntimeError("ネットワークインターフェースが見つかりません。Npcapが導入済みか確認してください。")

            self.iface_combo["values"] = self.iface_combo_values
            # それっぽいデフォルト（最初のもの）
            self.iface_combo.current(0)
        except Exception as e:
            messagebox.showerror("エラー", f"インターフェース取得に失敗: {e}")
            self.status_var.set(f"インターフェース取得失敗: {e}")

    # --------------- Capture control ---------------
    def start_capture(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return
        sel = self.iface_combo.get()
        if not sel:
            messagebox.showwarning("注意", "インターフェースを選択してください。")
            return

        iface = self.iface_map.get(sel, sel)
        bpf = self.filter_entry.get().strip()
        self.stop_event.clear()
        self.sniffer_thread = PacketSniffer(iface_name=iface, out_queue=self.q, stop_event=self.stop_event, bpf_filter=bpf)
        self.sniffer_thread.start()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set(f"キャプチャ開始: {sel} | フィルタ: {bpf or '(なし)'}")

    def stop_capture(self):
        self.stop_event.set()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("停止中…（数秒かかる場合があります）")

    def reset_counts(self):
        self.counter.clear()
        self.total_packets = 0
        self._draw_chart()

    # --------------- Update & Plot ----------------
    def _drain_queue(self):
        drained = 0
        while True:
            try:
                item = self.q.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, tuple) and item and item[0] == "__ERROR__":
                # スニッファ側エラー
                self.status_var.set(f"キャプチャエラー: {item[1]}")
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                continue

            if isinstance(item, tuple) and item and item[0] == "__LOG__":
                # ログ書き込み
                self._write_csv_log(item[1])
                continue

            # 通常カウント用
            self.counter[item] += 1
            self.total_packets += 1
            drained += 1
        return drained

    def _write_csv_log(self, log_entry):
        try:
            with open(self.log_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(log_entry)
        except Exception as e:
            self.status_var.set(f"CSV書き込みエラー: {e}")


    def _refresh_plot(self):
        # Queueから結果を取り出してカウント更新
        self._drain_queue()
        self._draw_chart()
        # ステータス
        self.total_var.set(f"Total packets: {self.total_packets} | Unique IPs: {len(self.counter)}")
        # 再スケジュール
        self.after(self.REFRESH_MS, self._refresh_plot)

    def _draw_chart(self):
        self.ax.clear()
        self.ax.set_title(f"Source IP counts (Top {self.TOP_N})")
        self.ax.set_xlabel("Source IP")
        self.ax.set_ylabel("Packets")
        self.ax.grid(True, axis='y')

        if self.counter:
            # 上位N件
            top = self.counter.most_common(self.TOP_N)
            labels = [ip for ip, cnt in top]
            values = [cnt for ip, cnt in top]
            self.ax.bar(labels, values)
            # IPが長くて重なるので回転
            self.ax.set_xticklabels(labels, rotation=30, ha='right')

        self.canvas.draw_idle()


if __name__ == "__main__":
    # scapyの最適化（必要に応じて）
    # WindowsではL2socketを使わずWinPcap経由になる
    app = App()
    app.mainloop()
