import io
import ipaddress
from collections import Counter
from datetime import datetime

import pandas as pd
import streamlit as st
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, ARP

st.set_page_config(page_title="PacketPilot AI", page_icon="🛡️", layout="wide")

APP_TITLE = "PacketPilot AI"


def get_setting(name, default=None):
    """Read a Streamlit secret first, then an environment variable."""
    try:
        value = st.secrets.get(name, default)
        if value is not None:
            return value
    except Exception:
        pass
    import os
    return os.getenv(name, default)


def authenticate():
    """
    Simple password gate for a single-user demo.
    Configure APP_USERNAME and APP_PASSWORD in Streamlit secrets.
    This is not a full identity provider or production Zero Trust system.
    """
    username = get_setting("APP_USERNAME")
    password = get_setting("APP_PASSWORD")

    if not username or not password:
        st.error(
            "Authentication is not configured. Add APP_USERNAME and APP_PASSWORD "
            "to Streamlit Cloud → app settings → Secrets, or set them as environment variables."
        )
        st.code('APP_USERNAME = "your-username"\\nAPP_PASSWORD = "use-a-long-unique-password"')
        st.stop()

    if st.session_state.get("authenticated") is True:
        with st.sidebar:
            st.success(f"Signed in as {st.session_state.get('username', username)}")
            if st.button("Log out"):
                st.session_state.clear()
                st.rerun()
        return

    st.title("🛡️ PacketPilot AI")
    st.subheader("Sign in")
    st.caption("Authorized access only.")
    with st.form("login_form"):
        entered_username = st.text_input("Username")
        entered_password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", use_container_width=True)

    if submitted:
        # Demo gate only. For multi-user production use OIDC/SSO and server-side authorization.
        if entered_username == str(username) and entered_password == str(password):
            st.session_state["authenticated"] = True
            st.session_state["username"] = entered_username
            st.rerun()
        else:
            st.error("Invalid username or password.")
    st.stop()


def classify_protocol(packet):
    if ARP in packet:
        return "ARP"
    if DNS in packet:
        return "DNS"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if IPv6 in packet:
        return "IPv6 (other)"
    if IP in packet:
        return "IPv4 (other)"
    return "Other"


def safe_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return str(value)


def analyze_capture(raw_bytes):
    packets = rdpcap(io.BytesIO(raw_bytes))
    rows = []
    src_counts = Counter()
    dst_counts = Counter()
    protocol_counts = Counter()
    syn_counts = Counter()
    port_counts = Counter()
    dns_queries = Counter()
    alerts = []

    for index, packet in enumerate(packets, start=1):
        timestamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S")
        src = dst = "N/A"
        src_port = dst_port = None
        length = len(packet)
        flags = ""
        protocol = classify_protocol(packet)

        if IP in packet:
            src, dst = safe_ip(packet[IP].src), safe_ip(packet[IP].dst)
        elif IPv6 in packet:
            src, dst = safe_ip(packet[IPv6].src), safe_ip(packet[IPv6].dst)
        elif ARP in packet:
            src, dst = packet[ARP].psrc or "N/A", packet[ARP].pdst or "N/A"

        if src != "N/A":
            src_counts[src] += 1
        if dst != "N/A":
            dst_counts[dst] += 1
        protocol_counts[protocol] += 1

        if TCP in packet:
            tcp = packet[TCP]
            src_port, dst_port = int(tcp.sport), int(tcp.dport)
            flags = str(tcp.flags)
            port_counts[(dst, dst_port)] += 1
            if "S" in flags and "A" not in flags:
                syn_counts[src] += 1

        if UDP in packet:
            src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)
            port_counts[(dst, dst_port)] += 1

        if DNS in packet and packet[DNS].qd is not None:
            try:
                qname = packet[DNS].qd.qname.decode("utf-8", errors="replace").rstrip(".")
                if qname:
                    dns_queries[qname] += 1
            except Exception:
                pass

        rows.append({
            "Packet": index,
            "Timestamp": timestamp,
            "Protocol": protocol,
            "Source IP": src,
            "Source Port": src_port,
            "Destination IP": dst,
            "Destination Port": dst_port,
            "Length (bytes)": length,
            "TCP Flags": flags,
        })

    # Heuristic alerts: these are indicators for investigation, not proof of an attack.
    for source, count in syn_counts.most_common():
        if count >= 20:
            alerts.append({
                "Severity": "Medium",
                "Type": "High SYN count",
                "Source": source,
                "Details": f"{count} TCP SYN packets without ACK observed. Could be scanning or normal connection bursts."
            })

    for (destination, port), count in port_counts.most_common():
        if count >= 25:
            alerts.append({
                "Severity": "Low",
                "Type": "High destination-port traffic",
                "Source": destination,
                "Details": f"{count} TCP/UDP packets observed to destination port {port}. Review in context."
            })

    for source, count in src_counts.most_common():
        if count >= 100:
            alerts.append({
                "Severity": "Low",
                "Type": "High packet volume",
                "Source": source,
                "Details": f"{count} packets associated with this source IP in the uploaded capture."
            })

    return packets, pd.DataFrame(rows), protocol_counts, src_counts, dst_counts, dns_queries, pd.DataFrame(alerts)


def main():
    authenticate()

    st.title("🛡️ PacketPilot AI")
    st.write("PCAP/PCAPNG traffic inspection and basic rule-based triage.")
    st.info(
        "This version analyzes uploaded captures only. It does not capture live traffic, "
        "and its heuristic alerts are not proof of malicious activity."
    )

    with st.sidebar:
        st.header("Analysis settings")
        st.caption("Upload a capture file to begin.")
        st.caption("For privacy, use captures you are authorized to inspect.")

    uploaded = st.file_uploader("Upload a PCAP or PCAPNG file", type=["pcap", "pcapng", "cap"])

    if uploaded is None:
        st.markdown("### What this demo can do")
        st.markdown(
            "- Summarize protocols and packet counts\n"
            "- List source and destination IP addresses\n"
            "- Inspect TCP/UDP ports and TCP flags\n"
            "- Extract visible DNS query names\n"
            "- Flag simple traffic patterns for manual review"
        )
        return

    max_size_mb = 50
    raw = uploaded.getvalue()
    if len(raw) > max_size_mb * 1024 * 1024:
        st.error(f"File is larger than the {max_size_mb} MB demo limit. Use a smaller capture.")
        return

    try:
        with st.spinner("Reading and analyzing the capture..."):
            packets, frame, protocol_counts, src_counts, dst_counts, dns_queries, alerts = analyze_capture(raw)
    except Exception as exc:
        st.error("Could not parse this capture. Confirm it is a valid PCAP/PCAPNG file.")
        st.caption(f"Technical detail: {type(exc).__name__}: {exc}")
        return

    if frame.empty:
        st.warning("The capture contains no packets.")
        return

    total_bytes = int(frame["Length (bytes)"].sum())
    unique_src = int(frame["Source IP"].nunique())
    unique_dst = int(frame["Destination IP"].nunique())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", f"{len(frame):,}")
    c2.metric("Capture size", f"{total_bytes:,} bytes")
    c3.metric("Unique sources", f"{unique_src:,}")
    c4.metric("Unique destinations", f"{unique_dst:,}")

    tab_overview, tab_packets, tab_ips, tab_dns, tab_alerts, tab_export = st.tabs(
        ["Overview", "Packets", "IP Analysis", "DNS", "Alerts", "Export"]
    )

    with tab_overview:
        st.subheader("Protocol distribution")
        protocol_frame = pd.DataFrame(protocol_counts.items(), columns=["Protocol", "Packets"])
        if not protocol_frame.empty:
            st.bar_chart(protocol_frame.set_index("Protocol"))
            st.dataframe(protocol_frame.sort_values("Packets", ascending=False), use_container_width=True, hide_index=True)
        st.subheader("Top source IPs")
        top_src = pd.DataFrame(src_counts.most_common(10), columns=["Source IP", "Packets"])
        st.dataframe(top_src, use_container_width=True, hide_index=True)

    with tab_packets:
        st.subheader("Packet table")
        protocol_options = ["All"] + sorted(frame["Protocol"].unique().tolist())
        selected_protocol = st.selectbox("Filter by protocol", protocol_options)
        filtered = frame if selected_protocol == "All" else frame[frame["Protocol"] == selected_protocol]
        st.dataframe(filtered, use_container_width=True, hide_index=True, height=480)

    with tab_ips:
        left, right = st.columns(2)
        with left:
            st.subheader("Source IPs")
            st.dataframe(pd.DataFrame(src_counts.most_common(), columns=["IP", "Packets"]), use_container_width=True, hide_index=True)
        with right:
            st.subheader("Destination IPs")
            st.dataframe(pd.DataFrame(dst_counts.most_common(), columns=["IP", "Packets"]), use_container_width=True, hide_index=True)

    with tab_dns:
        st.subheader("DNS queries visible in the capture")
        if dns_queries:
            dns_frame = pd.DataFrame(dns_queries.most_common(), columns=["Domain", "Queries"])
            st.dataframe(dns_frame, use_container_width=True, hide_index=True)
        else:
            st.info("No readable DNS query names were found in this capture. Encrypted DNS or a capture without DNS traffic can explain this.")

    with tab_alerts:
        st.subheader("Rule-based triage alerts")
        if alerts.empty:
            st.success("No configured heuristic thresholds were triggered.")
        else:
            st.warning("Alerts are heuristic indicators only. Validate them against context and other evidence.")
            st.dataframe(alerts, use_container_width=True, hide_index=True)

    with tab_export:
        st.subheader("Export results")
        st.download_button(
            "Download packet analysis CSV",
            data=frame.to_csv(index=False).encode("utf-8"),
            file_name="packetpilot_packet_analysis.csv",
            mime="text/csv",
        )
        if not alerts.empty:
            st.download_button(
                "Download alerts CSV",
                data=alerts.to_csv(index=False).encode("utf-8"),
                file_name="packetpilot_alerts.csv",
                mime="text/csv",
            )


if __name__ == "__main__":
    main()
