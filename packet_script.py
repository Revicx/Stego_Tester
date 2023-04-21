from telnetlib import IP
import paho.mqtt.client as mqtt
from time import sleep
from tkinter import *
from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
import subprocess
from datetime import datetime


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected OK")
    else:
        print("Bad connenction ", rc)

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.


def on_log(client, userdata, level, buf):
    print("log: " + buf)


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic + " " + str(msg.payload))


def sip_message(ip_dst, ip_src, CallID, mf, contact, cseq, iface):
    sourcePort = 3001
    destinationIp = ip_dst
    sourceIp = ip_src
    ip = IP(src=sourceIp, dst=destinationIp)
    myPayload = (
        "INVITE sip:{0}:5060;transport=tcp SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.44.32:5060;branch=1234\r\n"
        'From: "somedevice"<sip:somedevice@1.1.1.1:5060>;tag=5678\r\n'
        "To: <sip:{0}:5060>\r\n"
        "Call-ID: " + CallID + " \r\n"
        "CSeq: {1} INVITE\r\n"
        "Max-Forwards: " + mf + "\r\n"
        "Contact: <sip:" + contact + "@pc33.atlanta.com>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).format(destinationIp, cseq)
    udp = UDP(dport=5060, sport=sourcePort)
    send(ip / udp / myPayload, iface)


def mqtt_message(broker, id, user, psw, topic, payload, keepalive, retainval):
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client = mqtt.Client(id)
    client.username_pw_set(user, password=psw)
    print("connecting to broker ", broker)
    sleep(10)
    client.connect(broker, 1883, keepalive)
    client.loop_start()
    client.publish(topic, payload, retain=retainval)
    client.loop_stop()
    client.disconnect()


def mqtt_subscribe(ip, id, user, psw, topic, clean):
    print(topic)
    client = mqtt.Client(client_id=id, clean_session=clean)
    client.on_connect = on_connect
    client.on_message = on_message
    broker = ip
    client.username_pw_set(user, password=psw)
    print("connecting to broker ", broker)
    client.loop_start()
    client.connect(broker)
    client.subscribe(topic)
    client.loop_forever()


def create_layer3(src_ip, dst_ip, proto, tos=None, ttl=None, id=None):
    layer3 = IP()
    layer3.src = src_ip
    layer3.dst = dst_ip
    layer3.proto = proto

    if tos is not None:
        layer3.tos = tos

    if ttl is not None:
        layer3.ttl = ttl

    if id is not None:
        layer3.id = id

    return layer3


def create_icmp_layer4(type, code, id, seq):
    layer4 = ICMP()
    layer4.type = type
    layer4.code = code
    layer4.id = id
    layer4.seq = seq

    return layer4


def create_tcp_layer4(src_port, dst_port, reserved, flags, window, urg_ptr, seq_num):
    layer4 = TCP()
    layer4.sport = src_port
    layer4.dport = dst_port
    layer4.reserved = int(reserved, 2)
    layer4.flags = flags
    layer4.window = window
    layer4.urgptr = int(urg_ptr, 2)
    layer4.seq = seq_num

    return layer4


def cmd_ping(ip_dst, ip_src, seq, icmp_id, iface):
    layer3 = create_layer3(ip_src, ip_dst, 1)
    layer4 = create_icmp_layer4(8, 0, icmp_id, seq)
    pkt = layer3 / layer4 / b"abcdefghijklmn opqrstuvwabcdefg hi"
    send(pkt, iface=iface)
    print("Ping Sent")


def cmd_tcpip(
    ip_src,
    ip_dst,
    TOS,
    ttl,
    id,
    reserved,
    seq_num,
    window,
    urg_ptr,
    flags,
    payload,
    src_port,
    iface,
):
    layer3 = create_layer3(ip_src, ip_dst, 6, tos=TOS, ttl=ttl, id=id)
    layer4 = create_tcp_layer4(src_port, 80, reserved, flags, window, urg_ptr, seq_num)

    if not payload:
        pkt = layer3 / layer4
    else:
        pkt = layer3 / layer4 / payload

    send(pkt, iface=iface)


def start_capture(tshark_path, interface, capture_file_path):
    interface = f'"{interface}"'
    command = "%s -i %s -w %s" % (tshark_path, interface, capture_file_path)
    proc = subprocess.Popen(command)
    return proc


def main():
    # Define the variables for the function calls
    ip_src = "127.0.0.1"
    ip_dst = "127.0.0.1"
    CallID = "hello"
    mf = "100"
    contact = "alice@sip.pl"
    iface = "Ethernet 2"

    # Define messages to send
    messages = [
        "Longer test.",
    ]

    # Set the path to tshark.exe
    tshark_path = r'"C:\Program Files\Wireshark\tshark.exe"'
    current_date = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    filename = f"capture_{current_date}.pcap"
    capture_file_path = rf"C:\Users\John\Documents\Repos\Stego_Tester\{filename}"

    proc = start_capture(tshark_path, iface, capture_file_path)

    time.sleep(1)
    for msg in messages:
        message = msg
        for char in list(message):
            print(char)
            cseq = str(ord(char))
            # Call the sip_message() function with the parameters
            sip_message(ip_dst, ip_src, CallID, mf, contact, cseq, iface)
    time.sleep(1)
    # Terminate the tshark process
    proc.terminate()


if __name__ == "__main__":
    main()
