import time
import csv
import pyshark
import os

INTERFACE="eth0"
VICTIM="192.168.20.8"

capture = pyshark.LiveCapture(
    interface=INTERFACE,
    bpf_filter=f"ip dst {VICTIM}"
)

print("Mode: 0 normal / 1 attack")
label = int(input("Enter: "))

file_exists = os.path.exists("dataset_raw.csv")

f = open("dataset_raw.csv","a",newline="")
writer = csv.writer(f)

if not file_exists:
    writer.writerow(["timestamp","src","label"])

print("Recording... CTRL+C to stop")

try:
    for pkt in capture.sniff_continuously():

        try:
            writer.writerow([
                time.time(),
                pkt.ip.src,
                label
            ])
        except:
            continue

except KeyboardInterrupt:
    print("Stopped")

finally:
    f.close()
