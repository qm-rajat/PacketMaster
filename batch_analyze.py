import os
from packetmaster import PacketMaster

pcap_folder = "pcaps/"  # Put all .pcap files here
results = []

for file in os.listdir(pcap_folder):
    if file.endswith('.pcap'):
        print(f"Analyzing {file}...")
        try:
            analyzer = PacketMaster(os.path.join(pcap_folder, file))
            analyzer.run_full_analysis()
            results.append(f"✅ {file}: OK")
        except:
            results.append(f"❌ {file}: FAILED")

print("\nBATCH SUMMARY:")
for r in results:
    print(r)