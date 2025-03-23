# DDoS Detection and Blocking System with SDN

Sistem deteksi dan blocking DDoS menggunakan Software Defined Networking (SDN) dengan Mininet dan Ryu Controller.

## Prasyarat

- Kali Linux
- Mininet
- Open vSwitch
- Docker
- Ryu Controller

## Instalasi

1. Install dependensi yang diperlukan:
```bash
sudo apt update
sudo apt install mininet openvswitch-switch docker.io -y
```

2. Start Open vSwitch:
```bash
sudo systemctl start openvswitch-switch
sudo systemctl enable openvswitch-switch
```

3. Start Docker:
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

## Cara Penggunaan

1. Jalankan Ryu Controller dengan DDoS detector:
```bash
sudo docker run --rm -it -p 6633:6633 osrg/ryu ryu-manager --verbose ddos_detector.py
```

2. Di terminal baru, jalankan simulasi Mininet:
```bash
sudo python mininet_attack.py
```

## Penjelasan Sistem

### Komponen Utama

1. **DDoS Detector (ddos_detector.py)**
   - Controller Ryu yang mendeteksi anomali lalu lintas
   - Menggunakan threshold 100 paket per detik
   - Otomatis memblokir sumber yang terdeteksi melakukan serangan

2. **Mininet Attack Simulator (mininet_attack.py)**
   - Membuat topologi jaringan dengan 4 host dan 2 switch
   - Mensimulasikan serangan ping flood dari h1 ke h2
   - Durasi serangan: 10 detik

### Topologi Jaringan

```
h1 --- s1 --- s2 --- h3
 |      |      |      |
h2     |      |      h4
```

## Monitoring

- Controller akan menampilkan log ketika mendeteksi serangan DDoS
- Host yang terblokir tidak dapat mengirim paket ke jaringan
- Status blocking dapat dilihat di log Ryu Controller

## Troubleshooting

1. Jika port 6633 sudah digunakan:
```bash
sudo fuser -k 6633/tcp
```

2. Jika ada masalah dengan OVS:
```bash
sudo ovs-vsctl show
```

3. Untuk membersihkan environment:
```bash
sudo mn -c
``` 