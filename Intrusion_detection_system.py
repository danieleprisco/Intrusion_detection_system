import scapy.all
import datetime


def sniffaLarete():
    scapy.all.sniff(prn=controllaLivello)


def controllaLivello(pacchetto):
    porteSicureTCP=[80, 443, 53, 123,5223]
    porteSicureUDP=[53, 123, 67, 68, 5353, 1900]
    if(pacchetto.haslayer(scapy.all.IP)):
        if(FiltroDiReteLocale(pacchetto[scapy.all.IP].src) or FiltroDiReteLocale(pacchetto[scapy.all.IP].dst)):
        #if(datetime.datetime.now().hour > 2 and datetime.datetime.now().hour < 6):
            if(pacchetto.haslayer(scapy.all.TCP)):
                if(pacchetto[scapy.all.TCP].dport not in porteSicureTCP and pacchetto[scapy.all.TCP].sport not in porteSicureTCP):
                    messaggio=pacchetto.sprintf("⚠️ ALLARME: Traffico sospetto! [%IP.src%] -> [%IP.dst%] in orario notturno alla porta [%TCP.dport%]")
                    with open("intrusion_log.txt", "a") as file_log:
                        file_log.write(f"{datetime.datetime.now()} - {messaggio}\n")
            elif(pacchetto.haslayer(scapy.all.UDP)):
                if(pacchetto[scapy.all.UDP].dport not in porteSicureUDP and pacchetto[scapy.all.UDP].sport not in porteSicureUDP):
                    messaggio=pacchetto.sprintf("⚠️ ALLARME: Traffico sospetto! [%IP.src%] -> [%IP.dst%] in orario notturno alla porta [%UDP.dport%]")
                    with open("intrusion_log.txt", "a") as file_log:
                        file_log.write(f"{datetime.datetime.now()} - {messaggio}\n")


def FiltroDiReteLocale(indirizzoIP):
    if(indirizzoIP.startswith("192.168.") or indirizzoIP.endswith(".255")):
        return False
    else:
        return True



if(__name__ == "__main__"):
    print("Intrusion Detection System is running...")
    sniffaLarete()