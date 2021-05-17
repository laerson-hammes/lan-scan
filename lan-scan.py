import scapy.all as scapy # type: ignore
import re
import argparse


class LanScan(object):
   def __init__(self, /) -> None:
      self.ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")


   def verify_ip_address_range(self, ip_add_range_entered, /) -> bool:
      if self.ip_add_range_pattern.search(ip_add_range_entered):
         return True
      return False
   
   
   def get_arguments(self, /) -> str:
      parser = argparse.ArgumentParser()
      parser.add_argument("-ipr", dest="ipr", help="Enter the ip address and range that you want to send the ARP request to (ex 192.168.1.0/24)")
      options = parser.parse_args()
      if not options.ipr:
         options.ipr = str(input("[+] Enter the ip address and range that you want to send the ARP request to (ex 192.168.1.0/24) "))
      return options.ipr
   

   def start(self, /) -> None:
      ip_add_range_entered: str = self.get_arguments()
      verify_result: bool = self.verify_ip_address_range(ip_add_range_entered)
      if verify_result:
         arp_result: tuple = scapy.arping(ip_add_range_entered)
      else:
         print("[-] Invalid IP address and range...")
   
   
if __name__ == "__main__":
   scan = LanScan()
   scan.start()