job_queue: artur-oemscript-2404
provision_data:
  use_zapper: true
  url: http://10.102.196.9/stella/releases/noble/oem-24.04a/20240709-22/stella-noble-oem-24.04a-20240709-22.iso 
  skip_download: true
  robot_tasks:
    - hp/zbook/power_g11/boot/boot_from_usb.robot

