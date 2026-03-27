# Debian 13 Installation and Configuration for SIEM Setup

The guide covers preparing a Proxmox VM, performing a minimal Debian 13 installation and post-install configuration optimized for the SIEM stack.

## System Requirements & Configuration
### System Specifications
| Component | Requirement |
|-----------|-------------|
| Operating System | Debian 13 |
| RAM | 24 GB |
| CPU | 4 cores |
| Storage | 220 GB |
| Network | 2 NICs (Management + PCI passthrough) |
| Hypervisor | Proxmox VE |

### NIC Layout
| NIC | Purpose |
|-----|---------|
| NIC 1 | Management (Elastic, Wazuh, Vector, Filebeat) |
| NIC 2 | PCI Passthrough - Monitoring (Zeek) |

NIC 2 must not be configured with an IP address or managed by NetworkManager

### Before You Begin
* Ensure you have root or sudo access
* IOMMU enabled in Proxmox
* Verify system meets minimum requirements
* Download Debian 13 netinst ISO (verify SHA512 checksum)

## Installation Overview
This guide covers the following in order:

1. Prepare the VM in Proxmox
2. Minimal Debian 13 Installation
3. Essential Post-Install Hardening & Cleanup
4. Kernel & System Tuning
5. Misc OS Best Practices

## Part 1: Prepare the VM in Proxmox
### Step 1.1: Upload the Debian 13 netinst ISO
Upload the ISO into Proxmox storage (e.g., local ISO images).

### Step 1.2: Create VM
Click **Create VM** and configure the following:  
- **Name:** `red-threat-redemption`  
- **ISO Image:** Select Debian 13 netinst  
- **OS Type:** Linux → Debian  
- **BIOS:** Default (SeaBIOS)  
- **SCSI Controller:** VirtIO SCSI
- **Disk:**  
  - Format: **Raw** 
  - Size: **220+ GB**
  - Enable **Discard/TRIM** if supported  
- **CPU**: “**host**” type, **4 cores**  
- **Memory**: **24 GB** fixed (disable ballooning for stable allocation in SIEM tools)  
- **Network:** VirtIO bridge for primary NIC (general connectivity)  

Start the VM and proceed to installation.

## Part 2: Minimal Debian 13 Installation
**During Debian Installer:**  
Boot from the ISO and select **Install**.

### Step 2.1: Language and Location
- Select language (English).  
- Choose location (United States).  
- Select keyboard layout (American English).

### Step 2.2: Network Configuration
- Detect hardware; configure primary NIC - static: enter IP, subnet, gateway, DNS).  
- Set hostname: `siem-server`.  
- Domain name: e.g., `local`.

### Step 2.3: Users and Passwords
- Set strong root password.  
- Create non-root user with sudo privileges.

### Step 2.4: Clock and Time Zone
- Enable NTP for network time sync (critical for logs).  
- Select time zone.

### Step 2.5: Partitioning (with LVM for Flexibility)
- Select **Manual** for precise control (recommended over Guided for customization).  
- Detailed steps in installer:  
  1. Select the disk (e.g., /dev/sda - VirtIO Block Device) and confirm **Yes** to create a new empty partition table (use GPT).  
  2. Create the /boot partition:  
     - Select free space --> Create a new partition.  
     - Size: 1 GB (enter "1G").  
     - Type: Primary (at beginning of space).  
     - Use as: ext4 journaling file system.  
     - Mount point: /boot.  
     - Bootable flag: on.  
     - Done setting up the partition.  
  3. Create LVM physical volume:  
     - Select remaining free space --> Create a new partition.  
     - Size: max (use all remaining space).  
     - Type: Primary.  
     - Use as: physical volume for LVM.  
     - Done setting up the partition.  
  4. Configure LVM:  
     - Go to **Configure the Logical Volume Manager** --> **Yes** to write changes.  
     - Create volume group: Select **Create volume group** --> Name: `vg-siem` --> Select the physical volume (/dev/sda2 or similar) --> Continue.  
     - Create logical volumes:  
       - Select **Create logical volume** --> Volume group: vg-siem --> Name: root --> Size: 20G --> Continue.  
       - Repeat: Name: var --> Size: 50G (or more for logs/ES; e.g., 200G if 320GB disk) --> Continue.  
       - Repeat: Name: home --> Size: max (remaining) > Continue.  
       - (Skip swap for ES best practices; if needed: Name: swap --> Size: 4G).  
  5. Assign filesystems and mount points:  
     - Select LV root --> Use as: ext4 --> Mount point: / --> Done.  
     - Select LV var --> Use as: ext4 --> Mount point: /var --> Done.  
     - Select LV home --> Use as: ext4 --> Mount point: /home --> Done.  
     - (If swap: Select LV swap --> Use as: swap area --> Done).  
  6. Finish: Select **Finish partitioning and write changes to disk** --> **Yes** to confirm.  

This setup provides: /boot outside LVM for boot safety, LVM for easy resizing (lvextend for growing /var logs), no swap to avoid Elasticsearch performance issues.

### Step 2.6: Base System Installation
- Install base system.

### Step 2.7: Package Selection (For Minimal Setup)
- Select nearby mirror.  
- In tasksel:  
  - Select only **SSH server**.  
  - Deselect all else (no desktop, no standard utilities for ultra-minimal).

### Step 2.8: Boot Loader
- Install GRUB to primary disk.

### Step 2.9: Finish and Reboot
- Eject ISO.  
- Reboot; log in as root or user.

Checkpoint: Debian should boot to CLI with minimal packages (~500MB installed).

## Part 3: Essential Post-Install Hardening & Cleanup
Once Debian boots:

### Step 3.1: Update and Upgrade
```
apt update && apt upgrade -y
```  
Reboot if kernel updated:  
```
reboot
```

### Step 3.2: Install Only Required Tools
```
apt install --no-install-recommends sudo vim curl wget net-tools gnupg apt-transport-https ca-certificates -y
```  
Add user to sudo:  
```
usermod -aG sudo your-created-user
```

## Part 4: Kernel & System Tuning
### Step 4.1: Sysctl for Elasticsearch
```
sudo touch /etc/sysctl.d/99-elastic.conf

sudo vim /etc/sysctl.conf/99-elastic.comf
vm.max_map_count=262144
sysctl --system
```

### Step 4.2: File-descriptor limits (critical for Elastic/Zeek)
```
sudo vim /etc/security/limits.conf

* soft nofile 65536
* hard nofile 65536
```

### Step 4.3: Disable Unneeded Services
```
systemctl list-units --type=service
```  
Disable extras(example):  
```
systemctl disable --now bluetooth
```

## Misc OS Best Practices
### Time Sync
Debian uses systemd-timesyncd by default for NTP. Verify:  
```
timedatectl status
```  
Enable if needed:  
```
systemctl enable --now systemd-timesyncd
```  
Enhances precision for SIEM timestamps.

### SSH Hardening
- Disable root login and password auth:  
  ```
  sudo vim /etc/ssh/sshd_config
  
  # Add at the bottom
  PermitRootLogin no
  PubkeyAuthentication yes
  PasswordAuthentication no
  AllowUsers your_user
  
  systemctl restart sshd
  ```  
- Use SSH keys for auth (generate with `ssh-keygen` from your local machine; copy public key to Debian `~/.ssh/authorized_keys`).
- Do NOT close current shell until verify ssh access

## Verification Checklist
Before proceeding, verify base system:

| Component | Status | Verification Command |
|-----------|--------|----------------------|
| System Updated | Complete | apt list --upgradable |
| Network | Primary NIC up | ip addr show eth0 |
| Time Sync | Active | timedatectl status |
| SSH | Hardened | ssh -v localhost (should require key) |

## Troubleshooting
### Common Issues & Solutions
| Issue | Possible Cause | Solution |
|-------|----------------|----------|
| No internet during install | Network config | Re-run installer network step |
| Partitioning errors | Disk size | Use Manual mode for custom LVs |
| Services not starting | Dependencies | Check journalctl -u service |

## Log Locations
| Service | Log Location |
|---------|--------------|
| System | /var/log/syslog |
| SSH | /var/log/auth.log |
| Kernel | dmesg |

## Additional Resources
* Debian Official Documentation
  https://www.debian.org/doc/
* Proxmox VE Guide
  https://pve.proxmox.com/pve-docs/pve-admin-guide.html

Checkpoint: Debian 13 is now minimally installed, hardened, and tuned for the SIEM stack.
