# Requirements

| Version | Date | Authors | Contributors |
| :---- | :---- | :---- | :---- |
| 1.0 | 2026-01-27 | Nick Hummel | Eric Eilertson, B Keen |

These requirements are written to be practical and understandable, rather than to be definite specifications. The expectation is that the vendor works with these during the design of the product and does their best to comply with their spirit, as opposed to merely treating this as a checkbox exercise after the fact. These security requirements are to be regarded as inherent to the product and vendor processes, and compliance to them is not an add-on feature.

Not all requirements apply to all products. Check the [product types page](./producttypes.md) to see which requirements apply in a specific case.

## General

### GEN001: Debug

Debug features must fulfill the following:

* Offer no way to extract or leverage cryptographic or otherwise security-sensitive assets, like [UDSs](https://www.microsoft.com/en-us/research/project/dice-device-identifier-composition-engine/) or confidential [OTP](https://en.wikipedia.org/wiki/Programmable_ROM#One_time_programmable_memory) bits, which persist over resets.
* Be disabled by default and only possible to enable on reset.
* Have their enablement measured as part of firmware measurement.

This only applies to debug interfaces that can potentially be used to access confidential data or perform privileged actions. For example, [JTAG](https://en.wikipedia.org/wiki/JTAG) has to fulfill these points, whereas a pure logging facility specifically made to not show any data of the workloads running on the device or other confidential data would not have to fulfill these points.

### GEN002: Isolation

Functionality must be implemented to allow isolating workloads/tenants from each other during the normal production use of the platform, more specifically:

* Shared resources, such as [NICs](https://en.wikipedia.org/wiki/Network_interface_controller), [GPUs](https://en.wikipedia.org/wiki/Graphics_processing_unit) and memory, must be configurable to not leak data between concurrent but distinct users.
* Shared resources must also be configurable to avoid giving one user the power to make them unusable by the other users, e.g. by taking up all CPU time or simply switching them off.

### GEN003: Sanitization

The product must offer a way to easily and completely erase all user data between uses. This is to ensure no data leaks between workloads/tenants and attackers cannot store malicious data persistently.

### GEN004: Deprovisioning

The product must offer a way to easily (i.e. not having to physically grind it into dust) securely decommission the device. This must include erasing all user data and all other confidential data, such as [OTP](https://en.wikipedia.org/wiki/Programmable_ROM#One_time_programmable_memory) secrets, [private keys](https://en.wikipedia.org/wiki/Public-key_cryptography) and [UDSs](https://www.microsoft.com/en-us/research/project/dice-device-identifier-composition-engine/). Sanitization must adhere to [NIST SP 800-88](https://csrc.nist.gov/pubs/sp/800/88/r2/final).

## Business Processes

### BP001: Design and source code review

The design and source code of the product must be reviewed by an [approved third party lab](https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Documentation/security_review_providers.md) under [OCP S.A.F.E.](https://github.com/opencomputeproject/OCP-Security-SAFE) The short-form report must be published. Products do not have to be vulnerability-free to use them. Vulnerabilities are reviewed and it is decided case by case, based on what impact a vulnerability has with a given use-case and how it can be mitigated in the wider infrastructure, whether it is acceptable to use the product. However, it is strongly recommended getting reviewers involved as early as possible, as this will make mitigating issues much easier.

### BP002: Security vulnerabilities and incidents

Documented business processes must be implemented that cover:

* Finding out about public vulnerabilities and vendor-known vulnerabilities of third-party components included in the product.
* Communicating all vulnerabilities and security incidents known to affect the product to the customer according to a pre-agreed timeline.  
* Remediating vulnerabilities and security incidents.

### BP003: Secure transmission

Files that are confidential or need integrity protection must be transmitted in a suitably encrypted way, rather than, for example, by plaintext email or unprotected FTP. A simple way to accomplish this is to upload to a secure cloud drive of the respective customer. This applies to communication between the vendor and the customer, as well as between the vendor and their suppliers.

## Hardware

### HW001: Thermal and power limits

There must be hardware-enforced limits on temperature, clock, power, and any other relevant physical parameters that protect the physical integrity of the hardware. If there were only software-enforced limits, an attacker that successfully gained access to the required software privilege level could physically destroy the platform, thereby leaving no recovery path.

### HW002: Physical interfaces

Physical interfaces that are not necessary for the production operation of the platform must be removed for production builds. All remaining interfaces, for debug, management, manufacturing, or other purposes, must be protected against unauthorized use.

## Software

These requirements apply to all software, including firmware.

### SW001: Testing

All software must have the following automated release blocking tests:

* A thorough set of unit and integration tests  
* Real hands-on test of a normal use-case on real hardware without simulation, emulation or virtualization

### SW002: SBOM

[SBOMs (Software Bills of Material)](https://en.wikipedia.org/wiki/Software_supply_chain) must be delivered with all production releases of software. These are needed to monitor for security vulnerabilities and be able to quickly identify affected products when a new vulnerability becomes publicly known.

### SW003: Exploit protections

All software must be configured to enable the following where applicable:

* [Address Space Layout Randomization (ASLR)](https://en.wikipedia.org/wiki/Address_space_layout_randomization)  
* Stack overflow protection (e.g. Canaries)  
* Kernel Address Space Layout Randomization (KASLR)  
* Kernel heap overflow protection  
* Non-executable memory enforcement (aka NX, W^X, XD, XI, XN bit) via [MMU](https://en.wikipedia.org/wiki/Memory_management_unit), [MPU](https://en.wikipedia.org/wiki/Memory_protection_unit), or [IOMMU](https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit) as appropriate

[Appendix 1](#appendix-1-suggested-build-options) lists build options, these are only recommendations as it can vary wildly what is useful and reasonable.

### SW004: Updatability

All software must be updatable without physically accessing the product. This ensures that vulnerabilities can be patched at scale. This includes firmware, except the first immutable stage.

### SW005: Dependency updates

All external open source or third party dependencies must be kept up to date for every build for a production release. It is not sufficient to only update when a vulnerability becomes known in the version that is in use, because there are many fewer eyes on older versions looking for vulnerabilities.

### SW006: Privileged access

Functionality that provides privileged access, for example server remote management web interfaces, must be properly access controlled and connection to them must be encrypted, e.g. using [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security). Access control should avoid password-based authentication. All asymmetric cryptography must use [PQC](https://en.wikipedia.org/wiki/Post-quantum_cryptography) algorithms.

## Firmware

These requirements apply to firmware in addition to the software requirements. Firmware is all software that is not intended to be replaced and managed by the end user of the product.

### FW001: Firmware signature verification

The vendor must cryptographically sign all production firmware releases with a [PQC](https://en.wikipedia.org/wiki/Post-quantum_cryptography) signature scheme. The first, immutable stage need not be signed. The signatures must be verified before the firmware is executed and before a firmware update is applied.

The [OCP Hardware Secure Boot document](https://www.opencompute.org/documents/secure-boot-2-pdf) provides further details on how firmware signature verification on boot should work. ROM patching and other secure boot bypass mechanisms must be permanently disabled for production systems.

It is preferable that dual signing is supported, so that both the vendor and the customer can sign the firmware and both signatures are verified before executing/updating.

It would also be preferable if the vendor provides a signing transparency log.

### FW002: Measurement

Firmware must be measured by a [RoT](https://trustedcomputinggroup.org/about/what-is-a-root-of-trust-rot/). Measurement must include everything that affects the security of the product, such as configuration, mutable code and enablement of debug/recovery modes. Measurement must be redone when firmware is reloaded, otherwise malicious code loaded after a partial reset might stay undetected.

Measurements must be provided on request via [SPDM](https://www.dmtf.org/standards/spdm). At least SPDM 1.5 (because of [PQC](https://en.wikipedia.org/wiki/Post-quantum_cryptography)) with the following commands must be supported:

* Get Version  
* Negotiate Algorithms  
* Get Capabilities  
* Get Digests  
* Get Certificate  
* Challenge   
* Get Measurements (Respond If Ready) for attestation  
* Get CSR  
* Set Certificate

The [OCP Attestation of System Components document](https://www.opencompute.org/documents/attestation-v1-0-20201104-pdf) provides further details on how this should be implemented.

### FW003: Rollback protection

A mechanism must be implemented that ensures that an older version of a firmware cannot be written over a newer version and successfully loaded and executed by the device. Otherwise a malicious actor could execute a [downgrade attack](https://en.wikipedia.org/wiki/Downgrade_attack), in which the actor flashes an old firmware version with a known vulnerability and thereby exploits a vulnerability that had already been fixed.

### FW004: Firmware write protection after boot

All firmware must only be updatable prior to the completion of the boot process, but must not be writable afterwards. This ensures that an attacker cannot establish a permanent foothold by embedding malicious code in firmware.

### FW005: Firmware online recovery

For each piece of firmware there must be a method for it to be recovered online (i.e. without physical access) when it is corrupted. Firmware that cannot be recovered or can only be recovered offline opens up the risk of attackers bricking entire fleets at scale, with no fast way to recover.

Since flash memory degrades over time, devices should provide a recovery path if the mutable storage is completely corrupted. If that is not feasible it is acceptable to instead guarantee that the flash memory data retention is at least 6 months without power.

### FW006: Intel ME

[Intel ME (Management Engine)](https://en.wikipedia.org/wiki/Intel_Management_Engine) is a system integrated into modern Intel systems, which has far-reaching privileges. It is usually not possible to completely disable it, as it is involved in the boot process. But it must be restricted as much as possible to reduce its attack surface, specifically it must run in recovery mode or somehow be restricted even further.

## OS/Firmware

These requirements apply to Operating Systems, as well as firmware.

### OS001: Unnecessary functionality

Operating systems and firmware must remove or persistently disable all APIs, background/system services, kernel modules and other interfaces that are not needed for product functions.

This includes removing unnecessary [SMM (System Management Mode)](https://en.wikipedia.org/wiki/System_Management_Mode) functions.

### OS002: Factory default passwords

There may not be any factory default passwords that are the same across multiple devices. If such passwords are necessary, they must be generated in a cryptographically safe manner for each individual device.

### OS003: Configuration menus

It must be possible to disable all configuration menus, like boot and recovery menus, for the production use of the platform. This is to prevent attackers with physical access from making changes.

## Cryptography

### CRY001: No proprietary algorithms or unvalidated implementations

Proprietary cryptographic algorithms, or algorithms that have not been approved by a national or international standards body, are not considered to provide any security or confidentiality protections to the devices' owner or user. Furthermore, any proprietary implementation of a cryptographic algorithm must be validated by an [OCP S.A.F.E.](https://github.com/opencomputeproject/OCP-Security-SAFE) review provider. The provenance (whether third party IP, open source, or in-house development) of any cryptographic software, firmware, or hardware in the product must be transparent.

### CRY002: FIPS 140-3 validation

[FIPS 140-3](https://en.wikipedia.org/wiki/FIPS_140-3) validation is a complex topic, and it is out of scope of these requirements to provide an answer on whether it will be required for a particular product. An expert needs to assess this case by case.

### CRY003: Entropy

Entropy sources must comply with [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final) to ensure they produce sufficiently random numbers.

### CRY004: CNSA 2.0

Wherever asymmetric cryptography is required, the cryptographic algorithms and protocols built on them must meet [CNSA 2.0 requirements](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) to ensure post-quantum security.

## CPU

### CPU001: Speculative Execution Vulnerabilities

All known [speculative execution vulnerabilities](https://en.wikipedia.org/wiki/Transient_execution_CPU_vulnerability) must be mitigated. Everything described in [BP001](#bp001-design-and-source-code-review) also applies, this requirement just intends to specifically highlight this for speculative execution vulnerabilities.

### CPU002: Microcode updates without third-parties

It must be possible for the customer to update CPU [microcode](https://en.wikipedia.org/wiki/Microcode) in collaboration with only the CPU vendor, but without the involvement of any third-party, such as the integrator or mainboard vendor. This is because additional parties add latency and might even go out of business, which would leave customers with no way to patch security vulnerabilities.

### CPU003: Non-volatile memory

If a CPU has non-volatile memory, which is exposed via CPU pins, e.g. Intel Xeon's PIROM, then those CPU pins must remain disconnected. If it is not feasible to leave it disconnected, the writable part of the data must be cleared on every boot.

## System memory

These requirements apply to system memory like DDR.

### MEM001: SPD memory

Modern memory [DIMMs](https://de.wikipedia.org/wiki/Dual_Inline_Memory_Module) contain an [SPD](https://en.wikipedia.org/wiki/Serial_presence_detect)\-chip, which contains information the platform needs to use the DIMM, such as timings used for communication. The chip's entire user-writable memory must either be cleared on boot or write-protected. If a malicious actor were to override this information, they could make the DIMM unusable and thereby prevent the platform from booting.

Depending on the [DDR](https://de.wikipedia.org/wiki/DDR-SDRAM) version, the memory is split into a different number of blocks that are used for different purposes. DDR5 has 16 blocks, which can all be write-protected.

Relying on vendors to deliver locked DIMMs has been unreliable in the past, so it is preferable to implement enabling of write-protection into a platform's boot process, rather than trusting that DIMMs are already locked.

### MEM002: Encryption

System memory must be encrypted to protect data from being exfiltrated by a physical attacker. For Intel CPUs this is called [Total Memory Encryption (TME)](https://www.intel.com/content/www/us/en/developer/articles/news/runtime-encryption-of-memory-with-intel-tme-mk.html), for AMD CPUs it is called [Transparent Secure Memory Encryption (TSME)](https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/memory-encryption-white-paper.pdf).

## PCIe

### PCIE001: IOMMU

PCIe devices can directly access the system memory of a platform. If a device is compromised this could lead to a compromise of the entire platform. To prevent this, all devices must be connected via an [IOMMU](https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit) and be set to enabled mode (as opposed to passthrough mode). This accomplishes that devices can only access the memory that they should be able to access.

### PCIE002: Encryption and integrity protection

PCIe links must be encrypted and integrity protected, if the platform is deployed to a third-party data center or wants to support confidential compute. This guards against an interposer gaining access to confidential data by intercepting the connection. The technologies used to accomplish this are [IDE (Integrity and Data Encryption) and TDISP (Trusted Execution Environment Device Interface Security Protocol)](https://pcisig.com/blog/ide-and-tdisp-overview-pcie%C2%AE-technology-security-features).

### PCIE003: Sanitization on FLR

PCIe devices must sanitize themselves on FLRs (Function Level Resets). Sanitization means all data, apart from persistent configuration, must be erased. This ensures that the platform can be sanitized between workloads.

## RoT

### ROT001: Fault injection and side-channel analysis

RoTs must implement protections against [side channel analysis](https://en.wikipedia.org/wiki/Side-channel_attack), as well as [fault injection](https://en.wikipedia.org/wiki/Fault_injection). RoTs are the most security-critical component of a platform, they contain secret data on which the security of the remaining platform is built. Side channel analysis and fault injection could be used to extract this data or otherwise bypass the RoTs security guarantees.

## Platform

These requirements apply to entire platforms as a whole, rather than specific components. A whole server or network switch are examples of platforms.

### PLAT001: Dedicated RoT

Platforms must have dedicated [RoTs](https://trustedcomputinggroup.org/about/what-is-a-root-of-trust-rot/) acting as ultimate trust anchor for secure boot, measured boot and firmware updates. RoTs are especially hardened for security, so using such a device as ultimate trust anchor is more secure than adding this functionality to a more complex component, such a BMC.

It is preferable for this RoT to be [Caliptra](https://github.com/chipsalliance/Caliptra).

### PLAT002: Physical access

It must be reasonably difficult (require special equipment and a considerable amount of time) to exploit the platform (exfiltrate confidential data, compel the platform to perform privileged actions or execute arbitrary code) from the parts of the platform that are physically accessible during its normal operation. For rack servers that is the front panel. Otherwise it would be too simple for an attacker inside the datacenter to cause considerable damage.

## Storage drive

### STRG001: TCG Opal

Storage drives must be [TCG Opal](https://en.wikipedia.org/wiki/Opal_Storage_Specification) compliant in order to provide standardized encryption-at-rest and sanitization functionality.

### STRG002: Sanitization

Storage drives must sanitize in accordance with [NIST SP 800-88](https://csrc.nist.gov/pubs/sp/800/88/r2/final) and the [OCP S.A.F.E. storage sanitization requirements](https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Documentation/storage_sanitization.md).

## Networking

### NET001: Confidentiality and integrity protection

Networking devices, such as [NICs](https://en.wikipedia.org/wiki/Network_interface_controller), switches and routers need to provide functionality to enable networks to protect the confidentiality and integrity of network traffic. This is usually [IPsec](https://en.wikipedia.org/wiki/IPsec) or [PSP](https://github.com/google/psp).

This also applies to [RDMA](https://en.wikipedia.org/wiki/Remote_direct_memory_access) (Nvidia: [GPUDirect](https://developer.nvidia.com/gpudirect)) traffic, especially [RoCE](https://en.wikipedia.org/wiki/RDMA_over_Converged_Ethernet) (RDMA over Converged Ethernet).

## Appendix 1: Suggested build options

### Linux ELF binaries  

GNU Compiler Collection (GCC)

* Stack Protection (-fstack-protector-strong)  
* CET Control Flow Protection (-fcf-protection=full)  
* Fortify Source (-D\_FORTIFY\_SOURCE=2) \- requires \-O2 or higher  
* Non-Executable Stack (-z noexecstack)  
* Address Space Layout Randomization (-fpie \-Wl,-pie for executables, \-fpic \-shared for shared libraries)  
* GOT Protection \- BIND\_NOW (-Wl,-z,relro \-Wl,-z,now) for most distributions. For RHEL 6, also use \-Wl,-z,defs to catch underlinking.  
* Format String Warnings (-Wformat \-Wformat-security \-Werror=format-security)  
* GCC 8 or later: Stack Clash Protection (-fstack-clash-protection)

LLVM / Clang

* SafeStack (-fsanitize=safe-stack)  
* Stack Protection (-fstack-protector-strong or \-fstack-protector-all)  
* Control Flow Integrity (-flto \-fsanitize=cfi)  
* CET Control Flow Protection (-fcf-protection=full)  
* Address Space Layout Randomization (-fPIE \-pie for executables, \-fPIC for shared libraries)  
* GOT Protection (-Wl,-z,relro \-Wl,-z,now)
* Format String Warnings (-Wformat \-Wformat-security \-Werror=format-security)  
* Speculative Load Hardening (-mspeculative-load-hardening)

### Windows PE binaries

* Buffer Security Check (/GS) \- Also known as "stack cookies".
* Control Stack Checking Calls (/Gs)  
* Control Flow Guard (/guard:cf)  
* CET Shadow Stack Compatible (/CETCOMPAT)  
* Address Space Layout Randomization (ASLR) (/DYNAMICBASE)  
* High-Entropy Virtual Addresses (/HIGHENTROPYVA) (64-bit only)  
* Handle Large Addresses (/LARGEADDRESSAWARE) (64-bit only)  
* Additional Security Checks (/sdl)  
* Spectre Mitigations using the /Qspectre compiler flag  
* All RPC and DCOM code must be compiled using the /ROBUST option when using the MIDL compiler. The minimum target level is NT61 (/TARGET NT61).
* Avoid suppressing specific warnings with /wdnnnn or using pragmas in code.
* Enable all warnings using the /Wall flag, and treat warnings as errors with /WX

In addition for 32-bit Windows binaries:

* Data Execution Prevention (DEP) (NXCOMPAT)  
* Safe Exception Handlers (/SAFESEH)

In addition, for Windows kernel-mode driver components:

* Enforce deprecation of insecure CRT functions for drivers (/D\_CRT\_SECURE\_FORCE\_DEPRECATE)
