# Product Types

| Version | Date | Authors | Contributors |
| :---- | :---- | :---- | :---- |
| 1.0 | 2026-01-27 | Nick Hummel | Eric Eilertson, B Keen |

Not all requirements are applicable to all types of products. This page shows which requirements a specific type of product must comply with.

## All products

This list applies to all products regardless of type. To, for example, get a full list of requirements for a server, use this list plus the server-specific list.

* All [general requirements](./requirements.md#general)  
* All [business process requirements](./requirements.md#business-processes)  
* All [hardware requirements](./requirements.md#hardware)  
* All [software requirements](./requirements.md#software)  
* All [firmware requirements](./requirements.md#firmware)  
* All [OS/firmware requirements](./requirements.md#osfirmware)  
* All [cryptography requirements](./requirements.md#cryptography)  
* All [CPU requirements](./requirements.md#cpu)  
* All [PCIe requirements](./requirements.md#pcie) (for devices with PCIe interfaces)

## Server

Entire servers consisting of different components. A server hosts an operating system and runs user applications.

* All [system memory requirements](./requirements.md#system-memory)  
* All [RoT requirements](./requirements.md#rot)  
* All [platform requirements](./requirements.md#platform)

## Accelerator

A separate PCIe card, or alternately a relatively fixed-function assembly of hardware (such as GPUs connected through a back end network) attached to one or more servers.

* All [system memory requirements](./requirements.md#system-memory)  
* All [RoT requirements](./requirements.md#rot)  
* If not enclosed in a server: All [platform requirements](./requirements.md#platform)

## Network appliance

Routers, switches, etc., but not NICs.

* All [system memory requirements](./requirements.md#system-memory)  
* All [RoT requirements](./requirements.md#rot)  
* All [platform requirements](./requirements.md#platform)  
* All [networking requirements](./requirements.md#networking)

## Disk

Persistent storage drives like SSDs or magnetic drives

* All [storage drive requirements](./requirements.md#storage-drive)

## NIC

Network cards

* All [networking requirements](./requirements.md#networking)
