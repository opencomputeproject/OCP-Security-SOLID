# OCP S.O.L.I.D.

| Version | Date | Authors | Contributors |
| :---- | :---- | :---- | :---- |
| 1.0 | 2026-01-27 | Nick Hummel | Eric Eilertson, B Keen |

# Glossary

* CSP - Cloud Service Provider
* DV - Device Vendor

# OCP S.O.L.I.D.

S.O.L.I.D. stands for Securing Of Latest Infrastructure Devices, do not read too much into that, it's a backronym. OCP S.O.L.I.D. defines baseline security requirements for products used in datacenters. It concerns products that touch production data (e.g. servers) or could cause unavailability of products that touch production data (e.g. UPSes). This also includes components of such products that do not directly touch production data themselves (e.g. server power supplies, cooling systems, etc). Excluded are products that do not contain any logic themselves (e.g. network cables, server cases).

The purpose of publishing these requirements is to enable vendors to work towards them well in advance. The device vendor can incorporate them into the development process for all products, even before having any contractual agreement with a customer or even knowing which one in particular will be interested.

To get OCP S.O.L.I.D. accreditation for a product, the DV must prepare a document that explains how each [applicable](./producttypes.md) requirement is met. The product must then undergo a review under [OCP S.A.F.E.](https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Documentation/framework.md) to verify these requirements.

The [requirements page](./requirements.md) lists all current requirements. Forward looking requirements that are not required *yet* are listed for discussion in [Future Requirements](./futurerequirements.md).

The [product types page](./producttypes.md), lists which requirements apply to a particular type of product.
