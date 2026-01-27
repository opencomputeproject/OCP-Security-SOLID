# OCP S.O.L.I.D.

| Version | Date | Authors | Contributors |
| :---- | :---- | :---- | :---- |
| 1.0 | 2026-01-27 | Nick Hummel | Eric Eilertson, B Keen |

S.O.L.I.D. stands for Securing Of Latest Infrastructure Devices, do not read too much into that, it's a backronym. OCP S.O.L.I.D. defines baseline security requirements for products used in datacenters. It concerns products that touch production data (e.g. servers) or could cause unavailability of products that touch production data (e.g. UPSes). This also includes components of such products that do not directly touch production data themselves (e.g. server power supplies). Excluded are products that do not contain any logic themselves (e.g. network cables, server cases).

The purpose of publishing these requirements is to enable vendors to work towards them well in advance. You can incorporate them into the development process for all products, even before having any contractual agreement with a customer or even knowing which one in particular will be interested.

To get OCP S.O.L.I.D. accreditation for your product, you must prepare a document that explains per requirement applicable to your type of product how it is met. Then the product must undergo a review under [OCP S.A.F.E.](https://github.com/opencomputeproject/OCP-Security-SAFE/blob/main/Documentation/framework.md) to verify this.

On the [requirements page](./requirements.md), you can see all requirements.

On the [product types page](./producttypes.md), you can see which requirements apply to a particular type of product.
