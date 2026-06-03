<!-- Adding Writeup Document for Capstone Project to explain decision choices and provide insight to first 
principles thinking applied to this project. -->

# WRITEUP.md for ACME Health Project 2026-1-14-01

## NOW (Current Sprint)

### Design Decisions

#### Voice

We have chosen to speak in the first person plural throughout this project writeup to emphasize that "We" are a team. Understanding that the task of solving our concerns for shipping an audit-defensible product was assigned to, and worked on solely by myself, Benjamin Hobbs- GRC Engineer, I know that I could not have completed this task without the men and women of the ACME Health Team and my professional contemporaries in the field of GRC Engineering. "We" bring you this solution for your consideration.

#### Choosing a Primary Framework

- We chose to use HIPAA as our primary framework because it most directly mapped to ACME Health proposed Patient Intake API. The industry that ACME is in (Healthcare) is primarily governed by HIPAA (Health Insurance Portability and Accountability Act).

- As HIPAA is a law enacted by Congress, it is most prudent for ACME to comply with this first. This sprint we will address the [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html), a regulation mandating technical, physical, and administrative safeguards to protect electronic data. [The HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html) regulation will be addressed at a later sprint as indicated in the "LATER" section of this project write up.

- Considering the business goals of ACME Health to deliver this solution to both enterprises and federal government interests as well we will remain observant of SOC 2 Type II and CMMC Level 2 controls that map to our chosen HIPAA controls to make sure that we "build once, and map everywhere."

### Control Coverage

#### HIPAA 164.308(a)(7)

#### HIPAA 164.312(a)(1)

#### HIPAA 164.312(a)(2)(iv)

GAP-01 & GAP-03

#### HIPAA 164.312(b) Switching to a REST API is the cleaner, more secure, and defensible architectural choice, especially when security and compliance are paramount

We are choosing to present this change as a trade-off between architectural simplicity and security compliance.

#### HIPAA 164.312(e)(1)

GAP-03 & GAP-05

### Trade-Offs

As there is not currently an official OSCAL (Open Security Controls Assessment Language) catlog for HIPAA, we will be citing the NIST SP 800-66 Rev. 2 titled (Implementing the HIPAA Security Rule) as the catalog.

## NEXT (Next couple of sprints)

## LATER

- Complete HIPAA Privacy Rule adoption using IAM (AWS Identity Center) Resources to layer on privacy protection using NIST SP 800-188 as the catalog.
