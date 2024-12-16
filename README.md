# Community Edition
## Overview
Over the last several years ransomware has been becoming an increasingly complex problem, elevating to epidemic levels around the world. Today there are several dynamic actors involved in a successful attack and the problem is actually turning into a business model in itself called ransomware as a service (RAAS). With this in mind, we recognize the value of community and bringing all stakeholders to the table to help find a solution to the problem once and for all. After spending several years investigating the problem of ransomware both from an offensive and defensive perspective, our research team wanted to provide an open source release of several protection capabilities and testing artifacts that we have found helpful along the way.

Small businesses and non profits make up a significant portion of successful ransom attacks and ironically enough don't have the resources that enterprises have, those of which most of the cybersecurity industry targets their efforts to help. However, we feel like these smaller stakeholders, those of which who's livelihoods would be upended completely upon a successful attack, need to be empowered to defend themselves using economically friendly resources. As such, we are hoping to start a trend in the industry by releasing a ransomware protection capability to the broader research and stakeholder community. With more education and innovations within the space, our hope is that we all can collectively rid the ransomware problem for good.

## Technology Components
The foundation of our research team has been the power of open source and community engagement to create the most optimal solutions. Consistent with this theme, we have built the technology offered through a community edition by incorporating what we believe to be the best contributions from the open source community. Furthermore, we are planning to open source the specific protection code from our community edition, allowing for modules and other protections to be built upon our core framework.

The following components are included in our current release. Other protections are planned to be incorporated in the future based on feedback to further enhance the protection level of the community. These features are listed below:

**Current Features**
1) **Honeypot Encryption Mitigation** - Attackers often start their encryption activity from predefined locations, expanding throughout the system from the base starting points. A significant portion of attacks affecting the SMB and non profit communities are "spray and pray" variants, trying to use generic techniques for maximum volume. We use this aspect against the attacker by inserting honeypot folders scattered in the normal starting locations, mitigating these variants before they have the chance to cause damage.
2) **Encryption material interception** - Encryption behavior in some cases leverages existing cryptography libraries within the Windows operating system. By hooking and intercepting calls to these native libraries, we can record metadata and material related to the encryption events.

**Future Planned Features**
1) **Ransomware specific AI scanning** - Default antivirus solutions like Windows Defender are often the first line of malware defense. However, in some cases more advanced AI scanning is necessary to detect ransomware malware. We plan to build upon existing open source AI models to provide a ransomware scanning module.
2) **Rule based behavioral monitoring** - Ransomware behavior sometimes shows unique signs compared to generic malware. We plan to build upon existing YARA behavior detection frameworks to offer a ransomware specific behavior monitoring module.

## Repository Layout
1) **Decryptors** - We collected a starting collection from around the community into a single location. Furthermore, we will release custom decryptors as we further refine our encryption material interception module.
2) **Examples** - We have included example ransomware and encryption programs that can be used to test protections. Further, these are good resources to begin to learn about the fundamentals of how ransomware programs operate. Make sure you test these programs within a VM environment and not on your normal system.
3) **Modules** - This is where we will release our open source versions of our module code.
4) **Videos** - Videos of demos, examples, and other related content.

## Support
This project is a hybrid open source and community edition model. We will try our best to update the repository as things progress but unfortunately support will be limited. It is important to note that real ransomware software is included in this repository within an encrypted password protected archive. Users should take all precautions when testing and run at their own risk.
## Acknowledgements
We would like to thank the following projects and initiatives for paving the way for this effort.
1) Paybreak - Pioneering encryption key material interception
```
Kolodenker, Eugene, William Koch, Gianluca Stringhini, and Manuel Egele.
"PayBreak: Defense against cryptographic ransomware." In Proceedings of
the 2017 ACM Asia Conference on Computer and Communications Security (ASIACCS).
ACM (Association for Computing Machinery), 2017.
```
2) Doken - Virtual FUSE based filesystem for Windows
```
https://dokan-dev.github.io
```
3) NoMoreRansom Project - A vast collection of decryptors
```
https://www.nomoreransom.org
```
