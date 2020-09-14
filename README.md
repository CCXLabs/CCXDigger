# CCX Digger / A CyberCX Velociraptor Project

<div align="center">
    <img src="https://camo.githubusercontent.com/72b54ccf6ce09bbf05d92ff18bbd0fae41f51561/68747470733a2f2f6d656469612d657870312e6c6963646e2e636f6d2f646d732f696d6167652f433536304241514734687335786e6a43326f672f636f6d70616e792d6c6f676f5f3230305f3230302f303f653d3231353930323434303026763d6265746126743d6c794954454e66557876773235565967596b363676384d53346b364c784e6561414c79454462314647704d"></img>
</div>

The CCX Digger project is designed to help Australian organisations determine if they have been impacted by certain high profile [cyber security incidents](https://www.pm.gov.au/media/statement-malicious-cyber-activity-against-australian-networks). CCX Digger provides threat hunting functionality packaged in a simple-to-use tool, allowing users to detect certain attacker activities; **all for free**.

**Please refer to the [wiki](https://github.com/CCXLabs/CCXDigger/wiki) for more information about the CCX Digger project, and the tool itself.**

# Quick Start

CCX Digger can perform scans on both individual systems and across an entire network. A network connection is not required to use this tool. An HTML report will be generated once the scan completes.

## Scanning an individual system

1. Go to the [Downloads](https://github.com/CCXLabs/CCXDigger/wiki/Downloads) page to obtain the latest CCX Digger executable and checksum. Verify the download against the checksum. 

2. Open a **Command Prompt with Administrator privileges** and run the CCX Digger executable. It can be run from any drive, including a removable drive or network share. It requires no installation and has no external dependencies. It makes no configuration changes to the system and should have negligible impact on the system.

3. After completing the scan, an HTML report is created within the same folder. This contains any findings from the scan, plus details on what each finding means. The HTML report links back to this website for additional information, however no scan data is uploaded and we do not record your visits to the website. Any relevant items found are copied into a ZIP file in the same folder, to assist with further analysis.

3. Further investigation may be necessary to confirm if any findings are indeed malicious. The HTML report will recommend any next steps required.

## Scanning an entire network

1. [Install Velociraptor](https://www.velocidex.com/docs/getting-started/) across the network.  
2. Follow the instructions here to obtain the latest CCX Digger artefact pack.
3. Follow the instructions above to execute a Velociraptor hunt across your network.
4. Review the hunt results.

Detailed installation guides can be found at the [Installation](https://github.com/CCXLabs/CCXDigger/wiki/Installation) page.

# Introducing CCX Digger

**During 2020, especially within the May to June period, Australia experienced a significant increase in cyber incidents targeting all levels of government and across a [wide range of industry sectors](https://www.pm.gov.au/media/statement-malicious-cyber-activity-against-australian-networks). The threat actors responsible combined basic attack techniques with more sophisticated elements that are more difficult to detect. The threat actor is known to leave implants on compromised networks to facilitate re-entry. CCX Digger was created to help system owners determine whether their networks may have been compromised by these methods.**

CyberCX’s Digital Forensic & Incident Response (DFIR) team has worked with several clients to detect and respond to these breaches, in collaboration with government agencies and industry partners. Through this work, our DFIR team has produced specific threat intelligence which can quickly and effectively detect evidence of the threat actors on systems.

Through CyberCX’s ongoing collaboration with the [Velociraptor Project](www.velocidex.com) (another proud Australian technology innovation) we have developed CCX Digger.

The objectives for CCX Digger are to:
* Help protect Australia from a current advanced, sophisticated and persistent threat
* Empower Australian organisations to detect and respond to intrusions on their networks
* Provide a powerful but simple toolset which organisations can easily use
* Share threat intelligence from the front lines in an actionable way
* Keep updating CCX Digger as our analysis of this threat continues
* Provide this advanced capability for **free**.

The key features of CCX Digger are:
* Full transparency through [free and open source software](https://www.velocidex.com/about/license/)
* Single executable, which requires no installation and has no external dependencies 
* No registration, licenses or dongles required
* No collection or transmission of scan data outside your network
* No ‘calling home’ and no external network connections required to perform scans.

**If you believe your network may be compromised, please contact the CyberCX Digital Forensic & Incident Response team at digger@cybercx.com.au**

## About CyberCX
[CyberCX](https://www.cybercx.com.au) is Australia’s leading force of cyber security professionals, with over 500 specialists across Australia, New Zealand, the UK and the USA, providing services across the following practice areas:

* Strategy & Consulting
* Security Testing & Assurance
* Governance, Risk & Compliance
* Security Integration & Engineering
* Identity & Access Management
* Managed Security Services
* Digital Forensics & Incident Response
* Education & Training

The CyberCX Digital Forensics & Incident Response team (DFIR) helps our clients to investigate and respond to a broad range of digital forensic investigations and cyber incidents every day. With the largest number of DFIR specialists across the region, we provide an unmatched depth of technical expertise, industry experience and local resources when and where our clients need us.

## About Velociraptor 

[Velociraptor](https://www.velocidex.com) is an endpoint visibility platform developed in Australia, which provides leading capabilities for distributed forensic analysis, endpoint monitoring and the surgical collection of evidence from across networks.  

The foundation of Velociraptor is a unique query language named VQL which allows writing specific detection queries, known in Velociraptor as Artefacts, which leverage the underlying Velociraptor functionality and can be easily distributed and shared.

CyberCX has been a proud collaborator of the Velociraptor project since its early days. CCX Digger is yet another example of the benefits of this partnership to the cyber security industry and the communities we protect.

## Other Conditions

Please note the following conditions when using CCX Digger:
* CCX Digger is provided "as is", without any support nor warranties, either expressed or implied.
* While CyberCX has conducted our own testing of CCX Digger, we provides no guarantees that CCX Digger will work as intended on every computer system.
* Use of CCX Digger is entirely at the user's own risk. Execution of CCX Digger does not make any direct changes to a system other than producing a report and collecting source files to support further analysis, and should have negligible performance impacts. CyberCX takes no responsibilies for any adverse effect that its execution may have. If you have concerns, you should first trial CCX Digger on test systems before using more widely.
* While you may contact CyberCX for more information or if you believe that your network is compromised, CyberCX provides no guarantees of what response or support CyberCX will provide.
* CCX Digger is not intended to find all possible traces of threat actor activities. All results should be verified through further investigation, as described in the [wiki](https://github.com/CCXLabs/CCXDigger/wiki).
* While CCX Digger may detect malware and other attacker activities, it is **not** an anti-virus solution and is **not** configured to remove malicious files nor block malicious activities that it finds.
* While CyberCX has collaborated with various third parties to produce CCX Digger, any references to third parties in CCX Digger, inculding but not limited to within the website, detection artefacts, reports and documentation, are not endorsements of CCX Digger by these third parties.
* CyberCX has taken reasonable steps to respect and maintain the ownership of intellectual property and threat intelligence used in the development of CCX Digger. This includes abiding by the terms of relevant software licenses and obtaining consent for the use of threat intelligence in this way. Components from the Velociraptor project are made available under the terms of its [GNU Affero General Public License](https://www.velocidex.com/about/license/).
