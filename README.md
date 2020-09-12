# CCX Digger / A CyberCX Velociraptor Project

<div align="center">
    <img src="https://camo.githubusercontent.com/72b54ccf6ce09bbf05d92ff18bbd0fae41f51561/68747470733a2f2f6d656469612d657870312e6c6963646e2e636f6d2f646d732f696d6167652f433536304241514734687335786e6a43326f672f636f6d70616e792d6c6f676f5f3230305f3230302f303f653d3231353930323434303026763d6265746126743d6c794954454e66557876773235565967596b363676384d53346b364c784e6561414c79454462314647704d"></img>
</div>

The CCX Digger project is designed to help Australian organisations determine if they have been impacted by certain high profile [cyber security incidents](https://www.pm.gov.au/media/statement-malicious-cyber-activity-against-australian-networks). CCX Digger provides sophisticated threat hunting functionality packaged in a simple to use tool, allowing users to detect certain attacker activities; **all for free**.

<div align="center">
<table>
    <thead>
        <tr>
          <th align="center"><a href="https://github.com/CCXLabs/CCXDigger/wiki">Wiki</a></th>
            <th align="center"><a href="https://github.com/CCXLabs/CCXDigger/wiki/Installation">Install</a></th>
          <th align="center"><a href="https://github.com/CCXLabs/CCXDigger/wiki/FAQ">FAQ</a></th>
            <th align="center"><a href="https://github.com/CCXLabs/CCXDigger/wiki/Acknowledgements">Acknowledgements</a></th>
          <th align="center"><a href="https://github.com/CCXLabs/CCXDigger/wiki/Contribution-Guide">Contribute</a></th>
          <th align="center"><a href="https://github.com/CCXLabs/CCXDigger/wiki/Need-Help%3F">Need Help?</a></th>
        </tr>
    </thead>
</table>
</div>

# Quick Start

CCX Digger can perform scans on both individual systems and across an entire network. A network connection is **not** required to use this tool. An HTML report will be generated once the scan completes.

## Scanning an individual system

1.	Go to the [Downloads](https://github.com/CCXLabs/CCXDigger/wiki/Downloads) page to obtain the latest CCX Digger executable and checksum. Verify the download, then execute through the Command Prompt with Administrator privileges. CCX Digger can be run from any drive, including a removable drive or network share. It requires no installation and has no external dependencies. It makes no configuration changes to the system.

2.	After completing the scan, an HTML report is created within the same folder. This contains any findings from the scan, plus details on what each finding means. The HTML report links back to this website for additional information, however no scan data is uploaded and your visits are not recorded by CyberCX. Any relevant items found are copied into a ZIP file, also in the same folder.



3.	Further investigation may be necessary to confirm any findings are indeed malicious. The HTML report will recommend any next steps required.

## Scanning an entire network

1.	[Install Velociraptor](https://www.velocidex.com/docs/getting-started/) across the network.  
2.	Follow the instructions here to obtain the latest CCX Digger artefact pack.
3.	Follow the instructions above to execute a Velociraptor hunt across your network.
4.	Review the hunt results.

Detailed installation guides can be found at the [Installation](https://github.com/CCXLabs/CCXDigger/wiki/Installation) page.

# Introducing CCX Digger

**In 2020, specifically within the May to June period, Australia experienced a significant increase in cyber incidents targeting all levels of government and across a wide range of industry sectors. No aspect of Australian society was [untouched](https://www.pm.gov.au/media/statement-malicious-cyber-activity-against-australian-networks). The threat actor combined basic attack techniques with more sophisticated elements that are more difficult to detect. The threat actor is known to leave implants on compromised networks to facilitate re-entry.**

CyberCX’s Digital Forensic & Incident Response (DFIR) team has worked with several clients to detect and respond to these breaches, in collaboration with government agencies and industry partners. Through this work, our DFIR team has produced specific threat intelligence which can quickly and effectively detect the threat actors on systems.
Through CyberCX’s ongoing collaboration with the [Velociraptor Project](www.velocidex.com) (another proud Australian technology innovation) we have developed CCX Digger.

The objectives for CCX Digger is to:
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
* No collection or transmission of data outside your network
* No ‘calling home’ and no external network connections required to run scans.

**If you believe your network may be compromised, please contact the CyberCX Digital Forensic & Incident Response team at digger@cybercx.com.au**

## About CyberCX
CyberCX is Australia’s leading force of cyber security professionals, with over 500 specialists across Australia, New Zealand, the UK and the USA, providing services across the following practice areas:

* Strategy & Consulting
* Security Testing & Assurance
* Governance, Risk & Compliance
* Security Integration & Engineering
* Identity & Access Management
* Managed Security Services
* Digital Forensics & Incident Response
* Education & Training

The CyberCX Digital Forensics & Incident Response teams (DFIR) help our clients to investigate and respond to a broad range of digital forensic investigations and cyber incidents every day. With the largest number of DFIR specialists across Australia, we provide an unmatched depth of technical expertise, industry experience and local resources when and where our clients need us.

For more details, refer to www.cybercx.com.au 
