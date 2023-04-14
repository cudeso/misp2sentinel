# MISP 2 Sentinel integration

Please see the MISP project blog post [https://www.misp-project.org/2023/04/03/MISP-Sentinel.html/](https://www.misp-project.org/2023/04/03/MISP-Sentinel.html/) for more details.

The MISP to Azure / Sentinel integration allows you to upload indicators from MISP to Microsoft Sentinel. It relies on **PyMISP** to get indicators from MISP and an **Azure App** and **Threat Intelligence Data Connector** in Azure.

This repository is started from the [Microsoft Graph Security](https://github.com/microsoftgraph/security-api-solutions) API GitHub repository. Because the Microsoft repository seems no longer maintained a separate repository was started, stripped of the non-MISP items and with updated Python code. Compared to the original Microsoft repository, this now includes

Handle attributes in objects
Handle URLs that do not have http/https included
Handle network direction (network_ignore_direction)
Adjust logging - verbosity
Ignore local tags (misp_ignore_localtags)
Properly deal with tags on attribute level
Add defaultConfidenceLevel
Add sentinel-threattype
Convert KillChain labels for Azure

