
[![Prisma Icon](https://avatars.githubusercontent.com/u/4855743?s=48&v=4)](https://www.paloaltonetworks.com/sase/sd-wan)
# Prisma Config 

[![image](https://img.shields.io/pypi/v/prisma_config.svg)](https://pypi.org/project/prisma-config/)
[![image](https://img.shields.io/pypi/pyversions/prisma_config.svg)](https://pypi.org/project/prisma-config/)
[![Downloads](https://pepy.tech/badge/prisma-config)](https://pepy.tech/project/cloudgenix-config)
[![License: MIT](https://img.shields.io/pypi/l/prisma_config.svg?color=brightgreen)](https://pypi.org/project/prisma-config/)
[![GitHub issues open](https://img.shields.io/github/issues/PaloAltoNetworks/prisma_config.svg)](https://github.com/PaloAltoNetworks/prisma_config/issues)

#### Introduction
Configuration exporting and Continuous Integration (CI) capable configuration importing for the Prisma SDWAN Cloud Controller.

#### Synopsis
Enables export and import of configurations and templates from the Prisma SDWAN Cloud Controller. Also, the Import of 
configuration is designed to be run on file change, to maintain configuration state on the Cloud Controller.

#### Features
 - Replace ION at site by extracting configuration, replacing 'serial_number' with new ION (Must be online and at least allocated to the account).
 - Check configurations into a repository (private GIT), and have a CI process system automatically configure site(s)
 - Use configs as a rollback tool after changes.
 - Delete most configurations by simply removing them from the file and/or setting to null.
 - Use configs as a template to deploy 10s-100s-1000s of sites.

#### Requirements
* Active Prisma SDWAN Account
* Python >= 2.7 or >=3.6
* Python modules:
    * Prisma SASE Python SDK >= 6.3.1b1 - <https://github.com/PaloAltoNetworks/prisma-sase-sdk-python>

#### License
MIT

#### Installation:
 - **PIP:** `pip install prisma_config`. After install, `pull_site`/`do_site` scripts should be placed in the Python
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run `pull_site.py` and `do_site.py` scripts.

#### Authentication:
**prisma_config** uses OAuth2 to authenticate and authorize the use of this utility to configure the Prisma SDWAN controller. To authenticate,
1. Create a Service Account from the Settings -> Identity & Access menu
2. Make sure the right privileges are assigned to the service account.
3. Copy the client ID and client secret generated for this service account
4. Create a file **prismasase_settings.py** and copy the client ID, client secret and TSG ID of the tenant you intend to manage using this utility. Use [prismasase_settings.py.example](https://github.com/PaloAltoNetworks/prisma_config/blob/master/prismasase_settings.py.example)  as a reference.
5. When you initiate the **pull_site** or **do_site** command, the utility will look for the **prismasase_settings.py** file in the directory you're calling these scripts from. 

#### Examples of usage:
 1. Configure a Site, Element, and related objects using the UI. Record the Site name (example, MySite)
 2. Extract the configuration using the `pull_site` script: `pull_site -S "MySite" --output MySite.yaml`
    ```bash
    edwards-mbp-pro:prisma_config aaron$ ./pull_site.py -S "MySite" --output MySite.yml 
    edwards-mbp-pro:prisma_config aaron$ 
    ```
 3. View, edit, make changes to the configuration file as needed. 
 4. Use `do_site.py` to apply the configuration, script will get site to that state.
    ```bash
    edwards-mbp-pro:prisma_config aaron$ ./do_site.py ./MySite.yml
    No Change for Site MySite.
     No Change for Waninterface Circuit to Comcast.
     No Change for Waninterface Circuit to AT&T.
     No Change for Waninterface Circuit to Megapath.
     No Change for Lannetwork NATIVE_VLAN.
     Element: Code is at correct version 5.0.1-b9.
      No Change for Element MySite Element.
       No Change for Interface 23.
       No Change for Interface 1.
       No Change for Interface controller 1.
       No Change for Interface 4.
       No Change for AS-PATH Access List test3.
       No Change for IP Community List 20.
       No Change for Routing Prefixlist test-script-list2.
       No Change for Route Map toady.
       No Change for Route Map test8.
       No Change for Route Map toady2.
       No Change for BGP Global Config 15311892501660245.
       No Change for BGP Peer teaerz.
       No Change for Staticroute 15312386843200245.
       No Change for Ntp default.
       No Change for Toolkit 15311890594020131.
    No Change for Site MySite state (active).
    DONE
    ```
 
#### Prisma Config Utility Upgrade Considerations:
When a major version change in the Prisma SDWAN Config Utility is published, new parameters will likely be introduced in the YAML config template.

Please adhere to the following workflow to make sure existing configuration templates or YAML files can be reused with the latest version of the config utility:
* **Step 1**: Upgrade the Prisma Config Utility using the command ```pip install --upgrade prisma_config```

* **Step 2**: For existing Jinja2 templates and/or site specific YAML config files, re-run ```pull_site``` for the site

* **Step 3**: Compare (diff) the old Jinja2 template and/or site specific YAML file with YAML file generated in Step 2.

* **Step 4**: Identify all the new attributes introduced in the latest version that are applicable to your configuration

* **Step 5**: Update the old Jinja2 template and/or YAML config file with the new parameters identified in Step 4.   

**Note**: Make sure the following steps are followed after upgrading the Prisma Config Utility. 
The Prisma Config Utility will default to using the SDK version. An out-of-date YAML file could cause issues with resource creation and/or resource updates.

#### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.
 - Requires 6.3.1b1 prisma_sase SDK. Future minor SDK revisions (5.6.x, etc.) will likely require a matching `prisma_config` update.
 - While this script can EXTRACT a single file with ALL sites, running do_sites.py on that file is NOT RECOMMENDED.
   - Best practice is to do one site per config file.
     - These can be automatically pulled via `pull_site.py` with `--multi-output <directory>` switch, will create a config per site.
   - Site safety factor is set to 1 by default (prevents unintentional multi-site configurations)
 - Re-naming Sites is not currently supported (changing site name in config causes a new site to be created)
 - Deletion of sites using `do_site.py` DESTROYS all objects under the Site. This operation is done by running `do_site.py` with the `--destroy` option.
   - Delete WILL happily auto-destroy EVERY SITE in the referenced YAML config file (Even FULLY-CONFIGURED SITES). Use with caution.
   - Site safety factor also applies to `--destroy` operations.
 - If Element is permanently offline or in other broken state, it will fail to be removed from a site. To force-removal, 
 use the `--declaim` option. This will unassign AND declaim (AKA "put back in inventory") the permanently offline or broken device. 
 It will also force revocation of all credentials and certificates for that device.
 - Element Extensions with specific PATH IDs are not currently templatable across multiple sites using this script.
 - For ION 9000, if trying to configure a bypasspair and the port with the same name (12,13,14,15,16), configuration pushes via do_site have to be done in the following two steps:
     - Include only interface configuration of type port and use the do_site utility to push this configuration first.
     - Update the YAML file to remove the interface configuration of type port, include interface configuration of type bypasspair and use the do_site utiltiy to push the bypasspair configuration.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
|  6.3.1  | **b1** | Initial Release. |
|  6.5.1  | **b1** | Support for Prisma SASE SDK 6.5.1. |
|  6.5.1  | **b2** | Fix for CGSDW-31314       |



#### For more info
 * Get help and additional Prisma SDWAN Documentation at <https://docs.paloaltonetworks.com/prisma/prisma-sd-wan>
