
# Server Availability Manager - SSL check

The purpose of this module is to add a probe to the Server Availability Manager to check if the SSL certificates used for a website are valid and are not going to expire in the next 7 days.
## Installation

- In Jahia, go to "Administration --> Server settings --> System components --> Modules"
- Upload the JAR **sam-ssl-check-X.X.X.jar**
- Check that the module is started

## How to use
The probe will be automatically added to the Server Availability Manager output (read [this page](https://academy.jahia.com/documentation/system-administrator/dev-ops/monitoring-your-jahia-platform/monitoring-your-servers) for more information).
