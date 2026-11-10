# Authentication

Public audits never claim complete plugin inventory or exact PHP runtime. For authenticated inventory, install the companion plugin in `wordpress-connector/` through a trusted administrator workflow. It provides only `GET /wp-json/wp-maintenance/v1/inventory`, protected by REST authentication and `current_user_can('view_wp_maintenance_inventory')`. On activation the plugin grants this dedicated read capability to administrators so it can also be assigned to an explicitly configured least-privilege role.

Create a dedicated WordPress account with the required capability and a unique Application Password. Application Password authentication alone does not grant access: WordPress must authenticate the user and the endpoint checks capability. Configure the credential in a secret manager or process environment variable and refer to its name from YAML. TLS remains required by default.

The connector reports installed plugin headers/status, available update transient versions, WordPress core version and PHP version. It does not trigger updates, execute code, or expose filesystem paths or user records.
