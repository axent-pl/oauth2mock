workspace "Name" "Description" {

    model {
        u = person "User"
        c = softwareSystem "Client" "System requestion auhtorization"
        ss_axes = softwareSystem "Axes" "Authorization Suite" "" {
            // !docs ./axes.md
            auth_server = container "Authorization Server" "OAuth2 Authorization Server / SAML Identity Provider" "Go" "" {
                c_srv = component "HTTP Server" "" "" "auth_flow,token_flow,scim_flow"
                c_router = component "HTTP Router" "" "" "auth_flow,token_flow,scim_flow"

                c_authhandler = component "Authorize Handler" "" "" "auth_flow"
                c_tokenhandler = component "Token Handler" "" "" "token_flow"
                c_scimhandler = component "SCIM Handler" "" "" "scim_flow"

                c_tpl_srv = component "Template Service" "" "" "auth_flow"
                c_cli_srv = component "Client Service" "" "" "auth_flow,token_flow"    
                c_auc_srv = component "Auth Code Service" "" "" "auth_flow,token_flow"
                c_cla_srv = component "Claim Service" "" "" "token_flow"
                c_usr_srv = component "User Service" "" "" "auth_flow,scim_flow"
                c_key_srv = component "Key Service" "" "" "token_flow"
            }
            auth_proxy = container "Authorization Proxy" "" "Go" "" {
                ap_srv = component "HTTP Server" "" "" ""
                ap_key_srv = component "Key Service" "" "" ""
            }
        }

        // authorization server

        // authorization server // container level
        u -> auth_server "OAuth2 authorize request" "" "auth_flow" 
        c -> auth_server "OAuth2 token request" "" "token_flow"
        c -> auth_server "SCIM request" "" "scim_flow"

        // authorization server // component level
        u -> c_srv "OAuth2 authorize request" "" "auth_flow"
        c -> c_srv "OAuth2 token request" "" "token_flow"
        c -> c_srv "SCIM request" "" "scim_flow"

        c_srv -> c_router "Uses" "" "all"

        c_router -> c_authhandler "Uses" "" "auth_flow"
        c_router -> c_tokenhandler "Uses" "" "token_flow"
        c_router -> c_scimhandler "Uses" "" "scim_flow"

        c_authhandler -> c_tpl_srv "Uses" "" "auth_flow"
        c_authhandler -> c_cli_srv "Uses" "" "auth_flow"
        c_authhandler -> c_usr_srv "Uses" "" "auth_flow"
        c_authhandler -> c_auc_srv "Uses" "" "auth_flow"

        c_tokenhandler -> c_cli_srv "Uses" "" "token_flow"
        c_tokenhandler -> c_auc_srv "Uses" "" "token_flow"
        c_tokenhandler -> c_cla_srv "Uses" "" "token_flow"
        c_tokenhandler -> c_key_srv "Uses" "" "token_flow"

        c_scimhandler -> c_usr_srv "Uses" "" "scim_flow"

        // authorization proxy // container level
        u -> auth_proxy "request" "HTTP/HTTPS" "proxy_flow"
    }

    views {
        systemContext ss_axes {
            include *
            autolayout lr
        }

        container ss_axes {
            include *
            autolayout lr
        }
        component auth_server "000_all" {
            include *
            autoLayout lr
        }
        component auth_server "001_authorize_flow" {
            include u
            include element.tag==auth_flow
            exclude *->*
            include relationship.tag==auth_flow
            include relationship.tag==all
            autoLayout lr
        }
        component auth_server "002_token_flow" {
            include c
            include element.tag==token_flow
            exclude *->*
            include relationship.tag==token_flow
            include relationship.tag==all
            autoLayout lr
        }
        component auth_server "003_scim_flow" {
            include c
            include element.tag==scim_flow
            exclude *->*
            include relationship.tag==scim_flow
            include relationship.tag==all
            autoLayout lr
        }

        styles {
            element "Element" {
                color #ffffff
            }
            element "Person" {
                background #048c04
                shape person
            }
            element "Software System" {
                background #047804
            }
            element "Container" {
                background #55aa55
            }
            element "Database" {
                shape cylinder
            }
        }
    }

    configuration {
        scope softwaresystem
    }

}