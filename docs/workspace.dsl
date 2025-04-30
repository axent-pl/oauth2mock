workspace "Name" "Description" {

    model {
        u = person "User"
        c = softwareSystem "Client"
        ss_axes = softwareSystem "Axes" "OAuth2 Authorization Server" "" {
            // !docs ./axes.md
            webapp = container "Web Application" "" "Go" "" {
                c_srv = component "HTTP Server" "" "" "auth_flow,token_flow"
                c_router = component "HTTP Router" "" "" "auth_flow,token_flow"

                c_authhandler = component "Authorize Handler" "" "" "auth_flow"
                c_tokenhandler = component "Token Handler" "" "" "token_flow"

                c_tpl_srv = component "Template Service" "" "" "auth_flow"
                c_cli_srv = component "Client Service" "" "" "auth_flow,token_flow"    
                c_sub_srv = component "Subject Service" "" "" "auth_flow"
                c_auc_srv = component "Auth Code Service" "" "" "auth_flow,token_flow"
                c_cla_srv = component "Claim Service" "" "" "token_flow"
                c_usr_srv = component "User Service" "" "" "auth_flow"
            }
        }

        u -> c_srv "Authorize request"
        c -> c_srv "Token request"

        c_srv -> c_router "Uses"

        c_router -> c_authhandler "Uses"
        c_router -> c_tokenhandler "Uses"

        c_authhandler -> c_tpl_srv "Uses" "" "auth_flow"
        c_authhandler -> c_cli_srv "Uses" "" "token_flow"
        c_authhandler -> c_sub_srv "Uses" "" ""
        c_authhandler -> c_auc_srv "Uses" "" ""

        c_tokenhandler -> c_cli_srv "Uses"
        c_tokenhandler -> c_auc_srv "Uses"
        c_tokenhandler -> c_cla_srv "Uses"

        c_sub_srv -> c_usr_srv "Uses"
        c_sub_srv -> c_cli_srv "Uses"
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
        component webapp "000_all" {
            include *
            autoLayout lr
        }
        component webapp "001_authorize_flow" {
            include u
            include c
            include element.tag==auth_flow
            autoLayout lr
        }
        component webapp "002_token_flow" {
            include u
            include c
            include element.tag==token_flow
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