<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="htmx-config" content='{"responseHandling": [{"code":".*", "swap": true}]}' />
    <title>Axes Authorization Server</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <style>
        .content-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            
            padding: 4rem;
        }

        .login-card {
            width: 30%;
        }
    </style>
</head>

<body class="vh-100">
    <div class="container-fluid h-100">
        <div class="row h-100">
            <div class="content-wrapper">
                <div class="card login-card shadow border-0">
                <div class="card-header"><h2 class="text-muted">Axxes Authorization Server</h2></div>
                    <div class="card-body">
                        <form method="POST" action="{{ .FormAction }}" enctype="multipart/form-data" class="needs-validation" novalidate>
                            {{ if .FormErrorMessage }}
                            <div class="alert alert-danger" role="alert">
                                {{ .FormErrorMessage }}
                            </div>
                            {{ end }}
                            <div class="mb-4">
                                <label for="username" class="form-label">Email address</label>
                                <input name="username" value="{{ .Username }}" type="text" class="form-control {{ if .UsernameError }}is-invalid{{ end }}" id="username" aria-describedby="validationFeedbackUsername">
                                {{ if .UsernameError }}
                                <div id="validationFeedbackUsername" class="invalid-feedback">
                                    {{ .UsernameError }}
                                </div>
                                {{ end }}
                            </div>
                            <div class="mb-4">
                                <label for="password" class="form-label">Password</label>
                                <input name="password" type="password" class="form-control {{ if .PasswordError }}is-invalid{{ end }}" id="password" aria-describedby="validationFeedbackPassword">
                                {{ if .PasswordError }}
                                <div id="validationFeedbackPassword" class="invalid-feedback">
                                    {{ .PasswordError }}
                                </div>
                                {{ end }}
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-success">Sign In</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
</body>

</html>