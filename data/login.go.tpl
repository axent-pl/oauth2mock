<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="htmx-config" content='{"responseHandling": [{"code":".*", "swap": true}]}' />
    <title>Axes login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
</head>

<body>
    <main role="main" class="container">
        <form method="POST" action="{{ .FormAction }}" enctype="multipart/form-data" class="needs-validation" novalidate>
            {{ if .AuthenticationError }}
            <div class="alert alert-danger" role="alert">
                {{ .AuthenticationError }}
            </div>
            {{ end }}
            <div class="mb-3">
                <label for="username" class="form-label">Email address</label>
                <input name="username" value="{{ .Credentials.Username }}" type="text" class="form-control {{ if .ValidationErrors.Username }}is-invalid{{ end }}" id="username" aria-describedby="validationFeedbackUsername">
                {{ if .ValidationErrors.Username }}
                <div id="validationFeedbackUsername" class="invalid-feedback">
                    {{ .ValidationErrors.Username.ErrorMessage }}
                </div>
                {{ end }}
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input name="password" type="password" class="form-control  {{ if .ValidationErrors.Password }}is-invalid{{ end }}" id="password" aria-describedby="validationFeedbackPassword">
                {{ if .ValidationErrors.Password }}
                <div id="validationFeedbackPassword" class="invalid-feedback">
                    {{ .ValidationErrors.Password.ErrorMessage }}
                </div>
                {{ end }}
            </div>
            
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </main>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
</body>

</html>