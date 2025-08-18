# brx framework

An opinionated Go web stack. Not really a framework—more like proven libraries with a 'bow on top'.

The main objective of brx is to provide rapid prototyping + minimise boiler plate code.

## What it does

- HTTP server (Echo)
- Dependency injection (fx)
- Database (GORM)
- Sessions, auth, logging, mail
- Templates or SPAs (Inertia.js via gonertia)

## Quick start

```go
package main

import (
    "net/http"
    "github.com/labstack/echo/v4"
    "github.com/tech-arch1tect/brx"
)

func main() {
    app := brx.New()
    
    app.Get("/", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{
            "message": "Hello from brx!",
        })
    })
    
    app.Run()
}
```

## Documentation

TODO

I recommend looking at go.mod to see what lib's we currently wrap, this should imediately give you an idea of what services brx provides.