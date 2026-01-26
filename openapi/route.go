package openapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type RouteBuilder struct {
	openapi   *OpenAPI
	method    string
	path      string
	operation *openapi3.Operation
}

func (rb *RouteBuilder) autoExtractPathParams() {
	parts := strings.Split(rb.path, "/")
	for _, part := range parts {
		var paramName string

		if strings.HasPrefix(part, ":") {
			paramName = strings.TrimPrefix(part, ":")
		}

		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			paramName = strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
		}
		if paramName != "" {
			rb.operation.Parameters = append(rb.operation.Parameters, &openapi3.ParameterRef{
				Value: &openapi3.Parameter{
					Name:     paramName,
					In:       "path",
					Required: true,
					Schema:   &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				},
			})
		}
	}
}

func (rb *RouteBuilder) Summary(summary string) *RouteBuilder {
	rb.operation.Summary = summary
	return rb
}

func (rb *RouteBuilder) Description(description string) *RouteBuilder {
	rb.operation.Description = description
	return rb
}

func (rb *RouteBuilder) OperationID(id string) *RouteBuilder {
	rb.operation.OperationID = id
	return rb
}

func (rb *RouteBuilder) Tags(tags ...string) *RouteBuilder {
	rb.operation.Tags = append(rb.operation.Tags, tags...)
	return rb
}

func (rb *RouteBuilder) Deprecated(deprecated bool) *RouteBuilder {
	rb.operation.Deprecated = deprecated
	return rb
}

func (rb *RouteBuilder) PathParam(name, description string) *ParamBuilder {
	param := rb.findOrCreateParam(name, "path")
	param.Description = description
	param.Required = true
	return &ParamBuilder{route: rb, param: param}
}

func (rb *RouteBuilder) QueryParam(name, description string) *ParamBuilder {
	param := rb.findOrCreateParam(name, "query")
	param.Description = description
	return &ParamBuilder{route: rb, param: param}
}

func (rb *RouteBuilder) HeaderParam(name, description string) *ParamBuilder {
	param := rb.findOrCreateParam(name, "header")
	param.Description = description
	return &ParamBuilder{route: rb, param: param}
}

func (rb *RouteBuilder) CookieParam(name, description string) *ParamBuilder {
	param := rb.findOrCreateParam(name, "cookie")
	param.Description = description
	return &ParamBuilder{route: rb, param: param}
}

func (rb *RouteBuilder) findOrCreateParam(name, in string) *openapi3.Parameter {
	for _, p := range rb.operation.Parameters {
		if p.Value != nil && p.Value.Name == name && p.Value.In == in {
			return p.Value
		}
	}

	param := &openapi3.Parameter{
		Name:   name,
		In:     in,
		Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
	}
	rb.operation.Parameters = append(rb.operation.Parameters, &openapi3.ParameterRef{Value: param})
	return param
}

func (rb *RouteBuilder) Body(example any, description string) *RouteBuilder {
	schemaRef := rb.openapi.generateSchema(example)

	rb.operation.RequestBody = &openapi3.RequestBodyRef{
		Value: &openapi3.RequestBody{
			Description: description,
			Required:    true,
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: schemaRef,
				},
			},
		},
	}
	return rb
}

func (rb *RouteBuilder) BodyOptional(example any, description string) *RouteBuilder {
	rb.Body(example, description)
	rb.operation.RequestBody.Value.Required = false
	return rb
}

func (rb *RouteBuilder) BodyMultipart(description string) *MultipartBuilder {
	return &MultipartBuilder{
		route:       rb,
		description: description,
		properties:  make(openapi3.Schemas),
		required:    []string{},
	}
}

type MultipartBuilder struct {
	route       *RouteBuilder
	description string
	properties  openapi3.Schemas
	required    []string
}

func (mb *MultipartBuilder) Field(name string, required bool) *MultipartBuilder {
	mb.properties[name] = &openapi3.SchemaRef{
		Value: &openapi3.Schema{Type: &openapi3.Types{"string"}},
	}
	if required {
		mb.required = append(mb.required, name)
	}
	return mb
}

func (mb *MultipartBuilder) FileField(name string, required bool) *MultipartBuilder {
	mb.properties[name] = &openapi3.SchemaRef{
		Value: &openapi3.Schema{
			Type:   &openapi3.Types{"string"},
			Format: "binary",
		},
	}
	if required {
		mb.required = append(mb.required, name)
	}
	return mb
}

func (mb *MultipartBuilder) Done() *RouteBuilder {
	mb.route.operation.RequestBody = &openapi3.RequestBodyRef{
		Value: &openapi3.RequestBody{
			Description: mb.description,
			Required:    len(mb.required) > 0,
			Content: openapi3.Content{
				"multipart/form-data": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type:       &openapi3.Types{"object"},
							Properties: mb.properties,
							Required:   mb.required,
						},
					},
				},
			},
		},
	}
	return mb.route
}

func (mb *MultipartBuilder) Response(statusCode int, example any, description string) *RouteBuilder {
	mb.Done()
	return mb.route.Response(statusCode, example, description)
}

func (mb *MultipartBuilder) Build() {
	mb.Done()
	mb.route.Build()
}

func (rb *RouteBuilder) Response(statusCode int, example any, description string) *RouteBuilder {
	var content openapi3.Content

	if example != nil {
		schemaRef := rb.openapi.generateSchema(example)
		content = openapi3.Content{
			"application/json": &openapi3.MediaType{
				Schema: schemaRef,
			},
		}
	}

	rb.operation.Responses.Set(statusCodeToString(statusCode), &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: &description,
			Content:     content,
		},
	})

	return rb
}

func (rb *RouteBuilder) ResponseBinary(statusCode int, contentType, description string) *RouteBuilder {
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	rb.operation.Responses.Set(statusCodeToString(statusCode), &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: &description,
			Content: openapi3.Content{
				contentType: &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type:   &openapi3.Types{"string"},
							Format: "binary",
						},
					},
				},
			},
		},
	})

	return rb
}

func (rb *RouteBuilder) ResponseWithHeaders(statusCode int, example any, description string, headers map[string]string) *RouteBuilder {
	rb.Response(statusCode, example, description)

	resp := rb.operation.Responses.Value(statusCodeToString(statusCode))
	if resp != nil && resp.Value != nil {
		resp.Value.Headers = make(openapi3.Headers)
		for name, desc := range headers {
			resp.Value.Headers[name] = &openapi3.HeaderRef{
				Value: &openapi3.Header{
					Parameter: openapi3.Parameter{
						Description: desc,
						Schema:      &openapi3.SchemaRef{Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
					},
				},
			}
		}
	}

	return rb
}

func (rb *RouteBuilder) Security(schemes ...string) *RouteBuilder {
	if rb.operation.Security == nil {
		rb.operation.Security = &openapi3.SecurityRequirements{}
	}
	for _, scheme := range schemes {
		req := openapi3.SecurityRequirement{}
		req[scheme] = []string{}
		*rb.operation.Security = append(*rb.operation.Security, req)
	}
	return rb
}

func (rb *RouteBuilder) SecurityAll(schemes ...string) *RouteBuilder {
	if rb.operation.Security == nil {
		rb.operation.Security = &openapi3.SecurityRequirements{}
	}
	req := openapi3.SecurityRequirement{}
	for _, scheme := range schemes {
		req[scheme] = []string{}
	}
	*rb.operation.Security = append(*rb.operation.Security, req)
	return rb
}

func (rb *RouteBuilder) SecurityWithScopes(scheme string, scopes ...string) *RouteBuilder {
	if rb.operation.Security == nil {
		rb.operation.Security = &openapi3.SecurityRequirements{}
	}
	req := openapi3.SecurityRequirement{}
	req[scheme] = scopes
	*rb.operation.Security = append(*rb.operation.Security, req)
	return rb
}

func (rb *RouteBuilder) NoSecurity() *RouteBuilder {
	rb.operation.Security = &openapi3.SecurityRequirements{}
	return rb
}

func (rb *RouteBuilder) ExternalDocs(url, description string) *RouteBuilder {
	rb.operation.ExternalDocs = &openapi3.ExternalDocs{
		URL:         url,
		Description: description,
	}
	return rb
}

func (rb *RouteBuilder) Build() {
	rb.openapi.addOperation(rb.method, rb.path, rb.operation)
}

func statusCodeToString(code int) string {
	switch code {
	case http.StatusOK:
		return "200"
	case http.StatusCreated:
		return "201"
	case http.StatusAccepted:
		return "202"
	case http.StatusNoContent:
		return "204"
	case http.StatusBadRequest:
		return "400"
	case http.StatusUnauthorized:
		return "401"
	case http.StatusForbidden:
		return "403"
	case http.StatusNotFound:
		return "404"
	case http.StatusMethodNotAllowed:
		return "405"
	case http.StatusConflict:
		return "409"
	case http.StatusUnprocessableEntity:
		return "422"
	case http.StatusTooManyRequests:
		return "429"
	case http.StatusInternalServerError:
		return "500"
	case http.StatusBadGateway:
		return "502"
	case http.StatusServiceUnavailable:
		return "503"
	default:
		return strconv.Itoa(code)
	}
}

type ParamBuilder struct {
	route *RouteBuilder
	param *openapi3.Parameter
}

func (pb *ParamBuilder) Required() *ParamBuilder {
	pb.param.Required = true
	return pb
}

func (pb *ParamBuilder) Optional() *ParamBuilder {
	pb.param.Required = false
	return pb
}

func (pb *ParamBuilder) Type(t string) *ParamBuilder {
	pb.param.Schema.Value.Type = &openapi3.Types{t}
	return pb
}

func (pb *ParamBuilder) TypeInt() *ParamBuilder {
	pb.param.Schema.Value.Type = &openapi3.Types{"integer"}
	return pb
}

func (pb *ParamBuilder) TypeBool() *ParamBuilder {
	pb.param.Schema.Value.Type = &openapi3.Types{"boolean"}
	return pb
}

func (pb *ParamBuilder) TypeNumber() *ParamBuilder {
	pb.param.Schema.Value.Type = &openapi3.Types{"number"}
	return pb
}

func (pb *ParamBuilder) Format(format string) *ParamBuilder {
	pb.param.Schema.Value.Format = format
	return pb
}

func (pb *ParamBuilder) Enum(values ...string) *ParamBuilder {
	for _, v := range values {
		pb.param.Schema.Value.Enum = append(pb.param.Schema.Value.Enum, v)
	}
	return pb
}

func (pb *ParamBuilder) Default(value any) *ParamBuilder {
	pb.param.Schema.Value.Default = value
	return pb
}

func (pb *ParamBuilder) Example(value any) *ParamBuilder {
	pb.param.Example = value
	return pb
}

func (pb *ParamBuilder) Min(min float64) *ParamBuilder {
	pb.param.Schema.Value.Min = &min
	return pb
}

func (pb *ParamBuilder) Max(max float64) *ParamBuilder {
	pb.param.Schema.Value.Max = &max
	return pb
}

func (pb *ParamBuilder) MinLength(length uint64) *ParamBuilder {
	pb.param.Schema.Value.MinLength = length
	return pb
}

func (pb *ParamBuilder) MaxLength(length *uint64) *ParamBuilder {
	pb.param.Schema.Value.MaxLength = length
	return pb
}

func (pb *ParamBuilder) Pattern(pattern string) *ParamBuilder {
	pb.param.Schema.Value.Pattern = pattern
	return pb
}

func (pb *ParamBuilder) Done() *RouteBuilder {
	return pb.route
}

func (pb *ParamBuilder) Summary(summary string) *RouteBuilder {
	return pb.route.Summary(summary)
}

func (pb *ParamBuilder) Description(description string) *RouteBuilder {
	return pb.route.Description(description)
}

func (pb *ParamBuilder) Tags(tags ...string) *RouteBuilder {
	return pb.route.Tags(tags...)
}

func (pb *ParamBuilder) PathParam(name, description string) *ParamBuilder {
	return pb.route.PathParam(name, description)
}

func (pb *ParamBuilder) QueryParam(name, description string) *ParamBuilder {
	return pb.route.QueryParam(name, description)
}

func (pb *ParamBuilder) HeaderParam(name, description string) *ParamBuilder {
	return pb.route.HeaderParam(name, description)
}

func (pb *ParamBuilder) Body(example any, description string) *RouteBuilder {
	return pb.route.Body(example, description)
}

func (pb *ParamBuilder) Response(statusCode int, example any, description string) *RouteBuilder {
	return pb.route.Response(statusCode, example, description)
}

func (pb *ParamBuilder) Security(schemes ...string) *RouteBuilder {
	return pb.route.Security(schemes...)
}

func (pb *ParamBuilder) Build() {
	pb.route.Build()
}
