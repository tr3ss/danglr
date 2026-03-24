package templateutil

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var tokenPattern = regexp.MustCompile(`{{\s*([a-zA-Z0-9_\[\]]+)\s*}}`)

type Context struct {
	Host              string
	Parent            string
	Parents           []string
	Apex              string
	Owner             string
	Target            string
	LabelBeforeSuffix string
}

func Validate(input string) error {
	matches := tokenPattern.FindAllStringSubmatch(input, -1)
	for _, match := range matches {
		if err := validateToken(match[1]); err != nil {
			return fmt.Errorf("invalid token %q: %w", match[1], err)
		}
	}
	if strings.Contains(input, "{{") || strings.Contains(input, "}}") {
		normalized := tokenPattern.ReplaceAllString(input, "")
		if strings.Contains(normalized, "{{") || strings.Contains(normalized, "}}") {
			return fmt.Errorf("malformed template %q", input)
		}
	}
	return nil
}

func Render(input string, ctx Context) (string, error) {
	var renderErr error
	rendered := tokenPattern.ReplaceAllStringFunc(input, func(raw string) string {
		if renderErr != nil {
			return ""
		}
		match := tokenPattern.FindStringSubmatch(raw)
		if len(match) != 2 {
			renderErr = fmt.Errorf("malformed token %q", raw)
			return ""
		}
		value, err := tokenValue(match[1], ctx)
		if err != nil {
			renderErr = err
			return ""
		}
		return value
	})
	if renderErr != nil {
		return "", renderErr
	}
	return strings.ToLower(strings.TrimSuffix(rendered, ".")), nil
}

func UsesParentToken(input string) bool {
	return strings.Contains(input, "{{parent}}")
}

func Tokens(input string) []string {
	matches := tokenPattern.FindAllStringSubmatch(input, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			out = append(out, match[1])
		}
	}
	return out
}

func validateToken(token string) error {
	switch token {
	case "host", "parent", "apex", "owner", "target", "label_before_suffix":
		return nil
	}
	if strings.HasPrefix(token, "parents[") && strings.HasSuffix(token, "]") {
		indexText := strings.TrimSuffix(strings.TrimPrefix(token, "parents["), "]")
		index, err := strconv.Atoi(indexText)
		if err != nil {
			return fmt.Errorf("invalid parents index %q", token)
		}
		if index < 0 {
			return fmt.Errorf("parents index out of range %q", token)
		}
		return nil
	}
	return fmt.Errorf("unsupported token %q", token)
}

func tokenValue(token string, ctx Context) (string, error) {
	switch token {
	case "host":
		return ctx.Host, nil
	case "parent":
		return ctx.Parent, nil
	case "apex":
		return ctx.Apex, nil
	case "owner":
		return ctx.Owner, nil
	case "target":
		return ctx.Target, nil
	case "label_before_suffix":
		return ctx.LabelBeforeSuffix, nil
	}

	if strings.HasPrefix(token, "parents[") && strings.HasSuffix(token, "]") {
		indexText := strings.TrimSuffix(strings.TrimPrefix(token, "parents["), "]")
		index, err := strconv.Atoi(indexText)
		if err != nil {
			return "", fmt.Errorf("invalid parents index %q", token)
		}
		if index < 0 || index >= len(ctx.Parents) {
			return "", fmt.Errorf("parents index out of range %q", token)
		}
		return ctx.Parents[index], nil
	}

	return "", fmt.Errorf("unsupported token %q", token)
}
